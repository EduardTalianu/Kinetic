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
        
        # Identify the client
        client_id = self.identify_client()
        self.log_message(f"Identified client from result: {client_id}")
        
        # Process the result
        try:
            # Decrypt the result data
            if client_id:
                result_data = self.crypto_helper.decrypt(encrypted_data, client_id)
            else:
                result_data = self.crypto_helper.decrypt(encrypted_data)
            
            self.log_message(f"Successfully decrypted result data: {result_data[:100]}...")
            
            # Process the result data
            self._process_result_data(client_id, result_data)
            
            # Send success response
            self.send_success_response()
            
        except Exception as e:
            logger.error(f"Error processing command result: {e}")
            self.send_error_response(400, "Bad Request")
    
    def _process_result_data(self, client_id, result_data):
        """Process command result data and update client history"""
        # Try to parse as JSON
        try:
            result_json = json.loads(result_data)
            if isinstance(result_json, dict) and 'timestamp' in result_json and 'result' in result_json:
                # This is a structured result with timestamp
                timestamp = result_json['timestamp']
                result = result_json['result']
                
                if client_id:
                    # Add the result to the command history
                    self.client_manager.add_command_result(client_id, timestamp, result)
                    self.log_message(f"Result processed for client {client_id} (timestamp: {timestamp})")
                    
                    # IMPORTANT: Remove the command from pending queue since we have the result
                    self._remove_from_pending(client_id, timestamp)
                else:
                    # If no client was found, log as a generic result
                    self.log_message(f"Result received from unknown client {self.client_address[0]}")
                    self.client_manager.log_event("Unknown", "Command Result Received", f"{result_data}")
            else:
                # Handle unstructured result
                self._handle_unstructured_result(client_id, result_data)
        except json.JSONDecodeError:
            # Not JSON, treat as plain text
            self._handle_unstructured_result(client_id, result_data)
        
    def _remove_from_pending(self, client_id, timestamp):
        """Remove a command from pending once its result is received"""
        if client_id in self.client_manager.clients:
            pending_commands = self.client_manager.clients[client_id].get("pending_commands", [])
            # Find and remove the command with matching timestamp
            for i, cmd in enumerate(pending_commands):
                if cmd.get("timestamp") == timestamp:
                    # Remove this specific command from pending
                    pending_commands.pop(i)
                    self.log_message(f"Removed completed command from pending for client {client_id}")
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