import logging
import json
import base64
from handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)

class KeyRegistrationHandler(BaseHandler):
    """Handler for secure client key registration requests"""
    
    def handle(self):
        """Process a key registration request from a client"""
        try:
            # Get the operation payload from the request
            payload = self.get_operation_payload()
            
            if payload:
                # Handle structured payload from operation router
                self._process_key_registration(payload)
            else:
                # Handle legacy or direct registration request
                self._process_legacy_key_registration()
        except Exception as e:
            logger.error(f"Error in key registration handler: {e}")
            self.send_error_response(500, "Internal server error")
    
    def _process_key_registration(self, payload):
        """Process a structured key registration payload"""
        logger.info(f"Processing key registration from {self.client_address[0]}")
        
        try:
            # Extract client ID if available
            client_id = None
            if hasattr(self.request_handler, 'client_id'):
                client_id = self.request_handler.client_id
            
            # If no client ID yet, try to identify from payload or IP
            if not client_id:
                # Try to get from payload
                if isinstance(payload, dict) and 'client_id' in payload:
                    client_id = payload['client_id']
                else:
                    # Fall back to identifying by IP
                    client_id = self._identify_client_by_ip()
            
            if not client_id:
                logger.error(f"Cannot identify client for key registration")
                self.send_error_response(401, "Authentication failed")
                return
            
            # Extract encrypted AES key from payload
            if isinstance(payload, dict) and 'encrypted_key' in payload:
                encrypted_key = payload['encrypted_key']
            else:
                logger.error("Missing encrypted key in payload")
                self.send_error_response(400, "Missing encrypted key")
                return
            
            # Get encryption service
            encryption_service = None
            if hasattr(self.server, 'encryption_service'):
                encryption_service = self.server.encryption_service
            
            if not encryption_service:
                logger.error("Encryption service not available")
                self.send_error_response(500, "Encryption service not available")
                return
            
            # Register the client key
            success = encryption_service.register_client_key(client_id, encrypted_key)
            
            if success:
                # Update client manager with key rotation time
                if hasattr(self.client_manager, 'set_client_key'):
                    # Just record the time, the actual key is already set in encryption service
                    self.client_manager.set_client_key(client_id, None)
                
                # Send success response
                response = {
                    "status": "success",
                    "message": "Key registered successfully"
                }
                
                # Encrypt the response with the newly registered key
                encrypted_response = encryption_service.encrypt(json.dumps(response), client_id)
                
                # Format final response
                final_response = {
                    "d": encrypted_response,
                    "t": self._generate_token_padding(),
                    "s": "key_registered"  # Status indicator for key registration
                }
                
                # Send the response
                self.send_response(200, "application/json", json.dumps(final_response))
                logger.info(f"Successfully registered key for client {client_id}")
            else:
                logger.error(f"Failed to register key for client {client_id}")
                self.send_error_response(400, "Key registration failed")
        except Exception as e:
            logger.error(f"Error processing key registration: {e}")
            self.send_error_response(500, f"Server error: {str(e)}")
    
    def _process_legacy_key_registration(self):
        """Process a legacy or direct key registration request"""
        # Read content data
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error_response(400, "Missing content")
            return
            
        request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
        
        try:
            # Parse the JSON body
            body_data = json.loads(request_body)
            
            # Extract client ID and encrypted key
            client_id = body_data.get('c') or body_data.get('client_id')
            encrypted_key = body_data.get('k') or body_data.get('encrypted_key')
            
            if not client_id:
                # Try to identify client by IP
                client_id = self._identify_client_by_ip()
                
                if not client_id:
                    logger.error("Cannot identify client for key registration")
                    self.send_error_response(401, "Authentication failed")
                    return
            
            if not encrypted_key:
                logger.error("Missing encrypted key in request")
                self.send_error_response(400, "Missing encrypted key")
                return
            
            # Get encryption service
            encryption_service = None
            if hasattr(self.server, 'encryption_service'):
                encryption_service = self.server.encryption_service
            
            if not encryption_service:
                logger.error("Encryption service not available")
                self.send_error_response(500, "Encryption service not available")
                return
            
            # Register the client key
            success = encryption_service.register_client_key(client_id, encrypted_key)
            
            if success:
                # Update client manager with key rotation time
                if hasattr(self.client_manager, 'set_client_key'):
                    # Just record the time, the actual key is already set in encryption service
                    self.client_manager.set_client_key(client_id, None)
                
                # Send success response
                response = {
                    "status": "success",
                    "message": "Key registered successfully"
                }
                
                # Encrypt the response with the newly registered key
                encrypted_response = encryption_service.encrypt(json.dumps(response), client_id)
                
                # Format final response
                final_response = {
                    "d": encrypted_response,
                    "t": self._generate_token_padding(),
                    "s": "key_registered"  # Status indicator for key registration
                }
                
                # Send the response
                self.send_response(200, "application/json", json.dumps(final_response))
                logger.info(f"Successfully registered key for client {client_id}")
            else:
                logger.error(f"Failed to register key for client {client_id}")
                self.send_error_response(400, "Key registration failed")
                
        except json.JSONDecodeError:
            logger.error("Invalid JSON format in request body")
            self.send_error_response(400, "Invalid JSON format")
        except Exception as e:
            logger.error(f"Error processing key registration: {e}")
            self.send_error_response(500, f"Server error: {str(e)}")