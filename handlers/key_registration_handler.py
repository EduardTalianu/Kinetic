import logging
import json
import base64
from handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)

class KeyRegistrationHandler(BaseHandler):
    """Handler for secure key registration requests from clients"""
    
    def handle(self):
        """Process a key registration request from a client"""
        logger.info(f"Key registration request received from {self.client_address[0]}")
        
        try:
            # Get content data
            content_length = int(self.request_handler.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error_response(400, "Missing content")
                return
                
            request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
            
            # Parse the JSON body
            try:
                body_data = json.loads(request_body)
                encrypted_key = body_data.get('encrypted_key')
                client_id = body_data.get('client_id')
                nonce = body_data.get('nonce', '')  # Optional nonce for uniqueness
                
                logger.info(f"Processing key registration for client {client_id}")
                
                if not encrypted_key or not client_id:
                    # Send a JSON error response, not HTML
                    response = {
                        "status": "error",
                        "message": "Missing required fields",
                        "nonce": nonce
                    }
                    self.send_json_response(400, response)
                    return
                
                # Access encryption service through the server
                encryption_service = None
                if hasattr(self.request_handler.server, 'encryption_service'):
                    encryption_service = self.request_handler.server.encryption_service
                
                if not encryption_service:
                    logger.error(f"Encryption service not available")
                    # Send a JSON error response, not HTML
                    response = {
                        "status": "error",
                        "message": "Encryption service not available",
                        "nonce": nonce
                    }
                    self.send_json_response(500, response)
                    return
                
                # Register the client key
                success = encryption_service.register_client_generated_key(client_id, encrypted_key)
                
                if success:
                    # Update client info to reflect key registration
                    if hasattr(self.client_manager, 'clients') and client_id in self.client_manager.clients:
                        self.client_manager.clients[client_id]['key_rotation_time'] = self._current_timestamp()
                        self.client_manager.clients[client_id]['client_generated_key'] = True
                    
                    # Log successful key registration
                    logger.info(f"Client {client_id} registered its own AES key")
                    
                    # Prepare success response
                    response = {
                        "status": "success",
                        "message": "Key registration successful",
                        "nonce": nonce  # Echo back nonce for verification
                    }
                    
                    # Send the response as JSON with proper headers
                    logger.info(f"Sending success response to key registration")
                    self.send_json_response(200, response)
                    return
                else:
                    # Log failure
                    logger.error(f"Failed to register key for client {client_id}")
                    
                    # Prepare error response
                    response = {
                        "status": "error",
                        "message": "Key registration failed",
                        "nonce": nonce
                    }
                    
                    # Send the response as JSON with proper headers
                    logger.info(f"Sending error response to key registration")
                    self.send_json_response(200, response)
                    return
                    
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in key registration request: {e}")
                response = {
                    "status": "error",
                    "message": "Invalid JSON format"
                }
                self.send_json_response(400, response)
            except Exception as e:
                logger.error(f"Error processing key registration: {e}")
                response = {
                    "status": "error",
                    "message": f"Server error: {str(e)}"
                }
                self.send_json_response(500, response)
        except Exception as e:
            logger.error(f"Error handling key registration: {e}")
            response = {
                "status": "error",
                "message": "Internal server error"
            }
            self.send_json_response(500, response)
    
    def send_json_response(self, status_code, data):
        """Send a JSON response instead of HTML"""
        response_json = json.dumps(data)
        self.request_handler.send_response(status_code)
        self.request_handler.send_header("Content-Type", "application/json")
        self.request_handler.end_headers()
        self.request_handler.wfile.write(response_json.encode('utf-8'))
    
    def _current_timestamp(self):
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()