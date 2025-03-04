import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class PathRouter:
    """Manages URL path routing and rotation"""
    
    def __init__(self, path_manager):
        self.path_manager = path_manager
        self.path_mapping = {}
        self.update_path_mapping()
    
    def update_path_mapping(self):
        """Update path mapping after rotation"""
        self.path_mapping = {}
        
        # Add current paths to mapping
        current_paths = self.path_manager.get_current_paths()
        for key, path in current_paths.items():
            self.path_mapping[path] = key
        
        # Also add previous rotation's paths for graceful transition
        if self.path_manager.rotation_counter > 0:
            previous_paths = self.path_manager.get_path_by_rotation_id(self.path_manager.rotation_counter - 1)
            if previous_paths:
                for key, path in previous_paths.items():
                    if path not in self.path_mapping:  # Don't overwrite current paths
                        self.path_mapping[path] = f"previous_{key}"
    
    def check_rotation(self):
        """Check if rotation is needed and update mapping if it is"""
        if self.path_manager.check_rotation():
            self.update_path_mapping()
            return True
        return False
    
    def get_endpoint_type(self, path):
        """Get the endpoint type for a given path"""
        # Check in current and previous paths
        if path in self.path_mapping:
            return self.path_mapping[path]
        
        # If not found in current or previous paths, check older rotations
        for rotation_id in range(max(0, self.path_manager.rotation_counter - 5), self.path_manager.rotation_counter):
            paths = self.path_manager.get_path_by_rotation_id(rotation_id)
            if paths:
                for key, old_path in paths.items():
                    if old_path == path:
                        return f"old_{key}"
        
        # Not found
        return None
    
    def get_current_paths(self):
        """Get the current active paths"""
        return self.path_manager.get_current_paths()
    
    def get_rotation_info(self):
        """Get information about the current rotation state"""
        return self.path_manager.get_rotation_info()
    
    def create_path_rotation_command(self):
        """Create a command to update client with new path rotation info"""
        rotation_info = self.path_manager.get_rotation_info()
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": "path_rotation",
            "args": json.dumps({
                "rotation_id": rotation_info["current_rotation_id"],
                "next_rotation_time": rotation_info["next_rotation_time"],
                "paths": rotation_info["current_paths"]
            })
        }