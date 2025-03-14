import time
import random
import string
import hashlib
import json
import os
from datetime import datetime, timedelta



class PathRotationManager:
    def __init__(self, campaign_folder, logger, initial_paths=None, rotation_interval=3600, pool_size=10):
        """
        Initialize the path rotation manager
        
        Args:
            campaign_folder: Path to the campaign folder
            logger: Logger function to log events
            initial_paths: Initial URL paths (optional)
            rotation_interval: Time in seconds between path rotations (default: 1 hour)
            pool_size: Number of paths to generate in the path pool (default: 10)
        """
        self.campaign_folder = campaign_folder
        self.logger = logger
        self.rotation_interval = rotation_interval
        self.last_rotation_time = int(time.time())
        self.rotation_counter = 0
        self.path_history = []
        self.pool_size = pool_size  # Store the path pool size
        
        # Default paths as fallback
        self.default_paths = {
            "beacon_path": "/beacon",
            "agent_path": "/raw_agent",
            "stager_path": "/b64_stager",
            "cmd_result_path": "/command_result",
            "file_upload_path": "/file_upload",
            "file_request_path": "/file_request"  # Make sure this is included
        }
        
        # Set current paths to initial_paths or defaults
        self.current_paths = initial_paths.copy() if initial_paths else self.default_paths.copy()
        
        # Ensure all required paths are present
        for key, path in self.default_paths.items():
            if key not in self.current_paths:
                self.current_paths[key] = path
                self.logger(f"Added missing path {key}: {path}")
        
        # Save initial paths to history
        self.path_history.append({
            "timestamp": self.last_rotation_time,
            "rotation_id": self.rotation_counter,
            "paths": self.current_paths.copy()
        })
        
        # Create the state file if it doesn't exist
        self.state_file = os.path.join(self.campaign_folder, "path_rotation_state.json")
        self._save_state()
        
        # Load URL patterns and components
        self.url_patterns = self._load_url_patterns()
        self.url_components = self._load_url_components()
        
        # Generate a pool of additional paths for modular operations
        self.current_paths["path_pool"] = self.generate_path_pool(self.rotation_counter, pool_size=self.pool_size)
        
        self.logger(f"Path rotation manager initialized with interval {rotation_interval} seconds and pool size {pool_size}")
        self.logger(f"Initial paths: {self.current_paths}")
    
    def _load_url_patterns(self):
        """Load URL patterns from links.txt file in helpers/links folder"""
        default_patterns = ["web_app", "api", "cdn", "blog", "custom"]
        
        try:
            # Find the links.txt file path
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            links_file = os.path.join(script_dir, "helpers", "links", "links.txt")
            
            if os.path.exists(links_file):
                with open(links_file, 'r') as f:
                    patterns = [line.strip() for line in f if line.strip()]
                
                if patterns:
                    # Always ensure 'custom' is available
                    if "custom" not in patterns:
                        patterns.append("custom")
                    return patterns
                    
            # If file doesn't exist or is empty, return defaults
            return default_patterns
        except Exception as e:
            self.logger(f"Error loading URL patterns: {str(e)}")
            return default_patterns
    
    def _load_url_components(self):
        """Load URL path components from links2.txt file in helpers/links folder"""
        try:
            # Find the links2.txt file path
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            links_file = os.path.join(script_dir, "helpers", "links", "links2.txt")
            
            if os.path.exists(links_file):
                with open(links_file, 'r') as f:
                    components = [line.strip() for line in f if line.strip()]
                
                if components:
                    return components
            
            # Default components if file couldn't be read or is empty
            return ["status", "ping", "monitor", "health", "check",
                    "js", "scripts", "resources", "assets", "static",
                    "loader", "init", "bootstrap", "setup", "config",
                    "data", "response", "events", "analytics", "logs",
                    "storage", "files", "upload", "content", "media"]
        except Exception as e:
            self.logger(f"Error loading URL components: {str(e)}")
            # Default components if exception occurred
            return ["status", "ping", "monitor", "health", "check",
                    "js", "scripts", "resources", "assets", "static",
                    "loader", "init", "bootstrap", "setup", "config",
                    "data", "response", "events", "analytics", "logs",
                    "storage", "files", "upload", "content", "media"]
    
    def _save_state(self):
        """Save the current rotation state to disk"""
        state = {
            "last_rotation_time": self.last_rotation_time,
            "rotation_counter": self.rotation_counter,
            "current_paths": self.current_paths,
            "path_history": self.path_history,
            "rotation_interval": self.rotation_interval,
            "pool_size": self.pool_size  # Save pool size in state
        }
        
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=4)
        except Exception as e:
            self.logger(f"Error saving path rotation state: {e}")
    
    def load_state(self):
        """Load rotation state from disk if available"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                
                self.last_rotation_time = state.get("last_rotation_time", self.last_rotation_time)
                self.rotation_counter = state.get("rotation_counter", self.rotation_counter)
                self.current_paths = state.get("current_paths", self.current_paths)
                self.path_history = state.get("path_history", self.path_history)
                self.rotation_interval = state.get("rotation_interval", self.rotation_interval)
                self.pool_size = state.get("pool_size", self.pool_size)  # Load pool size from state
                
                # Ensure all required paths are present after loading
                for key, path in self.default_paths.items():
                    if key not in self.current_paths:
                        self.current_paths[key] = path
                        self.logger(f"Added missing path {key}: {path} after loading state")
                
                # Make sure we have a path_pool
                if "path_pool" not in self.current_paths or not self.current_paths["path_pool"]:
                    self.current_paths["path_pool"] = self.generate_path_pool(self.rotation_counter, pool_size=self.pool_size)
                    self.logger(f"Generated new path pool after loading state")
                
                self.logger(f"Path rotation state loaded from {self.state_file}")
                self.logger(f"Current paths after loading: {self.current_paths}")
                return True
            except Exception as e:
                self.logger(f"Error loading path rotation state: {e}")
                return False
        return False
    
    def generate_path_pool(self, seed, pool_size=None):
        """
        Generate a pool of random paths for use with modular operations
        
        Args:
            seed: Seed value for deterministic generation
            pool_size: Number of paths to generate (if None, use instance pool_size)
        
        Returns:
            List of path strings
        """
        # Use instance pool_size if not explicitly provided
        if pool_size is None:
            pool_size = self.pool_size
            
        paths = []
        
        # Generate paths with diverse patterns
        for i in range(pool_size):
            # Create a deterministic seed for each path
            path_seed = f"{seed}_path_{i}"
            hash_obj = hashlib.sha256(path_seed.encode())
            hash_hex = hash_obj.hexdigest()
            
            # Use the hash to determine path characteristics
            pattern_index = int(hash_hex[0:2], 16) % len(self.url_patterns)
            pattern = self.url_patterns[pattern_index]
            
            component_index = int(hash_hex[2:4], 16) % len(self.url_components)
            component = self.url_components[component_index]
            
            # Determine if we'll use an extension
            use_extension = (int(hash_hex[4:6], 16) % 5) < 2  # 40% chance
            
            # Generate random path parts
            random_part1 = self._random_string(4, 10, seed=int(hash_hex[6:10], 16))
            random_part2 = self._random_string(4, 8, seed=int(hash_hex[10:14], 16))
            
            # Determine extension if needed
            extension = ""
            if use_extension:
                extensions = [".php", ".js", ".html", ".aspx", ".json", ".txt", ".xml", ".css"]
                ext_index = int(hash_hex[14:16], 16) % len(extensions)
                extension = extensions[ext_index]
            
            # Create the path based on pattern
            if pattern == "custom":
                if use_extension:
                    path = f"/custom/{random_part1}/{random_part2}{extension}"
                else:
                    path = f"/custom/{random_part1}/{random_part2}"
            else:
                if use_extension:
                    path = f"/{pattern.lower()}/{component}/{random_part1}{extension}"
                else:
                    # Use deeper path structure occasionally
                    if i % 3 == 0:  # Every third path gets a deeper structure
                        path = f"/{pattern.lower()}/{component}/{random_part1}/{random_part2}"
                    else:
                        path = f"/{pattern.lower()}/{component}/{random_part1}"
            
            # Add path to pool
            paths.append(path)
        
        self.logger(f"Generated path pool with {len(paths)} paths")
        return paths
        
    def _random_string(self, min_length=4, max_length=12, include_numbers=True, seed=None):
        """Generate a random string of variable length, optionally with a specific seed"""
        if seed is not None:
            # Save current random state
            old_state = random.getstate()
            # Set seed for deterministic output
            random.seed(seed)
        
        # Determine length based on seed or randomly
        if seed is not None:
            # Use seed to deterministically pick a length
            length = min_length + (seed % (max_length - min_length + 1))
        else:
            length = random.randint(min_length, max_length)
        
        chars = string.ascii_lowercase
        if include_numbers:
            chars += string.digits
        result = ''.join(random.choice(chars) for _ in range(length))
        
        if seed is not None:
            # Restore original random state
            random.setstate(old_state)
            
        return result
    
    def check_rotation(self):
        """
        Check if it's time to rotate paths and do so if needed
        
        Returns:
            True if rotation occurred, False otherwise
        """
        current_time = int(time.time())
        
        # Check if it's time for rotation
        if current_time - self.last_rotation_time >= self.rotation_interval:
            return self.rotate_paths()
        
        return False
    
    def rotate_paths(self, force=False):
        """
        Generate new paths and increment the rotation counter
        
        Args:
            force: Force rotation even if interval hasn't elapsed
        
        Returns:
            True if rotation occurred, False otherwise
        """
        current_time = int(time.time())
        
        # Check if it's time for rotation unless forced
        if not force and current_time - self.last_rotation_time < self.rotation_interval:
            return False
        
        # Increment rotation counter
        self.rotation_counter += 1
        self.last_rotation_time = current_time
        
        # Generate standard paths for each type
        new_paths = {}
        for path_type in self.default_paths:
            new_paths[path_type] = self._generate_path(self.rotation_counter, path_type)
        
        # Generate a pool of additional paths for modular use with configured pool size
        path_pool = self.generate_path_pool(self.rotation_counter, pool_size=self.pool_size)
        new_paths["path_pool"] = path_pool
        
        # Update current paths
        self.current_paths = new_paths
        
        # Add to history (keep last 10 rotations)
        self.path_history.append({
            "timestamp": self.last_rotation_time,
            "rotation_id": self.rotation_counter,
            "paths": self.current_paths.copy()
        })
        
        # Trim history to last 10 entries
        if len(self.path_history) > 10:
            self.path_history = self.path_history[-10:]
        
        # Save state to disk
        self._save_state()
        
        # Log the rotation
        next_rotation = datetime.datetime.fromtimestamp(self.last_rotation_time + self.rotation_interval)
        self.logger(f"Path rotation {self.rotation_counter} completed. Next rotation at {next_rotation}")
        self.logger(f"Path pool generated with {len(path_pool)} paths for modular operations")
        
        return True
    
    def _generate_path(self, rotation_id, path_type):
        """
        Generate a path for a specific type
        
        Args:
            rotation_id: The rotation ID for seed
            path_type: The type of path to generate
        
        Returns:
            A path string
        """
        # Create a deterministic seed based on rotation ID and path type
        seed_str = f"{rotation_id}_{path_type}"
        seed = int.from_bytes(hashlib.md5(seed_str.encode()).digest()[:4], byteorder='little')
        random.seed(seed)
        
        # Get a random pattern and component
        pattern = random.choice(self.url_patterns)
        component = random.choice(self.url_components)
        
        # Generate random parts
        random_part1 = self._random_string(4, 10)
        
        # Restore random state
        random.seed()
        
        # Generate path based on path type
        if path_type == "beacon_path":
            path = f"/{pattern.lower()}/{component}/{random_part1}"
        elif path_type == "agent_path":
            path = f"/{pattern.lower()}/{component}/{random_part1}.js"
        elif path_type == "stager_path":
            path = f"/{pattern.lower()}/{component}/{random_part1}.js"
        elif path_type.endswith("_path"):
            # Other paths use a simplified format
            path = f"/{pattern.lower()}/{component}/{random_part1}"
        else:
            # Default path format
            path = f"/{pattern.lower()}/{component}/{random_part1}"
        
        return path
    
    def get_current_paths(self):
        """Get the current paths"""
        # Make sure all required paths are present
        for key, path in self.default_paths.items():
            if key not in self.current_paths:
                self.current_paths[key] = path
                self.logger(f"Added missing path {key}: {path} to current paths")
        return self.current_paths.copy()
    
    def get_path_by_rotation_id(self, rotation_id):
        """
        Get paths for a specific rotation ID
        
        Args:
            rotation_id: The rotation ID to look up
            
        Returns:
            Dictionary of paths or None if not found
        """
        for entry in self.path_history:
            if entry["rotation_id"] == rotation_id:
                # Ensure all required paths are included
                paths = entry["paths"].copy()
                for key, path in self.default_paths.items():
                    if key not in paths:
                        paths[key] = path
                return paths
        
        # If not found in history, generate it deterministically
        if rotation_id > 0:
            paths = {}
            for path_type in self.default_paths:
                paths[path_type] = self._generate_path(rotation_id, path_type)
            
            # Generate path pool with current pool size
            paths["path_pool"] = self.generate_path_pool(rotation_id, pool_size=self.pool_size)
            return paths
        
        return None
    
    def get_next_rotation_time(self):
        """Get timestamp of the next scheduled rotation"""
        return self.last_rotation_time + self.rotation_interval
    
    def get_rotation_info(self):
        """Get information about current rotation state"""
        current_time = int(time.time())
        next_rotation = self.last_rotation_time + self.rotation_interval
        time_until_next = max(0, next_rotation - current_time)
        
        return {
            "current_rotation_id": self.rotation_counter,
            "last_rotation_time": self.last_rotation_time,
            "next_rotation_time": next_rotation,
            "time_until_next_rotation": time_until_next,
            "current_paths": self.current_paths,
            "rotation_interval": self.rotation_interval,
            "pool_size": self.pool_size  # Include pool size in rotation info
        }