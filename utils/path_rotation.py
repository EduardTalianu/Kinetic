import time
import random
import string
import hashlib
import json
import os
from datetime import datetime, timedelta

class PathRotationManager:
    def __init__(self, campaign_folder, logger, initial_paths=None, rotation_interval=3600, pool_size=30):
        """
        Initialize the path rotation manager
        
        Args:
            campaign_folder: Path to the campaign folder
            logger: Logger function to log events
            initial_paths: Initial URL paths (optional) - will be ignored in pool-only mode
            rotation_interval: Time in seconds between path rotations (default: 1 hour)
            pool_size: Number of paths to generate in the path pool (default: 30)
        """
        self.campaign_folder = campaign_folder
        self.logger = logger
        self.rotation_interval = rotation_interval
        self.last_rotation_time = int(time.time())
        self.rotation_counter = 0
        self.path_history = []
        self.pool_size = pool_size  # Store the path pool size
        
        # Create the state file if it doesn't exist
        self.state_file = os.path.join(self.campaign_folder, "path_rotation_state.json")
        
        # Load URL patterns and components
        self.url_patterns = self._load_url_patterns()
        self.url_components = self._load_url_components()
        
        # Generate path pool - this is now our only path storage mechanism
        self.current_paths = {"path_pool": self.generate_path_pool(self.rotation_counter, pool_size=self.pool_size)}
        
        # Save initial state
        self._save_state()
        
        self.logger(f"Pool-only path rotation manager initialized with interval {rotation_interval} seconds and pool size {pool_size}")
        self.logger(f"Generated {len(self.current_paths['path_pool'])} paths in pool")
    
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
            "pool_size": self.pool_size
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
                self.pool_size = state.get("pool_size", self.pool_size)
                
                # Make sure we have a path_pool
                if "path_pool" not in self.current_paths or not self.current_paths["path_pool"]:
                    self.current_paths["path_pool"] = self.generate_path_pool(self.rotation_counter, pool_size=self.pool_size)
                    self.logger(f"Generated new path pool after loading state")
                
                self.logger(f"Path rotation state loaded from {self.state_file}")
                self.logger(f"Current path pool has {len(self.current_paths['path_pool'])} paths")
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
        
        # Generate a pool of paths - this is all we need now
        path_pool = self.generate_path_pool(self.rotation_counter, pool_size=self.pool_size)
        
        # Update current paths
        self.current_paths = {"path_pool": path_pool}
        
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
        next_rotation = datetime.fromtimestamp(self.last_rotation_time + self.rotation_interval)
        self.logger(f"Path rotation {self.rotation_counter} completed. Next rotation at {next_rotation}")
        self.logger(f"Path pool generated with {len(path_pool)} paths")
        
        return True
    
    def get_current_paths(self):
        """Get the current paths"""
        # Just return the current paths - we only have the path_pool now
        return self.current_paths
    
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
                return entry["paths"]
        
        # If not found in history, generate it deterministically
        if rotation_id > 0:
            # Generate path pool with current pool size
            paths = {"path_pool": self.generate_path_pool(rotation_id, pool_size=self.pool_size)}
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
            "pool_size": self.pool_size
        }