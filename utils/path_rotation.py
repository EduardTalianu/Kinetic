import time
import random
import string
import hashlib
import json
import os
from datetime import datetime, timedelta

class PathRotationManager:
    def __init__(self, campaign_folder, logger, initial_paths=None, rotation_interval=3600):
        """
        Initialize the path rotation manager
        
        Args:
            campaign_folder: Path to the campaign folder
            logger: Logger function to log events
            initial_paths: Initial URL paths (optional)
            rotation_interval: Time in seconds between path rotations (default: 1 hour)
        """
        self.campaign_folder = campaign_folder
        self.logger = logger
        self.rotation_interval = rotation_interval
        self.last_rotation_time = int(time.time())
        self.rotation_counter = 0
        self.path_history = []
        
        # Default paths as fallback
        self.default_paths = {
            "beacon_path": "/beacon",
            "agent_path": "/raw_agent",
            "stager_path": "/b64_stager",
            "cmd_result_path": "/command_result",
            "file_upload_path": "/file_upload"
        }
        
        # Set current paths to initial_paths or defaults
        self.current_paths = initial_paths.copy() if initial_paths else self.default_paths.copy()
        
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
        
        self.logger(f"Path rotation manager initialized with interval {rotation_interval} seconds")
    
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
            "rotation_interval": self.rotation_interval
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
                
                self.logger(f"Path rotation state loaded from {self.state_file}")
                return True
            except Exception as e:
                self.logger(f"Error loading path rotation state: {e}")
                return False
        return False
    
    def _generate_path(self, seed, path_type, min_length=4, max_length=12):
        """
        Generate a deterministic but unpredictable path based on seed and path type
        
        Args:
            seed: Seed value (e.g. rotation counter)
            path_type: Type of path (e.g. 'beacon', 'agent')
            min_length: Minimum length of the random part of the path
            max_length: Maximum length of the random part of the path
            
        Returns:
            Generated path string with leading slash
        """
        # Create a deterministic seed by combining the rotation counter and path type
        combined_seed = f"{seed}_{path_type}"
        
        # Use SHA-256 hash to get a deterministic but unpredictable value
        hash_obj = hashlib.sha256(combined_seed.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Use the hash to seed the random generator for this specific path
        random.seed(int(hash_hex, 16) % (2**32))
        
        # Select a pattern category based on hash (deterministic)
        pattern_selector = int(hash_hex[0:2], 16) % len(self.url_patterns)
        selected_pattern_type = self.url_patterns[pattern_selector]
        
        # Select a component based on hash (deterministic)
        component_selector = int(hash_hex[2:4], 16) % len(self.url_components)
        selected_component = self.url_components[component_selector]
        
        # Generate the random part of the path deterministically with variable length
        length_seed = int(hash_hex[4:8], 16)
        random_part = self._random_string(min_length, max_length, seed=length_seed)
        
        # For custom pattern, use a different structure
        if selected_pattern_type == "custom":
            if path_type == "beacon_path":
                path = f"/custom/{random_part}/beacon"
            elif path_type == "agent_path":
                path = f"/custom/{random_part}/agent.js"
            elif path_type == "stager_path":
                path = f"/custom/{random_part}/loader.js"
            elif path_type == "cmd_result_path":
                path = f"/custom/{random_part}/results"
            elif path_type == "file_upload_path":
                path = f"/custom/{random_part}/upload"
            else:
                path = f"/custom/{random_part}/{path_type.replace('_path', '')}"
        else:
            # Base path using the selected pattern
            base_path = f"/{selected_pattern_type.lower()}"
            
            # Create paths based on path type
            if path_type == "beacon_path":
                path = f"{base_path}/{selected_component}/{random_part}"
            elif path_type == "agent_path" or path_type == "stager_path":
                path = f"{base_path}/{selected_component}/{random_part}.js"
            else:
                path = f"{base_path}/{selected_component}/{random_part}"
        
        # Restore the global random state to avoid affecting other code
        random.setstate(random.getstate())
        
        return path
        
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
        
        # Generate new paths for each type
        new_paths = {}
        for path_type in self.current_paths:
            new_paths[path_type] = self._generate_path(self.rotation_counter, path_type)
        
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
        next_rotation = datetime.fromtimestamp(self.last_rotation_time + self.rotation_interval)
        self.logger(f"Path rotation {self.rotation_counter} completed. Next rotation at {next_rotation}")
        
        return True
    
    def get_current_paths(self):
        """Get the current paths"""
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
                return entry["paths"].copy()
        
        # If not found in history, generate it deterministically
        if rotation_id > 0:
            paths = {}
            for path_type in self.default_paths:
                paths[path_type] = self._generate_path(rotation_id, path_type)
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
            "rotation_interval": self.rotation_interval
        }