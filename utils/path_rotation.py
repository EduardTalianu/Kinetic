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
        
        self.logger(f"Path rotation manager initialized with interval {rotation_interval} seconds")
    
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
    
    def _generate_path(self, seed, path_type, length=8):
        """
        Generate a deterministic but unpredictable path based on seed and path type
        
        Args:
            seed: Seed value (e.g. rotation counter)
            path_type: Type of path (e.g. 'beacon', 'agent')
            length: Length of the random part of the path
            
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
        
        # Patterns for different path types to make them look legitimate
        patterns = {
            "beacon_path": [
                f"/api/v{random.randint(1,3)}/status/{self._random_string(length)}",
                f"/app/{self._random_string(length-2)}/ping",
                f"/srv/status/check/{self._random_string(length-3)}",
                f"/monitor/{self._random_string(length)}",
                f"/health/{self._random_string(length-2)}/check"
            ],
            "agent_path": [
                f"/assets/js/lib/{self._random_string(length)}.js",
                f"/static/scripts/{self._random_string(length-2)}.min.js",
                f"/cdn/lib/{self._random_string(length)}.js",
                f"/resources/js/{self._random_string(length-3)}_bundle.js",
                f"/dist/{self._random_string(length)}/main.js"
            ],
            "stager_path": [
                f"/scripts/loader/{self._random_string(length-2)}.js",
                f"/cdn/init/{self._random_string(length)}.js",
                f"/app/bootstrap/{self._random_string(length-3)}.js",
                f"/assets/core/{self._random_string(length-1)}.min.js",
                f"/lib/init-{self._random_string(length-5)}.js"
            ],
            "cmd_result_path": [
                f"/api/data/{self._random_string(length)}",
                f"/feedback/{self._random_string(length-2)}",
                f"/log/events/{self._random_string(length-3)}",
                f"/analytics/{self._random_string(length)}",
                f"/reports/{self._random_string(length-2)}/submit"
            ],
            "file_upload_path": [
                f"/api/storage/{self._random_string(length)}",
                f"/upload/files/{self._random_string(length-2)}",
                f"/cdn/store/{self._random_string(length-3)}",
                f"/content/upload/{self._random_string(length-2)}",
                f"/media/{self._random_string(length)}/upload"
            ]
        }
        
        # Select a pattern based on the hash to make it deterministic
        pattern_index = int(hash_hex[0], 16) % len(patterns.get(path_type, ["/{self._random_string(length)}"]))
        selected_pattern = patterns.get(path_type, [f"/{path_type}/{self._random_string(length)}"])[pattern_index]
        
        # Restore the global random state to avoid affecting other code
        random.setstate(random.getstate())
        
        return selected_pattern
    
    def _random_string(self, length=8, include_numbers=True):
        """Generate a random string"""
        chars = string.ascii_lowercase
        if include_numbers:
            chars += string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
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