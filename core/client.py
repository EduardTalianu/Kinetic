import datetime
import os
import json
import hashlib
import string
import random
from utils.client_identity import generate_client_id, extract_system_info

class ClientManager:
    def __init__(self, log_event):
        # key: client_id, value: dict with keys: last_seen, ip, hostname, pending_commands, history, system_info
        self.clients = {}
        self.command_update_callbacks = {}  # Dictionary to store callbacks
        self.log_event = log_event  # This is now the log_client_event method from LogManager
        self.client_verifier = None  # Will be set by the server to the ClientVerifier instance
        self.client_keys = {}  # Storage for client-specific encryption keys
        self.clients = {}
        self.command_update_callbacks = {}
        self.log_event = log_event
        self.client_verifier = None
        self.client_keys = {}
        
        # New fields for auto rotation
        self.auto_rotation_enabled = True  # Default enabled
        self.rotation_frequency = 17  # Default frequency is 17 communications
        self.load_rotation_config()  # Load configuration from file if available

    def add_client(self, ip, hostname="Unknown", username="Unknown", machine_guid="Unknown", 
                os_version="Unknown", mac_address="Unknown", system_info=None, client_id=None, current_id=None):
        """Register a client using ClientId as the primary identifier"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if system_info is None:
            system_info = {}
        
        # Use the provided client_id, or generate one based on system info, or fall back to IP
        if not client_id:
            if machine_guid != "Unknown":
                client_id = generate_client_id(ip, hostname, username, machine_guid, os_version)
            else:
                client_id = ip
        
        # Handle updating existing client
        if client_id in self.clients:
            # Update existing client information
            self.clients[client_id]["last_seen"] = now
            self.clients[client_id]["ip"] = ip
            
            # Update current_client_id if provided and different
            if current_id and current_id != client_id and current_id != self.clients[client_id].get("current_client_id"):
                self.clients[client_id]["current_client_id"] = current_id
                self.log_event(client_id, "Security", f"Client ID tracking updated to {current_id}")
            
            # Only update these fields if they're not "Unknown"
            if hostname != "Unknown":
                self.clients[client_id]["hostname"] = hostname
            
            # Update any new system info values
            if system_info:
                if "system_info" not in self.clients[client_id]:
                    self.clients[client_id]["system_info"] = {}
                
                for key, value in system_info.items():
                    # Don't overwrite with empty or Unknown values
                    if value and value != "Unknown":
                        self.clients[client_id]["system_info"][key] = value
                        
            self.log_event(client_id, "Client Updated", f"Client reconnected: {hostname}")
        else:
            # Create new client entry
            self.clients[client_id] = {
                "last_seen": now,
                "ip": ip,
                "hostname": hostname,
                "system_info": system_info,
                "pending_commands": [],
                "history": [],
                "verification_status": {
                    "verified": True,
                    "confidence": 100,
                    "warnings": ["New client"]
                },
                # Add communication counter for auto rotation
                "communication_counter": 0,
                # Track rotation commands
                "rotation_commands_sent": 0
            }
            
            # Set current client ID if provided and different
            if current_id and current_id != client_id:
                self.clients[client_id]["current_client_id"] = current_id
                self.clients[client_id]["original_client_id"] = client_id
                self.log_event(client_id, "Security", f"Client initialized with rotated ID {current_id}")
            
            self.log_event(client_id, "Client Connected", f"New client connected: {hostname} from {ip}")
        
        # Ensure client info is saved to disk
        self._save_clients()
        
        # Force a refresh of the client list in the UI
        if hasattr(self, 'on_client_updated') and callable(self.on_client_updated):
            self.on_client_updated()
        
        return client_id

    def update_client_id_mapping(self, original_id, current_id):
        """Update the mapping between original and current client ID"""
        if original_id in self.clients:
            # Store the current ID in the client info
            self.clients[original_id]['current_client_id'] = current_id
            # Also store the original ID to make it easier to track
            if 'original_client_id' not in self.clients[original_id]:
                self.clients[original_id]['original_client_id'] = original_id
            
            # If this is not the first rotation, ensure the new ID also points back to original
            if current_id != original_id:
                # Create an entry for the new ID if it doesn't exist yet
                if current_id not in self.clients:
                    # Copy minimal information to the new ID entry
                    self.clients[current_id] = {
                        "last_seen": self.clients[original_id]["last_seen"],
                        "ip": self.clients[original_id]["ip"],
                        "hostname": self.clients[original_id].get("hostname", "Unknown"),
                        "pending_commands": [],  # Start with no pending commands
                        "history": [],           # Start with no history
                        "original_client_id": original_id,  # Point back to true original
                        "communication_counter": 0,  # Reset counter for the new ID
                        "rotation_commands_sent": 0   # Reset rotation tracking
                    }
                    
                    # Copy verification status if available
                    if "verification_status" in self.clients[original_id]:
                        self.clients[current_id]["verification_status"] = self.clients[original_id]["verification_status"].copy()
                    
                    # Copy system info if available, but only essential fields
                    if "system_info" in self.clients[original_id]:
                        self.clients[current_id]["system_info"] = {}
                        for key, value in self.clients[original_id]["system_info"].items():
                            if key in ["Hostname", "IP", "Username", "OsVersion", "MacAddress"]:
                                self.clients[current_id]["system_info"][key] = value
                else:
                    # Update existing entry to point to original
                    # Make sure we're pointing to the true original, not an intermediate ID
                    true_original = self.get_true_original_id(original_id)
                    if true_original and true_original in self.clients:
                        self.clients[current_id]["original_client_id"] = true_original
                    else:
                        # Fall back to the provided original ID
                        self.clients[current_id]["original_client_id"] = original_id
            
            self.log_event(original_id, "Security", f"Client ID rotated to {current_id}")
            
            # Save the updated client info
            self._save_clients()
            
            # If we're using client-specific keys, make sure they're accessible via both IDs
            if hasattr(self, 'client_keys') and original_id in self.client_keys:
                # Copy the key to be accessible via both IDs
                self.client_keys[current_id] = self.client_keys[original_id]
            
            return True
        return False

    def get_true_original_id(self, client_id):
        """
        Recursively trace back through the client ID chain to find the first original ID
        
        Args:
            client_id: The client ID to start the search from
            
        Returns:
            The true original client ID or the input client_id if the chain can't be traced
        """
        if not client_id or client_id not in self.clients:
            return client_id
            
        visited_ids = set()  # To detect cycles
        current_id = client_id
        
        while current_id and current_id in self.clients:
            # Check for cycles
            if current_id in visited_ids:
                # We found a cycle, break and use the last valid ID
                break
                
            visited_ids.add(current_id)
            
            # Get the recorded original ID for this client
            original_id = self.clients[current_id].get("original_client_id")
            
            # If it's the same as current or not set, we've reached the start of the chain
            if not original_id or original_id == current_id:
                return current_id
                
            # Continue tracing back
            current_id = original_id
        
        # If we couldn't find the true original, return the input ID
        return client_id

    def get_client_by_current_id(self, current_id):
        """Find the original client ID by the current rotated ID"""
        for client_id, client_info in self.clients.items():
            if client_info.get('current_client_id') == current_id:
                return client_id
        return None

    def get_original_client_id(self, client_id):
        """Find the original client ID regardless of whether client_id is original or current"""
        # First check if this is already an original ID
        if client_id in self.clients:
            # If it has an original_client_id field that's different from itself,
            # it's a rotated ID, so get the original
            if "original_client_id" in self.clients[client_id] and self.clients[client_id]["original_client_id"] != client_id:
                return self.clients[client_id]["original_client_id"]
            # Otherwise it might be an original ID itself
            return client_id
        
        # If not found, just return the input ID
        return client_id

    def get_current_client_id(self, original_id):
        """Get the current client ID for an original ID"""
        if original_id in self.clients:
            return self.clients[original_id].get('current_client_id', original_id)
        return original_id

    def get_client_display_name(self, client_id):
        """Get a display name for the client showing original and current IDs if rotated"""
        if client_id in self.clients:
            client_info = self.clients[client_id]
            current_id = client_info.get('current_client_id')
            
            if current_id and current_id != client_id:
                return f"{client_id} → {current_id}"
            return client_id
        return client_id

    def set_verification_status(self, client_id, is_verified, confidence=None, warnings=None):
        """Set the verification status for a client"""
        if client_id not in self.clients:
            return
            
        # Update the verification_status dictionary properly
        self.clients[client_id]['verification_status'] = {
            "verified": is_verified,
            "confidence": confidence if confidence is not None else self.clients[client_id]['verification_status'].get('confidence', 0),
            "warnings": warnings if warnings else self.clients[client_id]['verification_status'].get('warnings', [])
        }
                
        if is_verified:
            self.log_event(client_id, "Security", f"Client verified with {confidence:.1f}% confidence")
        else:
            warning_str = ", ".join(warnings) if warnings else "Unknown issues"
            self.log_event(client_id, "Security", f"Client verification failed ({warning_str})")

    def add_command(self, client_id, command_type, args, ip="Unknown", hostname="Unknown"):
        """Add a command to the client's pending commands"""
        # Find the original client ID if we're given a rotated ID
        original_id = self.get_original_client_id(client_id)
        
        # If we know the client already
        if original_id in self.clients:
            command = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command_type": command_type,
                "args": args
            }
            self.clients[original_id]["pending_commands"].append(command)
            self.clients[original_id]["history"].append(command)
            self.log_event(original_id, "Command added", f"Command {command_type} with args {args} was added")
            
            # Notify listeners that a command has been added
            self.on_command_updated(original_id)
            return True
        else:
            # Check if this is a key_rotation command - these should only be added to known clients
            if command_type == "key_rotation":
                self.log_event("ERROR", "Command Error", f"Cannot add key_rotation command for unknown client {client_id}")
                return
                
            # For backward compatibility, try to register client by IP if it's a valid client ID
            try:
                ip_address = ip if ip != "Unknown" else client_id
                self.add_client(ip_address, hostname)
                # Avoid recursion - directly add the command after registering the client
                if ip_address in self.clients:
                    command = {
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "command_type": command_type,
                        "args": args
                    }
                    self.clients[ip_address]["pending_commands"].append(command)
                    self.clients[ip_address]["history"].append(command)
                    self.log_event(ip_address, "Command added", f"Command {command_type} with args {args} was added")
                    self.on_command_updated(ip_address)
                else:
                    self.log_event("ERROR", "Command Error", f"Failed to add client for {ip_address}")
            except Exception as e:
                self.log_event("ERROR", "Command Error", f"Failed to add command for unknown client {client_id}: {str(e)}")

    def add_command_result(self, client_id, timestamp, result):
        """Add a result to a command in the client's history"""
        # Find the original client ID if we're given a rotated ID
        original_id = self.get_original_client_id(client_id)
        
        if original_id in self.clients:
            # Find the command with the matching timestamp
            found = False
            for command in self.clients[original_id]["history"]:
                if command.get("timestamp") == timestamp:
                    command["result"] = result
                    self.log_event(original_id, "Command Result", f"Result received for command at {timestamp}")
                    found = True
                    
                    # Notify listeners that the command has been updated
                    self.on_command_updated(original_id)
            
            if not found:
                # Handle case where the command might be missing from history
                self.log_event(original_id, "Command Result", f"Received result for unknown command timestamp: {timestamp}")
                
                # Create a placeholder command with the result
                command = {
                    "timestamp": timestamp,
                    "command_type": "unknown",
                    "args": "",
                    "result": result
                }
                self.clients[original_id]["history"].append(command)
                self.on_command_updated(original_id)
            
            return found
        return False

    def get_clients_info(self):
        """Get information about all clients"""
        return self.clients

    def get_client_history(self, client_id):
        """Get command history for a specific client"""
        # Find the original client ID
        original_id = self.get_original_client_id(client_id)
        
        # Get the history from the original ID
        history = self.clients.get(original_id, {}).get("history", [])
        
        # Also check if this client has a current ID and get history from there too
        current_id = self.get_current_client_id(original_id)
        if current_id and current_id != original_id and current_id in self.clients:
            # Add history from current ID if it exists and has any
            current_history = self.clients.get(current_id, {}).get("history", [])
            if current_history:
                # Combine histories, but avoid duplicates based on timestamp
                existing_timestamps = {cmd.get("timestamp") for cmd in history}
                for cmd in current_history:
                    if cmd.get("timestamp") not in existing_timestamps:
                        history.append(cmd)
                
                # Sort combined history by timestamp
                history.sort(key=lambda cmd: cmd.get("timestamp", ""))
        
        return history

    def get_pending_commands(self, client_id):
        """Get pending commands for a specific client"""
        # Find the original client ID
        original_id = self.get_original_client_id(client_id)
        
        # Get pending commands from original ID
        commands = self.clients.get(original_id, {}).get("pending_commands", [])
        
        # Also check the current ID if different
        current_id = self.get_current_client_id(original_id)
        if current_id and current_id != original_id and current_id in self.clients:
            # Add pending commands from current ID
            current_commands = self.clients.get(current_id, {}).get("pending_commands", [])
            if current_commands:
                # Check for duplicates based on timestamp
                existing_timestamps = {cmd.get("timestamp") for cmd in commands}
                for cmd in current_commands:
                    if cmd.get("timestamp") not in existing_timestamps:
                        commands.append(cmd)
        
        return commands

    def clear_pending_commands(self, client_id):
        """Clear all pending commands for a client"""
        # Find the original client ID if we're given a rotated ID
        original_id = self.get_original_client_id(client_id)
        
        if original_id in self.clients:
            self.clients[original_id]["pending_commands"] = []
            self.log_event(original_id, "Commands cleared", f"Pending commands cleared")

    def register_command_update_callback(self, client_id, callback):
        """Registers a callback to be called when a command result is updated."""
        # Find the original client ID if we're given a rotated ID
        original_id = self.get_original_client_id(client_id)
        self.command_update_callbacks.setdefault(original_id, []).append(callback)

    def on_command_updated(self, client_id):
        """Calls all registered callbacks for the given client."""
        # First call callbacks registered for the original ID
        for callback in self.command_update_callbacks.get(client_id, []):
            callback()
            
        # Also check if this client has a current ID and call those callbacks
        if client_id in self.clients:
            current_id = self.clients[client_id].get('current_client_id')
            if current_id and current_id != client_id:
                # Call callbacks for current ID as well, if any exist
                for callback in self.command_update_callbacks.get(current_id, []):
                    callback()

    def has_unique_key(self, client_id):
        """Check if client already has a unique key"""
        # Find the original client ID if we're given a rotated ID
        original_id = self.get_original_client_id(client_id)
        
        # Direct check in client_keys dictionary
        if original_id in self.client_keys:
            return True
            
        # Also check for current ID if applicable
        if original_id in self.clients:
            current_id = self.clients[original_id].get('current_client_id')
            if current_id and current_id != original_id and current_id in self.client_keys:
                return True
        
        # Additional check in client info if available
        if original_id in self.clients:
            if 'key_rotation_time' in self.clients[original_id]:
                # If we have a rotation time recorded, assume the key exists
                return True
        
        return False

    def set_client_key(self, client_id, key):
        """Set a unique key for a client"""
        # Find the original client ID if we're given a rotated ID
        original_id = self.get_original_client_id(client_id)
        
        # Store the key under the original ID
        self.client_keys[original_id] = key
        
        # Also store under current ID if different
        if original_id in self.clients:
            current_id = self.clients[original_id].get('current_client_id')
            if current_id and current_id != original_id:
                # Also store the key for the current ID
                self.client_keys[current_id] = key
        
        # Add timestamp for key rotation
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Update client info with key rotation time
        if original_id in self.clients:
            self.clients[original_id]['key_rotation_time'] = current_time
        
        self.log_event(original_id, "Security", "Unique encryption key assigned after verification")
        
        # Save keys to disk for persistence
        self._save_client_keys()
        
    def _save_client_keys(self):
        """Save client keys to disk for persistence"""
        if not self.client_keys:
            return
            
        # Don't save actual keys, just record which clients have unique keys
        client_key_status = {}
        for client_id in self.client_keys:
            # Only record info for original client IDs
            if client_id in self.clients and self.clients[client_id].get('original_client_id') == client_id:
                client_key_status[client_id] = {
                    "has_unique_key": True,
                    "assigned_at": self._current_timestamp()
                }
                
                # Also record current ID mapping if applicable
                current_id = self.clients[client_id].get('current_client_id')
                if current_id and current_id != client_id:
                    client_key_status[client_id]["current_id"] = current_id
        
        # Create client_keys.json in the campaign folder
        for client_id, client_info in self.clients.items():
            if 'campaign_folder' in client_info:
                campaign_folder = client_info['campaign_folder']
                client_keys_file = os.path.join(campaign_folder, "client_keys.json")
                
                try:
                    os.makedirs(os.path.dirname(client_keys_file), exist_ok=True)
                    with open(client_keys_file, 'w') as f:
                        json.dump(client_key_status, f, indent=2)
                    break
                except Exception as e:
                    self.log_event("ERROR", f"Error saving client key status: {e}")
                    
        # Also log to clients.json for reference
        self._save_clients()

    def _current_timestamp(self):
        """Get current timestamp in ISO format"""
        return datetime.datetime.now().isoformat()

    def _save_clients(self):
        """Save client information to the clients.json file in the campaign folder"""
        # First check if we know which campaign folder to use
        campaign_folder = None
        
        # Try to find a campaign folder from any client's info
        for client_id, client_info in self.clients.items():
            if 'system_info' in client_info and 'campaign_folder' in client_info['system_info']:
                campaign_folder = client_info['system_info']['campaign_folder']
                break
            elif 'campaign_folder' in client_info:
                campaign_folder = client_info['campaign_folder']
                break
        
        # If we couldn't find a campaign folder, try to detect it
        if not campaign_folder:
            # Look for campaign directories in the current directory
            campaign_dirs = [d for d in os.listdir() if d.endswith("_campaign") and os.path.isdir(d)]
            if campaign_dirs:
                # Use the first campaign found
                campaign_folder = campaign_dirs[0]
        
        # If we still don't have a campaign folder, we can't save
        if not campaign_folder:
            self.log_event("ERROR", "Storage Error", "Cannot save clients: campaign folder not found")
            return
        
        # Prepare client data for saving (removing any sensitive information)
        client_data = {}
        for client_id, client_info in self.clients.items():
            # Skip saving non-original client IDs (those that are just aliases)
            if client_info.get('original_client_id') != client_id and client_info.get('original_client_id'):
                continue
                
            # Create a clean copy without sensitive data
            client_data[client_id] = {
                "ip": client_info.get("ip", "Unknown"),
                "hostname": client_info.get("hostname", "Unknown"),
                "username": client_info.get("username", "Unknown"),
                "last_seen": client_info.get("last_seen", "Unknown"),
                "verification_status": client_info.get("verification_status", {
                    "verified": False,
                    "confidence": 0,
                    "warnings": ["Unknown client"]
                })
            }
            
            # Add current ID mapping if applicable
            if "current_client_id" in client_info and client_info["current_client_id"] != client_id:
                client_data[client_id]["current_client_id"] = client_info["current_client_id"]
                
            # Add key rotation time if available
            if "key_rotation_time" in client_info:
                client_data[client_id]["key_rotation_time"] = client_info["key_rotation_time"]
            
            # Add system info without sensitive fields
            if "system_info" in client_info:
                client_data[client_id]["system_info"] = {
                    k: v for k, v in client_info["system_info"].items() 
                    if k not in ["MachineGuid", "BiosSerial", "client_identifier"]
                }
        
        # Save to clients.json in the campaign folder
        clients_file = os.path.join(campaign_folder, "clients.json")
        
        try:
            os.makedirs(os.path.dirname(clients_file), exist_ok=True)
            with open(clients_file, 'w') as f:
                json.dump(client_data, f, indent=2)
        except Exception as e:
            self.log_event("ERROR", "Storage Error", f"Failed to save clients: {str(e)}")
    def load_rotation_config(self):
        """Load rotation configuration from agent_config.json if available"""
        try:
            # Find any campaign folder
            campaign_dirs = [d for d in os.listdir() if d.endswith("_campaign") and os.path.isdir(d)]
            if campaign_dirs:
                # Use the first campaign found
                campaign_folder = campaign_dirs[0]
                config_file = os.path.join(campaign_folder, "agent_config.json")
                
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                    
                    # Load auto rotation settings
                    if "auto_rotation_enabled" in config:
                        self.auto_rotation_enabled = config["auto_rotation_enabled"]
                    if "rotation_frequency" in config:
                        self.rotation_frequency = int(config["rotation_frequency"])
        except Exception as e:
            print(f"Warning: Could not load auto rotation config: {e}")

    def increment_communication_counter(self, client_id):
        """Increment the communication counter for a client and check if rotation is needed"""
        # Find the original client ID
        original_id = self.get_original_client_id(client_id)
        
        if original_id in self.clients:
            # Initialize counter if it doesn't exist
            if "communication_counter" not in self.clients[original_id]:
                self.clients[original_id]["communication_counter"] = 0
            
            # Increment counter
            self.clients[original_id]["communication_counter"] += 1
            counter = self.clients[original_id]["communication_counter"]
            
            # Log the counter (helpful for debugging)
            self.log_event(original_id, "Communication", f"Communication counter: {counter}/{self.rotation_frequency}")
            
            # Check if we need to auto-rotate based on counter and configuration
            if self.auto_rotation_enabled and counter >= self.rotation_frequency:
                # Reset counter
                self.clients[original_id]["communication_counter"] = 0
                
                # Check if client is verified before rotation
                is_verified = self.clients[original_id].get("verification_status", {}).get("verified", False)
                
                if is_verified:
                    # Log that we're auto-rotating
                    self.log_event(original_id, "Security", f"Auto-rotating client ID after {counter} communications")
                    return True  # Signal that rotation is needed
                else:
                    # Skip rotation for unverified clients
                    self.log_event(original_id, "Security", f"Skipping auto-rotation for unverified client (count: {counter})")
            
        return False  # No rotation needed