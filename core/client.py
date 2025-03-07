import datetime
import os
import json
import hashlib
from utils.client_identity import generate_client_id, extract_system_info

class ClientManager:
    def __init__(self, log_event):
        # key: client_id, value: dict with keys: last_seen, ip, hostname, pending_commands, history, system_info
        self.clients = {}
        self.command_update_callbacks = {}  # Dictionary to store callbacks
        self.log_event = log_event  # This is now the log_client_event method from LogManager
        self.client_verifier = None  # Will be set by the server to the ClientVerifier instance
        self.client_keys = {}  # Storage for client-specific encryption keys

    def add_client(self, ip, hostname="Unknown", username="Unknown", machine_guid="Unknown", 
                os_version="Unknown", mac_address="Unknown", system_info=None, existing_id=None):
        """Register a client using IP address as the client ID"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if system_info is None:
            system_info = {}
        
        # Use the existing_id if provided (should be the IP), otherwise use IP
        client_id = existing_id if existing_id else ip
        
        # Handle updating existing client
        if client_id in self.clients:
            # Update existing client information
            self.clients[client_id]["last_seen"] = now
            
            # Only update these fields if they're not "Unknown"
            if hostname != "Unknown":
                self.clients[client_id]["hostname"] = hostname
            if username != "Unknown":
                self.clients[client_id]["username"] = username
            if machine_guid != "Unknown":
                self.clients[client_id]["machine_guid"] = machine_guid
            if os_version != "Unknown":
                self.clients[client_id]["os_version"] = os_version
            if mac_address != "Unknown":
                self.clients[client_id]["mac_address"] = mac_address
            
            # Update any new system info values
            if system_info:
                if "system_info" not in self.clients[client_id]:
                    self.clients[client_id]["system_info"] = {}
                
                for key, value in system_info.items():
                    # Don't overwrite with empty or Unknown values
                    if value and value != "Unknown":
                        self.clients[client_id]["system_info"][key] = value
                        
            self.log_event(client_id, "Client Updated", f"Client reconnected: {hostname}/{username}")
        else:
            # Create new client entry
            self.clients[client_id] = {
                "last_seen": now,
                "ip": ip,
                "hostname": hostname,
                "username": username,
                "machine_guid": machine_guid,
                "os_version": os_version,
                "mac_address": mac_address,
                "system_info": system_info,
                "pending_commands": [],
                "history": [],
                "verification_status": {
                    "verified": False,
                    "confidence": 0,
                    "warnings": ["New client"]
                }
            }
            self.log_event(client_id, "Client Connected", f"New client connected: {hostname}/{username}")
        
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
        # If we know the client already
        if client_id in self.clients:
            command = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command_type": command_type,
                "args": args
            }
            self.clients[client_id]["pending_commands"].append(command)
            self.clients[client_id]["history"].append(command)
            self.log_event(client_id, "Command added", f"Command {command_type} with args {args} was added")
            
            # Notify listeners that a command has been added
            self.on_command_updated(client_id)
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
        if client_id in self.clients:
            # Find the command with the matching timestamp
            found = False
            for command in self.clients[client_id]["history"]:
                if command.get("timestamp") == timestamp:
                    command["result"] = result
                    self.log_event(client_id, "Command Result", f"Result received for command at {timestamp}")
                    found = True
                    
                    # Notify listeners that the command has been updated
                    self.on_command_updated(client_id)
            
            if not found:
                # Handle case where the command might be missing from history
                self.log_event(client_id, "Command Result", f"Received result for unknown command timestamp: {timestamp}")
                
                # Create a placeholder command with the result
                command = {
                    "timestamp": timestamp,
                    "command_type": "unknown",
                    "args": "",
                    "result": result
                }
                self.clients[client_id]["history"].append(command)
                self.on_command_updated(client_id)
            
            return found
        return False

    def get_clients_info(self):
        """Get information about all clients"""
        return self.clients

    def get_client_history(self, client_id):
        """Get command history for a specific client"""
        return self.clients.get(client_id, {}).get("history", [])

    def get_pending_commands(self, client_id):
        """Get pending commands for a specific client"""
        return self.clients.get(client_id, {}).get("pending_commands", [])

    def clear_pending_commands(self, client_id):
        """Clear all pending commands for a client"""
        if client_id in self.clients:
            self.clients[client_id]["pending_commands"] = []
            self.log_event(client_id, "Commands cleared", f"Pending commands cleared")

    def register_command_update_callback(self, client_id, callback):
        """Registers a callback to be called when a command result is updated."""
        self.command_update_callbacks.setdefault(client_id, []).append(callback)

    def on_command_updated(self, client_id):
        """Calls all registered callbacks for the given client."""
        for callback in self.command_update_callbacks.get(client_id, []):
            callback()

    def has_unique_key(self, client_id):
        """Check if client already has a unique key"""
        # Direct check in client_keys dictionary
        if client_id in self.client_keys:
            return True
        
        # Additional check in client info if available
        if client_id in self.clients:
            if 'key_rotation_time' in self.clients[client_id]:
                # If we have a rotation time recorded, assume the key exists
                return True
        
        return False

    def set_client_key(self, client_id, key):
        """Set a unique key for a client"""
        self.client_keys[client_id] = key
        
        # Add timestamp for key rotation
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Update client info with key rotation time
        if client_id in self.clients:
            self.clients[client_id]['key_rotation_time'] = current_time
        
        self.log_event(client_id, "Security", "Unique encryption key assigned after verification")
        
        # Save keys to disk for persistence
        self._save_client_keys()
        
    def _save_client_keys(self):
        """Save client keys to disk for persistence"""
        if not self.client_keys:
            return
            
        # Don't save actual keys, just record which clients have unique keys
        client_key_status = {}
        for client_id in self.client_keys:
            client_key_status[client_id] = {
                "has_unique_key": True,
                "assigned_at": self._current_timestamp()
            }
        
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