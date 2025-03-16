import datetime
import os
import json
import hashlib
from utils.client_identity import generate_client_id, extract_system_info

class ClientManager:
    def __init__(self, log_event, encryption_service=None):
        # key: client_id, value: dict with keys: last_seen, ip, hostname, pending_commands, history, system_info
        self.clients = {}
        self.command_update_callbacks = {}  # Dictionary to store callbacks
        self.log_event = log_event  # This is now the log_client_event method from LogManager
        self.client_verifier = None  # Will be set by the server to the ClientVerifier instance
        self.encryption_service = encryption_service  # Reference to the centralized encryption service

    def set_encryption_service(self, encryption_service):
        """Set the encryption service after initialization"""
        self.encryption_service = encryption_service

    def add_client(self, ip, hostname="Unknown", username="Unknown", machine_guid="Unknown", 
                os_version="Unknown", mac_address="Unknown", system_info=None, client_id=None):
        """Register a client using ClientId as the primary identifier"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if system_info is None:
            system_info = {}
        
        # Use the provided client_id, or generate one based on system info, or fall back to IP
        if not client_id:
            if machine_guid != "Unknown":
                client_id = hashlib.sha256(machine_guid.encode()).hexdigest()[:16]
            else:
                client_id = ip
        
        # Handle updating existing client
        if client_id in self.clients:
            # Update existing client information
            self.clients[client_id]["last_seen"] = now
            self.clients[client_id]["ip"] = ip
            
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
                }
            }
            self.log_event(client_id, "Client Connected", f"New client connected: {hostname} from {ip}")
        
        # Ensure client info is saved to disk
        self._save_clients()
        
        # Force a refresh of the client list in the UI
        if hasattr(self, 'on_client_updated') and callable(self.on_client_updated):
            self.on_client_updated()
        
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
        """Check if client already has a unique key - Using encryption service"""
        if self.encryption_service:
            return self.encryption_service.has_client_key(client_id)
        
        # Fallback - check client info
        if client_id in self.clients:
            return 'key_rotation_time' in self.clients[client_id]
        return False

    def set_client_key(self, client_id, key=None):
        """
        Set a unique key for a client - Using encryption service
        
        Args:
            client_id: Client ID
            key: Encryption key (bytes, or None to generate a new key)
            
        Returns:
            The key that was set
        """
        if self.encryption_service:
            # Let the encryption service handle key management
            key = self.encryption_service.set_client_key(client_id, key)
        else:
            # Log warning
            self.log_event("WARNING", "Encryption Warning", "No encryption service available for key management")
            
        # Record the key rotation time in client info
        if client_id in self.clients:
            self.clients[client_id]['key_rotation_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_event(client_id, "Security", "Unique encryption key assigned after verification")
            
        # Save client info to disk
        self._save_clients()
        
        return key
    
    def remove_client_key(self, client_id):
        """
        Remove a client-specific key
        
        Args:
            client_id: Client ID
            
        Returns:
            True if key was removed, False if client had no key
        """
        if self.encryption_service:
            success = self.encryption_service.remove_client_key(client_id)
        else:
            success = False
            self.log_event("WARNING", "Encryption Warning", "No encryption service available for key management")
        
        # Remove key rotation time from client info
        if success and client_id in self.clients and 'key_rotation_time' in self.clients[client_id]:
            del self.clients[client_id]['key_rotation_time']
            self.log_event(client_id, "Security", "Client-specific key removed")
            
            # Save client info to disk
            self._save_clients()
        
        return success

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
            
            # Add key rotation time if available
            if 'key_rotation_time' in client_info:
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