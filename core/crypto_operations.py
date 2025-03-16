import os
import base64
import json
import logging

logger = logging.getLogger(__name__)

class CryptoHelper:
    """
    Handles encryption and decryption operations for client communication
    Acts as a wrapper around the EncryptionService
    """
    
    def __init__(self, encryption_service, client_manager):
        """
        Initialize the crypto helper
        
        Args:
            encryption_service: The central encryption service
            client_manager: The client manager instance
        """
        self.encryption_service = encryption_service
        self.client_manager = client_manager
    
    def get_client_key(self, client_id):
        """
        Get the appropriate encryption key for a client
        
        Args:
            client_id: Client ID
            
        Returns:
            The encryption key
        """
        # This now just queries the encryption service
        return self.encryption_service.get_key(client_id)

    def _has_unique_key(self, client_id):
        """
        Check if client has a unique encryption key
        
        Args:
            client_id: Client ID
            
        Returns:
            True if the client has a unique key, False otherwise
        """
        return self.encryption_service.has_client_key(client_id)

    def encrypt(self, data, client_id=None):
        """
        Encrypt data using client key if available, otherwise generate a temporary key
        
        Args:
            data: Data to encrypt
            client_id: Client ID (optional)
            
        Returns:
            Encrypted data (base64 string)
        """
        return self.encryption_service.encrypt(data, client_id)
    
    def decrypt(self, encrypted_data, client_id=None):
        """
        Decrypt data using client key if available
        
        Args:
            encrypted_data: Encrypted data (base64 string)
            client_id: Client ID (optional)
            
        Returns:
            Decrypted data
        """
        return self.encryption_service.decrypt(encrypted_data, client_id)
    
    def identify_client_by_decryption(self, encrypted_data):
        """
        Identify client by trying each client key for decryption
        
        Args:
            encrypted_data: Encrypted data to attempt decryption
            
        Returns:
            tuple: (client_id, decrypted_data) or (None, None) if no key works
        """
        return self.encryption_service.identify_client_by_decryption(encrypted_data)