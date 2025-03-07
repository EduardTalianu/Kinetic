import os
import base64
import json
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class CryptoHelper:
    """Handles encryption and decryption operations for client communication"""
    
    def __init__(self, crypto_manager, client_manager):
        self.crypto_manager = crypto_manager
        self.client_manager = client_manager
    
    def get_client_key(self, client_id):
        """Get the appropriate encryption key for a client"""
        # Use client-specific key if available, otherwise use campaign key
        if hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys:
            return self.client_manager.client_keys[client_id]
        # Fall back to campaign-wide key
        return self.crypto_manager.key

    def _has_unique_key(self, client_id):
        """Check if client has a unique encryption key"""
        return hasattr(self.client_manager, 'client_keys') and client_id in self.client_manager.client_keys

    def encrypt(self, data, client_id=None):
        """Encrypt data using client key if available, otherwise campaign key"""
        key = self.get_client_key(client_id) if client_id else self.crypto_manager.key
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Add padding manually (simple PKCS7-like padding)
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length]) * padding_length
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext and base64 encode
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt(self, encrypted_data, client_id=None):
        """Decrypt data using client key if available, otherwise campaign key"""
        key = self.get_client_key(client_id) if client_id else self.crypto_manager.key
        
        # Decode the base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract the IV and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding manually
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data.decode('utf-8')