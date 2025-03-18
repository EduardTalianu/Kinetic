import os
import base64
import json
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from core.rsa_key_manager import RSAKeyManager

logger = logging.getLogger(__name__)

class EnhancedEncryptionService:
    """
    Enhanced encryption service that supports asymmetric key exchange
    """
    
    def __init__(self, campaign_folder):
        """
        Initialize the encryption service
        
        Args:
            campaign_folder: Path to the campaign folder
        """
        self.campaign_folder = campaign_folder
        self.client_keys = {}
        self.plugins = {}
        self.default_provider = "aes"
        self.client_key_source = {}  # Track which clients are using self-generated keys
        
        # Initialize RSA key manager
        self.rsa_key_manager = RSAKeyManager(campaign_folder)
        
        # Load AES plugins
        self.load_plugins()
        
        # Load client keys
        self.load_keys()
    
    def load_plugins(self):
        """Load encryption plugins"""
        # Add AES plugin by default
        aes_plugin = AESEncryptionPlugin()
        self.plugins[aes_plugin.name] = aes_plugin
        logger.debug(f"Loaded encryption plugin: {aes_plugin.name}")
    
    def load_keys(self):
        """Load client keys from campaign folder"""
        # Load client keys if available
        client_keys_file = os.path.join(self.campaign_folder, "client_keys.json")
        if os.path.exists(client_keys_file):
            try:
                with open(client_keys_file, 'r') as f:
                    client_keys_data = json.load(f)
                    
                # Process the loaded client keys
                for client_id, key_data in client_keys_data.items():
                    # If the key data contains the actual key (base64 encoded)
                    if "key" in key_data:
                        try:
                            # Decode the base64 key
                            key_bytes = base64.b64decode(key_data["key"])
                            self.client_keys[client_id] = key_bytes
                            
                            # Track key source if present
                            if "client_generated" in key_data:
                                self.client_key_source[client_id] = key_data["client_generated"]
                                
                            logger.info(f"Loaded key for client {client_id}")
                        except Exception as e:
                            logger.error(f"Error decoding key for client {client_id}: {e}")
                
                logger.info(f"Loaded {len(self.client_keys)} client keys from {client_keys_file}")
            except Exception as e:
                logger.error(f"Error loading client keys: {e}")
    
    def _current_timestamp(self):
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def save_client_keys_info(self):
        """Save client key information to disk"""
        client_keys_file = os.path.join(self.campaign_folder, "client_keys.json")
        
        # Save client keys with their status and actual key data (base64 encoded)
        client_key_data = {}
        for client_id, key in self.client_keys.items():
            client_key_data[client_id] = {
                "has_unique_key": True,
                "assigned_at": self._current_timestamp(),
                "key": base64.b64encode(key).decode('utf-8'),  # Save the actual key for troubleshooting
                "client_generated": self.client_key_source.get(client_id, False)  # Track key source
            }
        
        os.makedirs(os.path.dirname(client_keys_file), exist_ok=True)
        with open(client_keys_file, 'w') as f:
            json.dump(client_key_data, f, indent=2)
        
        logger.info(f"Saved client keys to {client_keys_file}")
    
    def get_key(self, client_id=None):
        """
        Get the encryption key for a client or generate a temporary one
        
        Args:
            client_id: Client ID (optional)
            
        Returns:
            Encryption key (bytes)
        """
        if client_id and client_id in self.client_keys:
            return self.client_keys[client_id]
        
        # Generate a temporary key for operations that don't have a client key
        return self.generate_key()
    
    def encrypt(self, data, client_id=None, provider=None, **kwargs):
        """
        Encrypt data using the appropriate key and provider
        
        Args:
            data: Data to encrypt
            client_id: Client ID (optional)
            provider: Encryption provider name (optional)
            **kwargs: Additional arguments for the encryption plugin
            
        Returns:
            Encrypted data
        """
        if provider is None:
            provider = self.default_provider
            
        if provider not in self.plugins:
            raise ValueError(f"Encryption provider {provider} not found")
        
        key = self.get_key(client_id)
        plugin = self.plugins[provider]
        
        return plugin.encrypt(data, key, **kwargs)
    
    def decrypt(self, data, client_id=None, provider=None, **kwargs):
        """
        Decrypt data using the appropriate key and provider
        
        Args:
            data: Data to decrypt
            client_id: Client ID (optional)
            provider: Encryption provider name (optional)
            **kwargs: Additional arguments for the encryption plugin
            
        Returns:
            Decrypted data
        """
        if provider is None:
            provider = self.default_provider
            
        if provider not in self.plugins:
            raise ValueError(f"Encryption provider {provider} not found")
        
        key = self.get_key(client_id)
        plugin = self.plugins[provider]
        
        try:
            return plugin.decrypt(data, key, **kwargs)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def identify_client_by_decryption(self, encrypted_data):
        """
        Identify a client by trying to decrypt with available client keys
        
        Args:
            encrypted_data: Encrypted data to attempt decryption
            
        Returns:
            tuple: (client_id, decrypted_data) or (None, None) if no key works
        """
        # Check if it's simple JSON (special case for first contact)
        try:
            simple_json = json.loads(encrypted_data)
            # If we can parse as JSON directly, it's likely first contact
            if isinstance(simple_json, dict) and not simple_json:
                logger.info("Identified first contact with empty JSON data")
                return None, encrypted_data
        except json.JSONDecodeError:
            # Not simple JSON, continue with key-based decryption
            pass
        
        # Try each client key
        for client_id, key in self.client_keys.items():
            try:
                plugin = self.plugins[self.default_provider]
                decrypted_data = plugin.decrypt(encrypted_data, key)
                
                # Try to verify it's valid data
                # Either valid JSON or readable text
                try:
                    json.loads(decrypted_data)
                except json.JSONDecodeError:
                    # Not JSON, but if we got this far, it's likely valid text
                    pass
                
                logger.info(f"Identified client {client_id} through key-based decryption")
                return client_id, decrypted_data
            except Exception:
                # Try next key
                continue
        
        # If none of the client keys worked, we're likely dealing with first contact
        logger.warning("No client key could decrypt the data - likely first contact or invalid data")
        return None, None
    
    def register_client_generated_key(self, client_id, encrypted_key_base64):
        """
        Register a client-generated key that was encrypted with the server's public key
        
        Args:
            client_id: Client ID
            encrypted_key_base64: Client key encrypted with server public key (base64)
            
        Returns:
            True if key registration was successful, False otherwise
        """
        # Decrypt the key using RSA private key
        decrypted_key = self.rsa_key_manager.decrypt_client_key(encrypted_key_base64)
        
        if decrypted_key:
            # Set the key for this client
            self.client_keys[client_id] = decrypted_key
            
            # Mark that this key was generated by the client
            self.client_key_source[client_id] = True
            
            # Save client keys to disk
            self.save_client_keys_info()
            
            logger.info(f"Registered client-generated key for client {client_id}")
            return True
        else:
            logger.error(f"Failed to register client-generated key for client {client_id}")
            return False
    
    def set_client_key(self, client_id, key=None):
        """
        Set a client-specific encryption key
        
        Args:
            client_id: Client ID
            key: Encryption key (generates new key if None)
            
        Returns:
            The encryption key
        """
        if key is None:
            key = self.generate_key()
            
        self.client_keys[client_id] = key
        
        # Mark that this key was server-generated (not client-generated)
        self.client_key_source[client_id] = False
        
        self.save_client_keys_info()  # Save keys to disk for persistence
        
        logger.info(f"Set server-generated key for client {client_id}")
        return key
    
    def remove_client_key(self, client_id):
        """
        Remove a client-specific key
        
        Args:
            client_id: Client ID
            
        Returns:
            True if the key was removed, False if the client had no key
        """
        if client_id in self.client_keys:
            del self.client_keys[client_id]
            
            # Remove from key source tracking
            if client_id in self.client_key_source:
                del self.client_key_source[client_id]
                
            self.save_client_keys_info()
            logger.info(f"Removed client key for client {client_id}")
            return True
        return False
    
    def has_client_key(self, client_id):
        """
        Check if a client has a specific key
        
        Args:
            client_id: Client ID
            
        Returns:
            True if the client has a specific key, False otherwise
        """
        return client_id in self.client_keys
    
    def is_client_key_self_generated(self, client_id):
        """
        Check if a client's key was generated by the client itself
        
        Args:
            client_id: Client ID
        
        Returns:
            True if the client generated its own key, False if server-generated
        """
        return self.client_key_source.get(client_id, False)
    
    def generate_key(self, provider=None):
        """
        Generate a new encryption key
        
        Args:
            provider: Encryption provider name (optional)
            
        Returns:
            New encryption key
        """
        if provider is None:
            provider = self.default_provider
            
        if provider not in self.plugins:
            raise ValueError(f"Encryption provider {provider} not found")
        
        plugin = self.plugins[provider]
        return plugin.generate_key()
    
    def get_public_key_base64(self):
        """
        Get the server's RSA public key in base64 format
        
        Returns:
            Base64 encoded public key or None if not available
        """
        return self.rsa_key_manager.get_public_key_base64()


class AESEncryptionPlugin:
    """AES-256-CBC encryption implementation"""
    
    def __init__(self):
        self.name = "aes"
    
    def encrypt(self, data, key, **kwargs):
        """
        Encrypt data with AES-256-CBC
        
        Args:
            data: Data to encrypt (string or bytes)
            key: Encryption key (bytes)
            
        Returns:
            Base64 encoded encrypted data (string)
        """
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
        
        # Add JPEG header if requested
        if kwargs.get('add_jpeg_header', False):
            # Add JPEG header bytes (0xFF, 0xD8, 0xFF) at binary level
            jpeg_header = bytes([0xFF, 0xD8, 0xFF])
            result = jpeg_header + iv + ciphertext
        else:
            # Combine IV and ciphertext
            result = iv + ciphertext
        
        # Base64 encode
        return base64.b64encode(result).decode('utf-8')
    
    def decrypt(self, data, key, **kwargs):
        """
        Decrypt data encrypted with AES-256-CBC
        
        Args:
            data: Base64 encoded encrypted data (string)
            key: Decryption key (bytes)
            
        Returns:
            Decrypted data (string)
        """
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(data)
            
            # Check if there's a JPEG header and remove it
            offset = 0
            if len(encrypted_bytes) > 3 and encrypted_bytes[0] == 0xFF and encrypted_bytes[1] == 0xD8 and encrypted_bytes[2] == 0xFF:
                offset = 3
            
            # Extract the IV (16 bytes) and ciphertext
            iv = encrypted_bytes[offset:offset+16]
            ciphertext = encrypted_bytes[offset+16:]
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_data[-1]
            if padding_length > 0 and padding_length <= 16:  # Validate padding
                data = padded_data[:-padding_length]
                return data.decode('utf-8')
            else:
                # Invalid padding, likely wrong key
                raise ValueError("Invalid padding in decrypted data")
                
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise
    
    def generate_key(self, **kwargs):
        """Generate a new AES-256 key"""
        return os.urandom(32)  # 256-bit key