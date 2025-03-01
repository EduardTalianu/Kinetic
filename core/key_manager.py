import os
import base64
import hashlib
import random
import string
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class KeyManager:
    def __init__(self, campaign_folder):
        """Initialize key manager for a campaign"""
        self.campaign_folder = campaign_folder
        self.keys_file = os.path.join(campaign_folder, "keys.json")
        self.campaign_name = os.path.basename(campaign_folder).replace("_campaign", "")
        self._load_or_create_keys()
    
    def _load_or_create_keys(self):
        """Load existing keys or create new ones if they don't exist"""
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r') as f:
                    self.keys = json.load(f)
            except Exception as e:
                print(f"Error loading keys file: {e}")
                self._create_new_keys()
        else:
            self._create_new_keys()
    
    def _create_new_keys(self):
        """Create new random keys for the campaign"""
        # Generate a truly random key rather than deriving from campaign name
        primary_key = os.urandom(32)  # 256-bit key
        
        # Create a keys dictionary
        self.keys = {
            "primary": base64.b64encode(primary_key).decode('utf-8'),
            "created_at": self._current_timestamp(),
            "campaign": self.campaign_name
        }
        
        # Save the keys
        self._save_keys()
    
    def _save_keys(self):
        """Save keys to the keys file"""
        os.makedirs(os.path.dirname(self.keys_file), exist_ok=True)
        with open(self.keys_file, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def _current_timestamp(self):
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_primary_key(self):
        """Get the primary key as bytes"""
        return base64.b64decode(self.keys["primary"])
    
    def get_key_for_agent(self):
        """Get the key in a format suitable for embedding in an agent"""
        return self.keys["primary"]
    
    def generate_agent_key_code(self, obfuscate=True):
        """Generate PowerShell code for embedding the key in an agent"""
        key_b64 = self.keys["primary"]
        
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
    
    def encrypt(self, data):
        """Encrypt data with the primary key"""
        key = self.get_primary_key()
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Add padding
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length]) * padding_length
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext and base64 encode
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt data encrypted with the primary key"""
        key = self.get_primary_key()
        
        # Decode the base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract the IV and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Decrypt the ciphertext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data.decode('utf-8')