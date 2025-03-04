import os
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self, campaign_name):
        """Initialize with a campaign-specific key from KeyManager"""
        # Get key from key_manager instead of deriving it
        self.campaign_folder = campaign_name + "_campaign"
        self.keys_file = os.path.join(self.campaign_folder, "keys.json")
        
        # Load or create key
        self._load_or_create_key()
    
    def _load_or_create_key(self):
        """Load the key from keys.json or create it if it doesn't exist"""
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r') as f:
                    keys_data = json.load(f)
                    self.key = base64.b64decode(keys_data["primary"])
            except Exception as e:
                print(f"Error loading keys file: {e}")
                self._create_new_key()
        else:
            self._create_new_key()
    
    def _create_new_key(self):
        """Create a new random key"""
        # Create the keys file directory if it doesn't exist
        os.makedirs(os.path.dirname(self.keys_file), exist_ok=True)
        
        # Generate a truly random key
        self.key = os.urandom(32)  # 256-bit key
        
        # Save the key
        keys_data = {
            "primary": base64.b64encode(self.key).decode('utf-8'),
            "created_at": self._current_timestamp(),
            "campaign": os.path.basename(self.campaign_folder).replace("_campaign", "")
        }
        
        with open(self.keys_file, 'w') as f:
            json.dump(keys_data, f, indent=2)
    
    def _current_timestamp(self):
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def encrypt(self, data):
        """Encrypt data with AES-256-CBC"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Encrypt the data
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Add padding manually (simple PKCS7-like padding)
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length]) * padding_length
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and ciphertext and base64 encode
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt data encrypted with encrypt method"""
        # Decode the base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract the IV and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Decrypt the ciphertext
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding manually
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data.decode('utf-8')
    
    def get_key_base64(self):
        """Return the key as a base64 string"""
        return base64.b64encode(self.key).decode('utf-8')
    
    @staticmethod
    def get_powershell_decryptor(include_key_generator=True):
        """Return PowerShell code for decryption"""
        key_generator = """
function Get-CampaignKey {
    param([string]$KeysPath)
    
    # Read the key from the JSON file
    $keysJson = Get-Content -Path $KeysPath -Raw | ConvertFrom-Json
    return [System.Convert]::FromBase64String($keysJson.primary)
}
""" if include_key_generator else ""

        return key_generator + """
function Decrypt-Data {
    param(
        [string]$EncryptedBase64,
        [byte[]]$Key
    )
    
    # Decode base64
    $encryptedBytes = [System.Convert]::FromBase64String($EncryptedBase64)
    
    # Extract IV and ciphertext
    $iv = $encryptedBytes[0..15]
    $ciphertext = $encryptedBytes[16..($encryptedBytes.Length-1)]
    
    # Create AES decryptor
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $Key
    $aes.IV = $iv
    
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    
    # Remove padding manually
    $paddingLength = $decryptedBytes[$decryptedBytes.Length-1]
    $unpaddedBytes = $decryptedBytes[0..($decryptedBytes.Length-$paddingLength-1)]
    
    # Convert to string
    return [System.Text.Encoding]::UTF8.GetString($unpaddedBytes)
}

function Encrypt-Data {
    param(
        [string]$PlainText,
        [byte[]]$Key
    )
    
    # Convert string to bytes
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    
    # Generate random IV
    $iv = New-Object byte[] 16
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($iv)
    
    # Apply padding
    $blockSize = 16
    $paddingLength = $blockSize - ($dataBytes.Length % $blockSize)
    $paddedBytes = New-Object byte[] ($dataBytes.Length + $paddingLength)
    [Array]::Copy($dataBytes, $paddedBytes, $dataBytes.Length)
    
    # Fill padding bytes
    for ($i = $dataBytes.Length; $i -lt $paddedBytes.Length; $i++) {
        $paddedBytes[$i] = [byte]$paddingLength
    }
    
    # Encrypt
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $Key
    $aes.IV = $iv
    
    $encryptor = $aes.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock($paddedBytes, 0, $paddedBytes.Length)
    
    # Combine IV and encrypted bytes
    $result = New-Object byte[] ($iv.Length + $encryptedBytes.Length)
    [Array]::Copy($iv, 0, $result, 0, $iv.Length)
    [Array]::Copy($encryptedBytes, 0, $result, $iv.Length, $encryptedBytes.Length)
    
    # Return Base64
    return [System.Convert]::ToBase64String($result)
}
"""

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