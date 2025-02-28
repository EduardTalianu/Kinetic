import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self, campaign_name):
        """Initialize with a campaign-specific key"""
        # Generate a deterministic key based on campaign name
        # In production, you should use a secure random key stored securely
        self.key = self._derive_key(campaign_name)
    
    def _derive_key(self, seed):
        """Derive a key from the campaign name (for demo purposes)"""
        # In production, replace this with proper key management
        import hashlib
        return hashlib.sha256(seed.encode()).digest()
    
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
    
    @staticmethod
    def get_powershell_decryptor():
        """Return PowerShell code for decryption"""
        return """
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

function Get-CampaignKey {
    param([string]$CampaignName)
    
    # Simple SHA256 hash of campaign name for key derivation
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    return $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($CampaignName))
}
"""