import os
import base64
import json
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class RSAKeyManager:
    """Manages RSA key pairs for secure key exchange"""
    
    def __init__(self, campaign_folder):
        """
        Initialize the RSA key manager
        
        Args:
            campaign_folder: Path to the campaign folder
        """
        self.campaign_folder = campaign_folder
        self.keys_folder = os.path.join(campaign_folder, "keys")
        self.rsa_key_file = os.path.join(self.keys_folder, "rsa_keypair.json")
        
        # Initialize private and public keys
        self.private_key = None
        self.public_key = None
        
        # Load or generate keys
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing RSA keys or generate new ones if they don't exist"""
        os.makedirs(self.keys_folder, exist_ok=True)
        
        if os.path.exists(self.rsa_key_file):
            try:
                with open(self.rsa_key_file, 'r') as f:
                    key_data = json.load(f)
                
                # Load private key
                private_key_pem = key_data.get('private_key')
                if private_key_pem:
                    self.private_key = serialization.load_pem_private_key(
                        private_key_pem.encode('utf-8'),
                        password=None,
                        backend=default_backend()
                    )
                    
                    # Generate public key from private key
                    self.public_key = self.private_key.public_key()
                    
                    logger.info(f"RSA keys loaded from {self.rsa_key_file}")
                    return
            except Exception as e:
                logger.error(f"Failed to load RSA keys: {e}")
        
        # Generate new RSA key pair
        self._generate_new_keys()
    
    def _generate_new_keys(self):
        """Generate a new RSA key pair"""
        try:
            # Generate private key - using 2048 bits for balance of security and performance
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Get public key
            self.public_key = self.private_key.public_key()
            
            # Save keys
            self._save_keys()
            
            logger.info("New RSA key pair generated")
        except Exception as e:
            logger.error(f"Failed to generate RSA keys: {e}")
            raise
    
    def _save_keys(self):
        """Save RSA keys to file"""
        try:
            # Serialize private key to PEM format
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Save to file
            key_data = {
                'private_key': private_key_pem,
                'created_at': self._current_timestamp()
            }
            
            with open(self.rsa_key_file, 'w') as f:
                json.dump(key_data, f, indent=2)
                
            logger.info(f"RSA keys saved to {self.rsa_key_file}")
        except Exception as e:
            logger.error(f"Failed to save RSA keys: {e}")
            raise
    
    def _current_timestamp(self):
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_public_key_pem(self):
        """
        Get the public key in PEM format
        
        Returns:
            Public key as PEM string
        """
        if not self.public_key:
            logger.error("Public key not available")
            return None
            
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def get_public_key_base64(self):
        """
        Get the public key in base64 format for easier transmission
        
        Returns:
            Base64 encoded public key
        """
        pem = self.get_public_key_pem()
        if not pem:
            return None
            
        # Strip header/footer and newlines
        pem_lines = pem.strip().split('\n')
        if len(pem_lines) >= 3:  # Ensure it has BEGIN/END markers
            pem_data = ''.join(pem_lines[1:-1])
            return pem_data
        
        return base64.b64encode(pem.encode('utf-8')).decode('utf-8')
    
    def decrypt_client_key(self, encrypted_key_base64):
        """
        Decrypt a client key that was encrypted with the server's public key
        
        Args:
            encrypted_key_base64: Base64 encoded encrypted key
            
        Returns:
            Decrypted key (bytes) or None if decryption fails
        """
        if not self.private_key:
            logger.error("Private key not available for decryption")
            return None
            
        try:
            # Decode base64
            encrypted_key = base64.b64decode(encrypted_key_base64)
            
            # Add debugging info
            logger.info(f"Attempting to decrypt client key, length: {len(encrypted_key)} bytes")
            
            # The agent uses OAEP padding with SHA-1 (RSACryptoServiceProvider.Encrypt with fOAEP=true)
            try:
                decrypted_key = self.private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )
                logger.info(f"Successfully decrypted client key using OAEP with SHA-1")
                return decrypted_key
            except Exception as e:
                logger.error(f"Failed to decrypt with OAEP SHA-1: {e}")
                
                # Fallback to PKCS#1v15 in case agent is using older .NET methods
                try:
                    decrypted_key = self.private_key.decrypt(
                        encrypted_key,
                        padding.PKCS1v15()
                    )
                    logger.info(f"Successfully decrypted client key using PKCS#1v15")
                    return decrypted_key
                except Exception as e:
                    logger.error(f"Failed to decrypt with PKCS#1v15: {e}")
                    
                    # Last attempt with SHA-256 OAEP
                    try:
                        decrypted_key = self.private_key.decrypt(
                            encrypted_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        logger.info(f"Successfully decrypted client key using OAEP with SHA-256")
                        return decrypted_key
                    except Exception as e:
                        logger.error(f"Failed to decrypt with OAEP SHA-256: {e}")
            
            logger.error("All decryption methods failed")
            return None
        except Exception as e:
            logger.error(f"Failed to decrypt client key: {e}")
            return None