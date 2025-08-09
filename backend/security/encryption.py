"""
Field-level encryption for PII compliance
COPPA-compliant implementation with AES-256-GCM
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from typing import Optional
import secrets

class FieldEncryption:
    """
    Field-level encryption for sensitive data
    Ensures all PII is encrypted before database storage
    """
    
    def __init__(self, key: Optional[str] = None):
        """Initialize with encryption key"""
        if key:
            self.key = base64.b64decode(key)
        else:
            # Generate key if not provided (dev only)
            self.key = AESGCM.generate_key(bit_length=256)
            print(f"🔑 Generated encryption key: {base64.b64encode(self.key).decode()}")
        
        self.aead = AESGCM(self.key)
    
    def encrypt(self, plaintext: str) -> Optional[str]:
        """
        Encrypt PII field for database storage
        Returns base64 encoded ciphertext
        """
        if not plaintext or plaintext.strip() == "":
            return None
        
        try:
            # Generate random nonce for each encryption
            nonce = os.urandom(12)  # 96-bit nonce for GCM
            
            # Encrypt with authenticated encryption
            ciphertext = self.aead.encrypt(
                nonce,
                plaintext.encode('utf-8'),
                None  # No additional authenticated data
            )
            
            # Combine nonce + ciphertext for storage
            encrypted_data = nonce + ciphertext
            
            # Return base64 encoded for JSON/database compatibility
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            # Log error but don't expose sensitive info
            print(f"🚨 Encryption failed: {type(e).__name__}")
            raise ValueError("Encryption operation failed")
    
    def decrypt(self, ciphertext: str) -> Optional[str]:
        """
        Decrypt PII field from database
        Returns plaintext string
        """
        if not ciphertext:
            return None
        
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(ciphertext)
            
            # Split nonce and ciphertext
            nonce = encrypted_data[:12]  # First 12 bytes
            actual_ciphertext = encrypted_data[12:]  # Rest is ciphertext
            
            # Decrypt with authenticated decryption
            plaintext_bytes = self.aead.decrypt(
                nonce,
                actual_ciphertext,
                None
            )
            
            return plaintext_bytes.decode('utf-8')
            
        except Exception as e:
            # Log error but don't expose sensitive info
            print(f"🚨 Decryption failed: {type(e).__name__}")
            raise ValueError("Decryption operation failed")
    
    def encrypt_dict(self, data: dict, fields: list) -> dict:
        """
        Encrypt specified fields in a dictionary
        Used for bulk PII encryption
        """
        encrypted_data = data.copy()
        
        for field in fields:
            if field in encrypted_data and encrypted_data[field]:
                encrypted_data[f"{field}_encrypted"] = self.encrypt(encrypted_data[field])
                # Remove plaintext
                del encrypted_data[field]
        
        return encrypted_data
    
    def decrypt_dict(self, data: dict, fields: list) -> dict:
        """
        Decrypt specified fields in a dictionary
        Used for bulk PII decryption
        """
        decrypted_data = data.copy()
        
        for field in fields:
            encrypted_field = f"{field}_encrypted"
            if encrypted_field in decrypted_data:
                decrypted_data[field] = self.decrypt(decrypted_data[encrypted_field])
                # Keep encrypted version for audit
        
        return decrypted_data

# Global encryption instance
_encryption = None

def get_encryption() -> FieldEncryption:
    """Get global encryption instance"""
    global _encryption
    if _encryption is None:
        from backend.core.config import settings
        _encryption = FieldEncryption(settings.encryption_key)
    return _encryption

def generate_encryption_key() -> str:
    """Generate a new encryption key for production"""
    key = AESGCM.generate_key(bit_length=256)
    return base64.b64encode(key).decode()

# PII field definitions for COPPA compliance
PII_FIELDS = {
    'critical': ['email', 'name', 'phone', 'address'],
    'sensitive': ['ip_address', 'device_id', 'location'],
    'identifiers': ['ssn', 'driver_license', 'passport']
}

def is_pii_field(field_name: str) -> bool:
    """Check if field contains PII that needs encryption"""
    field_lower = field_name.lower()
    
    for category, fields in PII_FIELDS.items():
        if any(pii in field_lower for pii in fields):
            return True
    
    return False

# Test function for development
def test_encryption():
    """Test encryption/decryption functionality"""
    enc = FieldEncryption()
    
    test_data = "parent@example.com"
    
    # Test encrypt/decrypt
    encrypted = enc.encrypt(test_data)
    decrypted = enc.decrypt(encrypted)
    
    assert decrypted == test_data
    assert test_data not in encrypted  # Ensure not plaintext
    
    print("✅ Encryption test passed")
    return True

if __name__ == "__main__":
    # For testing
    test_encryption()
    print(f"🔑 New encryption key: {generate_encryption_key()}")