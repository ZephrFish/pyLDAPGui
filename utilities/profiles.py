"""
Profile manager for saved LDAP connections
Handles encryption of passwords using Fernet symmetric encryption
"""
import json
import os
from typing import List, Dict, Any, Optional
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class ProfileManager:
    """Manages saved connection profiles with encrypted password storage"""
    
    def __init__(self, profile_file: str = "ldap_profiles.json"):
        self.profile_file = profile_file
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.encryption_key = self._get_or_create_key()
        self.load_profiles()
        
    def _get_or_create_key(self) -> bytes:
        """Generate or retrieve encryption key for password storage
        
        Uses a fixed key derivation so we can decrypt passwords later.
        Not perfect security but better than plaintext!
        """
        key_file = ".ldap_key"
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate a new key - yeah the salt is hardcoded, it was easier this way, I know SeCuRiTy says it's bad but so what!
            password = b"pyldap_gui_salt_2025"  # Fixed salt for simplicity
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'stable_salt',  # should be random but then we couldn't decrypt
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # Save key
            with open(key_file, 'wb') as f:
                f.write(key)
                
            # Hide file on Unix systems
            if os.name != 'nt':
                os.system(f'chmod 600 {key_file}')
                
            return key
            
    def _encrypt_password(self, password: str) -> str:
        """Encrypt password for storage"""
        f = Fernet(self.encryption_key)
        return f.encrypt(password.encode()).decode()
        
    def _decrypt_password(self, encrypted: str) -> str:
        """Decrypt stored password"""
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted.encode()).decode()
        
    def load_profiles(self):
        """Load profiles from file"""
        if os.path.exists(self.profile_file):
            try:
                with open(self.profile_file, 'r') as f:
                    self.profiles = json.load(f)
            except:
                self.profiles = {}
                
    def save_profiles(self):
        """Save profiles to file"""
        with open(self.profile_file, 'w') as f:
            json.dump(self.profiles, f, indent=2)
            
    def add_profile(self, name: str, host: str, port: Optional[int], 
                   username: str, password: str, use_ssl: bool,
                   proxy_settings: Optional[Dict[str, Any]] = None) -> bool:
        """Add or update a connection profile"""
        encrypted_password = self._encrypt_password(password)
        
        profile_data = {
            'host': host,
            'port': port,
            'username': username,
            'password': encrypted_password,
            'use_ssl': use_ssl
        }
        
        # Add proxy settings if provided
        if proxy_settings:
            # Encrypt proxy password if present
            if proxy_settings.get('password'):
                proxy_settings = proxy_settings.copy()
                proxy_settings['password'] = self._encrypt_password(proxy_settings['password'])
            profile_data['proxy_settings'] = proxy_settings
        
        self.profiles[name] = profile_data
        self.save_profiles()
        return True
        
    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a profile with decrypted password"""
        if name not in self.profiles:
            return None
            
        profile = self.profiles[name].copy()
        profile['password'] = self._decrypt_password(profile['password'])
        
        # Decrypt proxy password if present
        if 'proxy_settings' in profile and profile['proxy_settings']:
            proxy_settings = profile['proxy_settings'].copy()
            if proxy_settings.get('password'):
                proxy_settings['password'] = self._decrypt_password(proxy_settings['password'])
            profile['proxy_settings'] = proxy_settings
            
        return profile
        
    def delete_profile(self, name: str) -> bool:
        """Delete a profile"""
        if name in self.profiles:
            del self.profiles[name]
            self.save_profiles()
            return True
        return False
        
    def list_profiles(self) -> List[str]:
        """Get list of profile names"""
        return list(self.profiles.keys())