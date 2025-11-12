# PyFundaments: A Secure Python Architecture
# Copyright 2008-2025 - Volkan Kücükbudak
# Apache License V. 2
# Repo: https://github.com/VolkanSah/PyFundaments
# encryption.py
# A secure and robust encryption module using the cryptography library.
# This module is designed as a core component for a CMS architecture.

import os
import sys
import base64
import binascii
from typing import Dict, Union, Optional

# IMPORTANT: The cryptography library is required for this module.
# Please install it with 'pip install cryptography'.
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Error: The 'cryptography' library is required. Please install it with 'pip install cryptography'.")
    sys.exit(1)

class Encryption:
    """
    A class for symmetric encryption and decryption using AES-256-GCM.
    It securely handles both string data and file streaming.
    
    This version is designed as a reusable core component for a larger application.
    """
    CIPHER_NAME = 'AES-256-GCM'
    KEY_LENGTH = 32 # 256 bits
    NONCE_LENGTH = 12 # 96 bits, standard for GCM
    TAG_LENGTH = 16 # 128 bits
    SALT_LENGTH = 16

    @staticmethod
    def generate_salt() -> str:
        """
        Generates a new, cryptographically secure random salt for key derivation.
        This should be done once during application setup and stored securely.
        
        Returns:
            A hex-encoded string of the salt.
        """
        return binascii.hexlify(os.urandom(Encryption.SALT_LENGTH)).decode('utf-8')

    def __init__(self, master_key: str, salt: str):
        """
        Initializes the encryption class by deriving a secure key from a master key.
        The provided master_key and a persistent salt are used for key derivation.
        
        Args:
            master_key: The string to be used as the master key.
            salt: The hex-encoded string of the persistent salt.
        
        Raises:
            ValueError: If the provided salt is not a valid hex string or has an incorrect length.
        """
        try:
            salt_bytes = binascii.unhexlify(salt)
        except binascii.Error:
            raise ValueError("Invalid salt format. Must be a hex-encoded string.")
        
        if len(salt_bytes) != self.SALT_LENGTH:
            raise ValueError(f"Invalid salt length. Expected {self.SALT_LENGTH} bytes, got {len(salt_bytes)}.")
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt_bytes,
            iterations=480000, # Recommended value for 2023+
            backend=default_backend()
        )
        self.key = kdf.derive(master_key.encode('utf-8'))

    def encrypt(self, data: str) -> Dict[str, str]:
        """
        Encrypts a string using AES-256-GCM.
        
        Args:
            data: The string to be encrypted.

        Returns:
            A dictionary containing the base64-encoded ciphertext, hex-encoded IV/nonce,
            and hex-encoded authentication tag.
        """
        nonce = os.urandom(self.NONCE_LENGTH)
        
        aesgcm = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        
        encrypted_data = aesgcm.update(data.encode('utf-8')) + aesgcm.finalize()
        tag = aesgcm.tag

        return {
            'data': base64.b64encode(encrypted_data).decode('utf-8'),
            'nonce': binascii.hexlify(nonce).decode('utf-8'),
            'tag': binascii.hexlify(tag).decode('utf-8')
        }

    def decrypt(self, encrypted_data: str, nonce: str, tag: str) -> str:
        """
        Decrypts an AES-256-GCM encrypted string.
        
        Args:
            encrypted_data: The base64-encoded ciphertext.
            nonce: The hex-encoded nonce/IV.
            tag: The hex-encoded authentication tag.
            
        Returns:
            The decrypted plaintext string.
        
        Raises:
            ValueError: If nonce, tag, or data format is invalid.
            InvalidTag: If the authentication tag fails validation.
        """
        try:
            nonce_bytes = binascii.unhexlify(nonce)
            tag_bytes = binascii.unhexlify(tag)
            cipher_bytes = base64.b64decode(encrypted_data)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f'Invalid data format: {e}')
        
        aesgcm = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce_bytes, tag_bytes),
            backend=default_backend()
        ).decryptor()
        
        try:
            decrypted_data = aesgcm.update(cipher_bytes) + aesgcm.finalize()
            return decrypted_data.decode('utf-8')
        except InvalidTag:
            raise InvalidTag("Authentication tag validation failed. Data may be corrupted or key is incorrect.")

    def encrypt_file(self, source_path: str, destination_path: str) -> Dict[str, str]:
        """
        Encrypts a file using AES-256-GCM with a streaming approach.
        
        Args:
            source_path: Path to the file to be encrypted.
            destination_path: Path where the encrypted file will be saved.
            
        Returns:
            A dictionary containing the hex-encoded IV/nonce and authentication tag.
        """
        nonce = os.urandom(self.NONCE_LENGTH)
        
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        
        try:
            with open(source_path, 'rb') as fp_source, open(destination_path, 'wb') as fp_dest:
                fp_dest.write(nonce)
                
                chunk_size = 8192
                while True:
                    chunk = fp_source.read(chunk_size)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    fp_dest.write(encrypted_chunk)
                
                encryptor.finalize()
                tag = encryptor.tag
                fp_dest.write(tag)
            
            return {
                'nonce': binascii.hexlify(nonce).decode('utf-8'),
                'tag': binascii.hexlify(tag).decode('utf-8')
            }
        except FileNotFoundError as e:
            raise ValueError(f"File not found: {e.filename}") from e
        except Exception as e:
            raise IOError(f"File encryption failed: {e}") from e

    def decrypt_file(self, source_path: str, destination_path: str) -> None:
        """
        Decrypts an AES-256-GCM encrypted file.
        
        Args:
            source_path: Path to the encrypted file.
            destination_path: Path where the decrypted file will be saved.
        """
        try:
            with open(source_path, 'rb') as fp_source, open(destination_path, 'wb') as fp_dest:
                nonce = fp_source.read(self.NONCE_LENGTH)
                if len(nonce) != self.NONCE_LENGTH:
                    raise ValueError("Incomplete or invalid file format: Nonce is missing.")
                    
                fp_source.seek(-self.TAG_LENGTH, os.SEEK_END)
                tag = fp_source.read(self.TAG_LENGTH)
                if len(tag) != self.TAG_LENGTH:
                    raise ValueError("Incomplete or invalid file format: Tag is missing.")
                    
                fp_source.seek(self.NONCE_LENGTH, os.SEEK_SET) # Rewind to the start of the ciphertext
                
                decryptor = Cipher(
                    algorithms.AES(self.key),
                    modes.GCM(nonce, tag),
                    backend=default_backend()
                ).decryptor()
                
                chunk_size = 8192
                encrypted_file_size = os.path.getsize(source_path) - self.NONCE_LENGTH - self.TAG_LENGTH
                
                bytes_read = 0
                while bytes_read < encrypted_file_size:
                    chunk_to_read = min(chunk_size, encrypted_file_size - bytes_read)
                    chunk = fp_source.read(chunk_to_read)
                    
                    decrypted_chunk = decryptor.update(chunk)
                    fp_dest.write(decrypted_chunk)
                    bytes_read += len(chunk)
                
                decryptor.finalize()
                
        except InvalidTag as e:
            raise IOError(f"File decryption failed. The authentication tag is invalid, suggesting the file was corrupted or tampered with. Error: {e}") from e
        except FileNotFoundError as e:
            raise ValueError(f"File not found: {e.filename}") from e
        except Exception as e:
            raise IOError(f"File decryption failed due to an unexpected error: {e}") from e
