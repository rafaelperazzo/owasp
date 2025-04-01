'''
Functions for AES256-CBC encryption/decryption and Argon2 hashing.
This module provides functions to generate an AES key, encrypt and decrypt messages,
and hash and verify passwords using Argon2.
It uses the PyCryptodome library for AES encryption and Argon2 for password hashing.
It is important to note that the AES key should be kept secret and secure.
The Argon2 hash should also be stored securely, as it is used to verify passwords.
This module is intended for educational purposes and should not be used in 
production without proper security measures.

Author: RAFAEL PERAZZO B MOTA
Date: 2025-03-30
Version: 1.1
'''
# -*- coding: utf-8 -*-
from pathlib import Path
import argon2
from argon2 import PasswordHasher
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA3_256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def hexstring_to_bytes(hex_string):
    '''
    Converts a hexadecimal string to bytes.
    :param hex_string: hexadecimal string to be converted
    :return: bytes
    '''
    # Remove any leading '0x' and convert to bytes
    hex_string = hex_string.lstrip('0x')
    return bytes.fromhex(hex_string)

def bytes_to_hexstring(byte_string):
    '''
    Converts bytes to a hexadecimal string.
    :param byte_string: bytes to be converted
    :return: hexadecimal string
    '''
    # Convert bytes to hexadecimal string
    hex_string = byte_string.hex()
    # Add '0x' prefix
    hex_string = '0x' + hex_string
    return hex_string

def generate_key():
    '''
    Generates a new AES key and saves it to a file.
    :return: AES key
    '''
    keyfile = Path("key.key")
    # Check if the key file exists
    if not keyfile.is_file():
        # Generate a new AES key
        aes_key = get_random_bytes(32)
        # Save the key to a file
        with open("key.key", "wb") as key_file:
            key_file.write(aes_key)
    else:
        print("Key file already exists. Loading the existing key.")
        with open("key.key", "rb") as key_file:
            aes_key = key_file.read()
    return aes_key

def encrypt(key, plaintext):
    '''
    Encrypts the plaintext using AES CBC encryption with a random IV.
    :param key: AES key (must be 16, 24, or 32 bytes long)
    :param plaintext: plaintext to be encrypted
    :return: ciphertext (IV + ciphertext)
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ciphertext

def decrypt(key, ciphertext):
    '''
    Decrypts the ciphertext using AES decryption.
    :param key: AES key (must be 16, 24, or 32 bytes long)
    :param ciphertext: ciphertext to be decrypted (IV + ciphertext)
    :return: decrypted plaintext
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext

def aes_gcm_encrypt(key, plaintext):
    '''
    Encrypts the plaintext using AES GCM encryption with a random nonce.
    :param key: AES key (must be 16, 24, or 32 bytes long) -  bytes or hexadecimal string
    :param plaintext: plaintext to be encrypted - string or bytes
    :return: ciphertext (nonce + ciphertext + tag) - bytes
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    if isinstance(plaintext, str):
        # Convert string plaintext to bytes
        plaintext = plaintext.encode()
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag

def aes_gcm_decrypt(key, ciphertext):
    '''
    Decrypts the ciphertext using AES GCM decryption.
    :param key: AES key (must be 16, 24, or 32 bytes long) - bytes or hexadecimal string
    :param ciphertext: ciphertext to be decrypted (nonce + ciphertext + tag)
    :return: decrypted plaintext
    '''
    if isinstance(key, str):
        # Convert base64 string key to bytes
        key = hexstring_to_bytes(key)
    if isinstance(ciphertext, str):
        # Convert base64 string ciphertext to bytes
        ciphertext = base64.b64decode(ciphertext)
    nonce = ciphertext[:16]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[16:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def hmac(key, message):
    '''
    Applies HMAC to the message using SHA3-256.
    :param key: key for the HMAC
    :param message: message to be hashed
    :return: HMAC signature
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    # Create the HMAC
    h = HMAC.new(key, digestmod=SHA3_256)
    h.update(message.encode())
    # Convert to hexadecimal
    signature = h.hexdigest()
    return signature

def verify_hmac(key, message, signature):
    '''
    Verifies if the HMAC signature matches the message.
    :param key: key for the HMAC
    :param message: message to be verified
    :param signature: HMAC signature to be verified
    :return: True if the signature is valid, False otherwise
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    # Create the HMAC
    h = HMAC.new(key, digestmod=SHA3_256)
    h.update(message.encode())
    # Convert to hexadecimal
    signature_calculated = h.hexdigest()
    # Compare the calculated signature with the provided signature
    if signature_calculated == signature:
        return True
    else:
        return False

def hash_argon2id(key, password):
    '''
    Applies Argon2 hashing to the password using a HMAC.
    :param key: key for the HMAC
    :param password: password to be hashed
    :return: Argon2 hash
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    # Create the HMAC
    h = HMAC.new(key,digestmod=SHA3_256)
    h.update(password.encode())
    # Convert to hexadecimal
    signature = h.hexdigest()
    
    # Apply Argon2 hashing
    ph = PasswordHasher()
    hash_argon = ph.hash(signature)
    return hash_argon

def verify_hash(hash_argon, key, password):
    '''
    Verifies if the Argon2 hash matches the password.
    :param hash_argon: stored Argon2 hash
    :param key: key for the HMAC
    :param password: password to be verified
    :return: True if the password is correct, False otherwise
    '''
    if isinstance(key, str):
        # Convert hexadecimal string key to bytes
        key = hexstring_to_bytes(key)
    # Create the HMAC
    h = HMAC.new(key,digestmod=SHA3_256)
    h.update(password.encode())
    # Convert to hexadecimal
    signature = h.hexdigest()
    
    # Apply Argon2 hashing
    ph = PasswordHasher()
    try:
        ph.verify(hash_argon, signature)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

def main():
    '''
    Função principal para testes das funções de criptografia e hashing.
    '''
    # Generate or load the AES key
    aes_key = generate_key()
    print(f"AES Key: {aes_key.hex()}")
    
    # Encrypt a message
    MESSAGE = b"Hello, World!"
    encrypted_text = encrypt(aes_key, MESSAGE)
    print(f"Ciphertext: {encrypted_text.hex()}")
    
    # Decrypt the message
    decrypted_text = decrypt(aes_key, encrypted_text)
    print(f"Plaintext: {decrypted_text.decode()}")
    
    # Hash a password with Argon2
    PASSWORD = "mysecretpassword123456789012345"
    HASH_ARGON = hash_argon2id(aes_key, PASSWORD)
    print(f"Argon2 Hash: {HASH_ARGON}")
    # Verify the password
    is_valid = verify_hash(HASH_ARGON, aes_key, PASSWORD)
    print(f"Password is valid: {is_valid}")
    # Verify a different password
    is_valid = verify_hash(HASH_ARGON, aes_key, "wrongpassword")
    print(f"Password is valid: {is_valid}")
    
if __name__ == "__main__":
    main()
