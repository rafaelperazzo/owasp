from cripto import aes_gcm_encrypt,aes_gcm_decrypt, hash_argon2id,verify_hash, gpg_encrypt, gpg_decrypt
from Crypto.Random import get_random_bytes

def test_aes_gcm_encrypt_decrypt():
    '''
    Test the AES GCM encryption and decryption functions.
    1. Encrypt a known plaintext with a known key.
    2. Check that the ciphertext is not equal to the plaintext.
    3. Check that the ciphertext is not empty.
    4. Decrypt the ciphertext.
    5. Check that the decrypted plaintext is equal to the original plaintext.
    '''
    # Test with a known plaintext and key
    key = get_random_bytes(32) # 32 bytes key for AES-256
    plaintext = 'This is a test.'
    ciphertext = aes_gcm_encrypt(key, plaintext)
    # Check that the ciphertext is not equal to the plaintext
    assert ciphertext != plaintext
    assert len(ciphertext) > 0
    # Decrypt the ciphertext
    decrypted_plaintext = aes_gcm_decrypt(key, ciphertext)
    # Check that the decrypted plaintext is equal to the original plaintext
    assert decrypted_plaintext == plaintext
    
def test_argon2():
    '''
    Test the Argon2 hashing and verification functions.
    1. Hash a known password with a known salt.
    2. Check that the hash is not empty.
    3. Verify the hash with the correct password.
    4. Verify the hash with an incorrect password.
    '''
    # Test with a known password and salt
    password = 'password123'
    salt = get_random_bytes(32)
    hash_argon = hash_argon2id(salt,password)
    # Check that the hash is not empty
    assert len(hash_argon) > 0
    # Verify the hash with the correct password
    assert verify_hash(hash_argon, salt,password) is True
    # Verify the hash with an incorrect password
    assert verify_hash(hash_argon, salt,'wrondpassword') is False
    
def test_gpg_encrypt_decrypt():
    '''
    Test the GPG encryption and decryption functions.
    1. Encrypt a known plaintext with a known key.
    2. Check that the ciphertext is not equal to the plaintext.
    3. Check that the ciphertext is not empty.
    4. Decrypt the ciphertext.
    5. Check that the decrypted plaintext is equal to the original plaintext.
    '''
    # Test with a known plaintext and key
    key = '1234567890123456789012345678901234567890123456789012345678901234567890'
    plaintext = 'This is a test.'
    ciphertext = gpg_encrypt(key, plaintext)
    # Check that the ciphertext is not equal to the plaintext
    assert ciphertext != plaintext
    assert len(ciphertext) > 0
    # Decrypt the ciphertext
    decrypted_plaintext = gpg_decrypt(key, ciphertext)
    # Check that the decrypted plaintext is equal to the original plaintext
    assert decrypted_plaintext == plaintext