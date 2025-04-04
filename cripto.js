/**
 * 
 * @description Functions for AES256-GCM encryption/decryption and Argon2 hashing.<br>
 * This module provides functions to generate an AES key, encrypt and decrypt messages,
 * and hash and verify passwords using Argon2.<br>
 * It uses the PyCryptodome library for AES encryption and Argon2 for password hashing.<br>
 * It is important to note that the AES key should be kept secret and secure.<br>
 * The Argon2 hash should also be stored securely, as it is used to verify passwords.<br>
 * This module is intended for educational purposes and should not be used in 
 * production without proper security measures.<br>

 * @author RAFAEL PERAZZO B MOTA
 * @date Date: 2025-03-30
 * @version 1.0 
 * 
 */
var crypto = require('crypto');
const argon2 = require('argon2');

/**
 * Converts a hex string to a Uint8Array.
 * @param {string} hexString - The hex string to convert.
 * @returns {Uint8Array} - The converted Uint8Array.
 */
function hexString2bytes(hexString) {
    const convertido = Uint8Array.from(Buffer.from(hexString, 'hex'));
    return convertido;
}

/**
 * Encrypts a message using AES256-GCM encryption.
 * @param {string} text - The message to encrypt.
 * @param {Uint8Array} key - The AES key to use for encryption.
 * @returns {string} - The encrypted message in hex format.
 */
function encrypt_gcm(text, key) {
    if (typeof key === 'string') {
        key = hexString2bytes(key);
    }
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), iv);
    var encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    var tag = cipher.getAuthTag();
    encrypted = iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted;
    return encrypted;
}

/**
 * Decrypts a message using AES256-GCM encryption.
 * @param {string} text - The message to decrypt.
 * @param {Uint8Array} key - The AES key to use for decryption.
 * @returns {string} - The decrypted message.
 */
function decrypt_gcm(text, key) {
    if (typeof key === 'string') {
        key = hexString2bytes(key);
    }
    var iv = text.split(':')[0];
    var tag = text.split(':')[1];
    text = text.split(':')[2];
    var decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    var decrypted = decipher.update(text, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

/**
 * Generates a HMAC using SHA3-512.
 * @param {Uint8Array} key - The key to use for HMAC generation.
 * @param {string} data - The data to hash.
 * @returns {string} - The HMAC in hex format.
 */
function hmac(key, data) {
    if (typeof key === 'string') {
        key = hexString2bytes(key);
    }
    var hmac = crypto.createHmac('sha3-512', key);
    hmac.update(data);
    return hmac.digest('hex');
}

/**
 * Hashes a password using Argon2.
 * @param {string} password - The password to hash.
 * @returns {string} - The hashed password.
 */
async function hashPassword(password) {
    return await argon2.hash(password);;
}

/**
 * Verifies a password against a hash using Argon2.
 * @param {string} password - The password to verify.
 * @param {string} hash - The hash to verify against.
 * @returns {boolean} - True if the password matches the hash, false otherwise.
 * @throws {Error} - If the password does not match the hash.
 */
async function verifyPassword(password, hash) {
    try {
        return await argon2.verify(hash, password);
    }
    catch (err) {
        return false;
    }
}

module.exports = {
    encrypt_gcm,
    decrypt_gcm,
    hmac,
    hashPassword,
    verifyPassword
};