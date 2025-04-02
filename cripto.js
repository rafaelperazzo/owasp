/**
 * 
 * Functions for AES256-CBC and AES256-GCM encryption/decryption and Argon2 hashing.
 * This module provides functions to generate an AES key, encrypt and decrypt messages,
 * and hash and verify passwords using Argon2.
 * It uses the PyCryptodome library for AES encryption and Argon2 for password hashing.
 * It is important to note that the AES key should be kept secret and secure.
 * The Argon2 hash should also be stored securely, as it is used to verify passwords.
 * This module is intended for educational purposes and should not be used in 
 * production without proper security measures.

 * Author: RAFAEL PERAZZO B MOTA
 * Date: 2025-03-30
 * Version: 1.0
 * 
 */
var crypto = require('crypto');
const argon2 = require('argon2');

function hexString2bytes(hexString) {
    const convertido = Uint8Array.from(Buffer.from(hexString, 'hex'));
    return convertido;
}

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

function hmac(key, data) {
    if (typeof key === 'string') {
        key = hexString2bytes(key);
    }
    var hmac = crypto.createHmac('sha3-512', key);
    hmac.update(data);
    return hmac.digest('hex');
}

async function hashPassword(password) {
    return await argon2.hash(password);;
}

async function verifyPassword(password, hash) {
    return await argon2.verify(hash, password);
}

var key = crypto.randomBytes(32);
console.log('key', key.toString('hex'));

var text = 'hello world';
key = Uint8Array.from(Buffer.from("09d4d25caa46a1e355c68470231b079c6e92ade95aa6e560b11dc5c18fbe6eba", 'hex'));
var encrypted = encrypt_gcm(text, key);
console.log('encrypted', encrypted);
var decrypted = decrypt_gcm(encrypted, key);
console.log('decrypted', decrypted);
console.log('hmac',hmac(key, text));

hashPassword('hello world').then((hash) => {
    console.log('hash', hash);
    verifyPassword('hello world', hash).then((result) => {
        console.log('verify', result);
    }).catch((err) => {
        console.log('error', err);
    });
    verifyPassword('wrongpassword', hash).then((result) => {
        console.log('verify', result);
    }).catch((err) => {
        console.log('error', err);
    });
}
).catch((err) => {
    console.log('error', err);
});