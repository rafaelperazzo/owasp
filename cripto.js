var crypto = require('crypto');
const argon2 = require('argon2');

function encrypt(text, key) {
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
    var encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), encryptedData: encrypted };
}

function decrypt(text, key, iv) {
    var decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv, 'hex'));
    var decrypted = decipher.update(text, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function hmac(key, data) {
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
/*
var iv = crypto.randomBytes(16);
var algorithm = 'aes-256-cbc';
var cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
var decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
cipher.update('hello world', 'utf8', 'hex');
var mystr = cipher.final('hex');
console.log('cipher', mystr);
*/

var text = 'hello world';
var encrypted = encrypt(text, key);
console.log('encrypted', encrypted);
var decrypted = decrypt(encrypted.encryptedData, key, encrypted.iv);
console.log('decrypted', decrypted);
console.log(hmac(key, text));

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