/**
 * Automated test for cripto.js
 * 
 */

const cripto = require('./cripto.js');

test ('Encrypt and decrypt a message', () => {
        var text = 'hello world';
        const key = Uint8Array.from(Buffer.from("09d4d25caa46a1e355c68470231b079c6e92ade95aa6e560b11dc5c18fbe6eba", 'hex'));
        var encrypted = cripto.encrypt_gcm(text, key);
        var decrypted = cripto.decrypt_gcm(encrypted, key);
        expect(decrypted).toBe(text);
        expect(decrypted).not.toBe('hello world1');
    });

test ('Encrypt and decrypt a message with a string key', () => {
        var text = 'hello world';
        const key = "09d4d25caa46a1e355c68470231b079c6e92ade95aa6e560b11dc5c18fbe6eba";
        var encrypted = cripto.encrypt_gcm(text, key);
        var decrypted = cripto.decrypt_gcm(encrypted, key);
        expect(decrypted).toBe(text);
        expect(decrypted).not.toBe('hello world1');
    }
);

test ('hash and verify password', async () => {
        var text = 'hello world';
        const hash = await cripto.hashPassword(text);
        const result = await cripto.verifyPassword(text, hash);
        expect(result).toBe(true);
    }
);
test ('hash and verify password with wrong password', async () => {
        var text = 'hello world';
        const hash = await cripto.hashPassword(text);
        const result = await cripto.verifyPassword('wrongpassword', hash);
        expect(result).toBe(false);
    }
);
test ('hash and verify password with wrong hash', async () => {
        var text = 'hello world';
        const hash = await cripto.hashPassword(text);
        const result = await cripto.verifyPassword(text, 'wronghash');
        expect(result).toBe(false);
    }
);
