/**
 * Utilizando a biblioteca cripto para criptografar e descriptografar dados com AES GCM.
 * A chave AES deve ser definida na variável de ambiente 'AES_KEY' em formato hexadecimal.
 * A chave deve ser de 16, 24 ou 32 bytes (128, 192 ou 256 bits).
 *
 * Executar com o seguinte comando para injetar a chave AES:
 * infisical run -- node segredos.js
 */

const cripto = require('./cripto.js');

const text = 'hello world';

// Verifica se a chave AES foi definida
if (!process.env.AES_KEY) {
    console.error('A chave AES deve ser definida na variável de ambiente "AES_KEY" em formato hexadecimal.');
    process.exit(1);
}

console.log('Chave AES:', process.env.AES_KEY);
encrypted = cripto.encrypt_gcm(text, process.env.AES_KEY);
console.log('Texto criptografado:', encrypted);
decrypted = cripto.decrypt_gcm(encrypted, process.env.AES_KEY);
console.log('Texto descriptografado:', decrypted);
if (decrypted !== text) {
    console.error('Erro: o texto descriptografado não corresponde ao texto original.');
    process.exit(1);
}
console.log('Texto descriptografado corresponde ao texto original.');