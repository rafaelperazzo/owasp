'''
Utilizando a biblioteca cripto para criptografar e descriptografar dados
com AES GCM.
A chave AES deve ser definida na variável de ambiente 'AES_KEY' em formato hexadecimal.
A chave deve ser de 16, 24 ou 32 bytes (128, 192 ou 256 bits).

Executar com o seguinte comando para injetar a chave AES:
    infisical run -- python segredos.py
'''

import os
from cripto import aes_gcm_encrypt, aes_gcm_decrypt

try:
    key = os.environ['AES_KEY']
except KeyError:
    print("A chave criptografada não foi encontrada. Defina a variável de ambiente 'AES_KEY' com a chave AES em formato hexadecimal.")
    exit(1)

TEXTO = "Texto a ser criptografado"

enc = aes_gcm_encrypt(key, TEXTO)
print(enc)
dec = aes_gcm_decrypt(key, enc)
print(dec)
