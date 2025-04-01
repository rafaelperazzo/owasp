import os
from cripto import aes_gcm_encrypt, aes_gcm_decrypt
from cripto import hexstring_to_bytes,bytes_to_hexstring
import base64

try:
    key = os.environ['AES_KEY']
except KeyError:
    print("A chave criptografada não foi encontrada. Defina a variável de ambiente 'AES_KEY' com a chave AES em formato hexadecimal.")
    exit(1)

'''
Executar com o seguinte comando:
    infisical run -- python segredos.py
'''

TEXTO = "Texto a ser criptografado"

enc = aes_gcm_encrypt(key, TEXTO)
print(enc)
dec = aes_gcm_decrypt(key, enc)
print(dec)
