# AES in ECB mode
# The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
#
# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
#
# Decrypt it. You know the key, after all.
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

import codecs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def decrypt(key, ciphertext):
    decryptor = Cipher(
        algorithms.AES(key), #AES
        modes.ECB(), #ECB mode
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt(key, plaintext):
    encryptor = Cipher(
        algorithms.AES(key), #AES
        modes.ECB(), #ECB mode
        backend=default_backend()
    ).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def main():
    key = b'YELLOW SUBMARINE'
    filename = "set1_ch7_encrypted.txt"
    with open(filename, "rb") as file:
        content = codecs.decode(file.read(), 'base64')
        decrypted = decrypt(key, content)
    print(decrypted)
    encrypted = encrypt(key, decrypted)
    print(encrypted)
    print(encrypted == content)

if __name__ == "__main__":
    main()
