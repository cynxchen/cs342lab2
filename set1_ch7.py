# AES in ECB mode
# The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
#
# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
#
# Decrypt it. You know the key, after all.
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

from Crypto.Cipher import AES
import codecs

key = 'YELLOW SUBMARINE'

# cipher = AES.new(key, AES.MODE_ECB)

filename = "set1_ch7_encrypted.txt"
with open(filename, "rb") as file:
    content = codecs.decode(file.read(), 'base64')
    # content = file.read()

# msg =cipher.encrypt(content)
# print (type(msg))
#
# print(codecs.encode(msg, 'hex'))

def decipher(ciphertext):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(ciphertext)

print(decipher(content))
