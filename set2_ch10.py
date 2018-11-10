# Implement CBC mode
# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,
# despite the fact that a block cipher natively only transforms individual blocks.
#
# In CBC mode, each ciphertext block is added to the next plaintext block before the
# next call to the cipher core.
#
# The first plaintext block, which has no associated previous ciphertext block, is
# added to a "fake 0th ciphertext block" called the initialization vector, or IV.
#
# Implement CBC mode by hand by taking the ECB function you wrote earlier, making
# it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test),
# and using your XOR function from the previous exercise to combine them.
#
# The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE"
# with an IV of all ASCII 0 (\x00\x00\x00 &c)

import set1_ch6
import codecs
import set1_ch2
import set1_ch7
import set2_ch9

def unpad(text):
    last_byte = text[-1]
    if last_byte < len(text) and (text[-last_byte:] == bytes(bytearray([last_byte] * last_byte))):
        text = text[:-last_byte]
    return text

def cbc_decrypt(key, ciphertext, iv):
    blocks = list(set1_ch6.chunks(ciphertext, 16))
    prev_block = iv
    plaintext = []

    for b in blocks:
        decrypted = set1_ch7.decrypt(key, b)
        plaintext.append(set1_ch2.xor(decrypted, prev_block))
        prev_block = b

    joined = b"".join(plaintext)

    return unpad(joined)

def cbc_decrypt_wo_unpad(key, ciphertext, iv):
    blocks = list(set1_ch6.chunks(ciphertext, 16))
    prev_block = iv
    plaintext = []

    for b in blocks:
        decrypted = set1_ch7.decrypt(key, b)
        plaintext.append(set1_ch2.xor(decrypted, prev_block))
        prev_block = b

    joined = b"".join(plaintext)

    return joined

def cbc_encrypt(key, plaintext, iv):
    plaintext = set2_ch9.padding(plaintext, 16)
    blocks = list(set1_ch6.chunks(plaintext, 16))
    prev_encrypt = iv
    ciphertext = []

    for b in blocks:
        xored = set1_ch2.xor(b, prev_encrypt)
        prev_encrypt = set1_ch7.encrypt(key, xored)
        ciphertext.append(prev_encrypt)

    return b"".join(ciphertext)

filename = 'set2_ch10_cipher.txt'
with open(filename, "rb") as file:
    ciphertext = codecs.decode(file.read(), 'base64')
key = b"YELLOW SUBMARINE"
iv = b"\x00" * 16
plaintext = cbc_decrypt(key, ciphertext, iv)
ciphertext2 = cbc_encrypt(key, plaintext, iv)

print(plaintext)
print(ciphertext == ciphertext2)
