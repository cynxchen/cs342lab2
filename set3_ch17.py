# The CBC padding oracle
# This is the best-known attack on modern block-cipher cryptography.
#
# Combine your padding code and your CBC code to write two functions.
#
# The first function should select at random one of the following 10 strings:
#
# MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
# MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
# MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
# MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
# MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
# MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
# MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
# MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
# MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
# MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
# ... generate a random AES key (which it should save for all future encryptions),
# pad the string out to the 16-byte AES block size and CBC-encrypt it under that key,
# providing the caller the ciphertext and IV.

import set2_ch10
import random
import set2_ch15
import set1_ch2
import set1_ch6
import codecs

key = b'\xfdp \x14\x8a\x80W\xc2\xe6\xfec\x99\x9d^\xf4\x82'
iv = b'n\x0f\xb6|\xb1\xe1\x02k\xa5~T\xd7\x9e\xa2I\xc7'
random_input = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

for r in random_input:
    print(codecs.decode(r, 'base64'))

def cbc_encrypt_padding():
    input_ind = random.randint(0,9)
    input = random_input[input_ind]
    print(input)
    return set2_ch10.cbc_encrypt(key, input, iv), iv

rand_cipher, iv = cbc_encrypt_padding()
blocks = [iv] + list(set1_ch6.chunks(rand_cipher, 16))
len(blocks)

# The second function should consume the ciphertext produced by the first function,
# decrypt it, check its padding, and return true or false depending on whether the
# padding is valid.

def cbc_decrypt_padding(ciphertext):
    decrypt = set2_ch10.cbc_decrypt_wo_unpad(key, ciphertext, iv)
    # print(decrypt)
    try:
        set2_ch15.valid_padding(decrypt)
        return True
    except:
        return False

print(cbc_decrypt_padding(rand_cipher))

# What you're doing here.
# This pair of functions approximates AES-CBC encryption as its deployed serverside
# in web applications; the second function models the server's consumption of an
# encrypted session token, as if it was a cookie.
#
# It turns out that it's possible to decrypt the ciphertexts provided by the first
# function.


def exploit_cbc_oracle(blocks):
    message = b''
    for b_num in range(len(blocks)-1):
        guessed = bytearray([0] * 16)
        for b in range(15, -1, -1):
            padding = bytearray([0] * 16)
            padding[b:16] = [16-b] * (16-b)
            modified = set1_ch2.xor(set1_ch2.xor(blocks[b_num], padding), guessed)
            for i in range(256):
                r = bytearray([0] * 16)
                r[b] = i
                xored = set1_ch2.xor(modified,r)
                if cbc_decrypt_padding(xored + blocks[b_num+1]):
                    if not (16-b == 1 and i == 1):
                        guessed[b] = i
        message += codecs.decode(guessed, 'base64')
        print(guessed)
    print(message)

rand_cipher, iv = cbc_encrypt_padding()
exploit_cbc_oracle([iv] + list(set1_ch6.chunks(rand_cipher, 16)))
print('hi')
# The decryption here depends on a side-channel leak by the decryption function.
# The leak is the error message that the padding is valid or not.
#
# You can find 100 web pages on how this attack works, so I won't re-explain it.
# What I'll say is this:
#
# The fundamental insight behind this attack is that the byte 01h is valid padding,
# and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.
#
# 02h in isolation is not valid padding.
#
# 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
#
# 03h 03h 03h is even less likely.
#
# So you can assume that if you corrupt a decryption AND it had valid padding, you
# know what that padding byte is.
#
# It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding
# oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack
# that targets a specific bit of code that handles decryption. You can mount a padding
# oracle on any CBC block, whether it's padded or not.
