# Single-byte XOR cipher
# The hex encoded string:
#
# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character. Find the key, decrypt the message.
#
# You can do this by hand. But don't: write code to do it for you.
#
# How? Devise some method for "scoring" a piece of English plaintext.
# Character frequency is a good metric. Evaluate each output and choose the one with the best score.

import codecs

def single_byte_xor_cipher(cipher):
    return single_byte_xor_cipher_score(cipher)[0]

def single_byte_xor_cipher_score(cipher):
    poss = [single_xor_score(cipher, i) for i in range(256)]
    return max(poss, key = lambda x: x[2])

def single_xor_score(cipher, key):
    decode = codecs.decode(cipher, 'hex')
    key_multiple = [key] * len(decode)
    xor = bytes(a^b for a,b in zip(decode,key_multiple))
    return xor, key, scoring(str(xor))

def scoring(s):
    return s.count(" ")/len(s)
    # mapping = map(str.count, ['e', 't', 'a', 'i', 'n', 'o', 's'])
    # mapping =
    # return((sum(mapping)+(2*str.count(" ")))/len(str))

cipher = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
single_byte_xor_cipher(cipher)
