# An ECB/CBC detection oracle
# Now that you have ECB and CBC working:
#
# Write a function to generate a random AES key; that's just 16 random bytes.
#
# Write a function that encrypts data under an unknown key --- that is, a function
# that generates a random key and encrypts under it.
#
# The function should look like:
#
# encryption_oracle(your-input)
# => [MEANINGLESS JIBBER JABBER]
# Under the hood, have the function append 5-10 bytes (count chosen randomly) before
# the plaintext and 5-10 bytes after the plaintext.
#
# Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the
# other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
#
# Detect the block cipher mode the function is using each time. You should end up
# with a piece of code that, pointed at a block box that might be encrypting ECB or
# CBC, tells you which one is happening.

import os
from random import randint
import set1_ch7
import set2_ch9
import set2_ch10

def random_16_bytes():
    return os.urandom(16)

def random_append():
    count = randint(5,10)
    return os.urandom(count)

def encryption_oracle(message):
    key = random_16_bytes()
    print(message, len(message))
    message = random_append() + message + random_append()
    print(message, len(message))
    message = set2_ch9.padding(message, 16)
    print(message, len(message))
    if randint(0,1):
        return set1_ch7.encrypt(key, message)
    else:
        iv = random_16_bytes()
        return set2_ch10.cbc_encrypt(key, message, iv)

message = b"I'm back and I'm ringin' the bell"
encryption_oracle(message )

def detect_cipher(ciphertext):
    
