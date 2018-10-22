# There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
#
# Decrypt it.
#
# Here's how:
#
# Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
#
# Write a function to compute the edit distance/Hamming distance between two strings.
# The Hamming distance is just the number of differing bits. The distance between:
# this is a test
# and
# wokka wokka!!!
# is 37. Make sure your code agrees before you proceed.

import binascii
import codecs
import numpy as np


def byte_to_bin(byte_str):
    return bin(int.from_bytes(byte_str, byteorder="big"))

def edit_distance(str1, str2):
    bin1 = byte_to_bin(str1)[2:]
    bin2 = byte_to_bin(str2)[2:]
    diff = [s1 != s2 for s1,s2 in zip(bin1, bin2)]
    return sum(diff)

t1 = b'this is a test'
t2 = b'wokka wokka!!!'
print()

edit_distance(t1,t2)

# For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE
# worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.

import os
import itertools
rand = os.urandom(100)

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def key_distance(KEYSIZE, s):
    chunk_keysize = list(chunks(s, KEYSIZE))[:4]
    norm = [edit_distance(a,b) for a,b in itertools.combinations(chunk_keysize, 2)]
    return np.mean(norm)/KEYSIZE

    # norm = [
    #
    # return edit_distance(first, second)/KEYSIZE

print(key_distance(5, rand))

# The KEYSIZE with the smallest normalized edit distance is probably the key.
# You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks
# instead of 2 and average the distances.


def top_3_keysize(text):
    distances = [key_distance(i, text) for i in range(2,41)]
    return [n + 2 for n in np.argsort(distances)[:10]]

top_3_keysize(rand)
# top_3_keysize(content)

import set1_ch1

filename = "set1_ch6_file.txt"
with open(filename, "rb") as file:
    content = codecs.decode(file.read(), 'base64')
    keys = top_3_keysize(content)
    print(keys)

# Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

chunked = list(chunks(content, keys[3]))[:-1]
chunked
# Now transpose the blocks: make a block that is the first byte of every block, and a block
# that is the second byte of every block, and so on.

t_chunked = [bytes(z) for z in zip(*chunked)]
len(t_chunked)
print(t_chunked[0])

# Solve each block as if it was single-character XOR. You already have code to do this.
import set1_ch3

final_key = []
for b in t_chunked:
    encode = codecs.encode(b, 'hex')
    final_key.append(set1_ch3.single_byte_xor_cipher_score(encode)[1])

final_key

# For each block, the single-byte XOR key that produces the best looking histogram is
# the repeating-key XOR key byte for that block. Put them together and you have the key.

import set1_ch5

result = set1_ch5.fixed_xor(final_key, content)
print(result)
print(codecs.decode(result, 'hex'))

### EVERYTHING

poss_pt = []
for k in keys:
    chunked = list(chunks(content, k))[:-1]
    t_chunked = [bytes(z) for z in zip(*chunked)]

    final_key = []
    for b in t_chunked:
        encode = codecs.encode(b, 'hex')
        final_key.append(set1_ch3.single_byte_xor_cipher_score(encode)[1])

    result = set1_ch5.fixed_xor(final_key, content)
    poss_pt.append(codecs.decode(result, 'hex'))
print(poss_pt)
print(max(poss_pt, key = lambda x: set1_ch3.scoring(str(x))))

# This code is going to turn out to be surprisingly useful later on. Breaking repeating-key
# XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing.
# But more people "know how" to break it than can actually break it, and a similar technique
# breaks something much more important.
