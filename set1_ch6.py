# There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
#
# Decrypt it.
#
# Here's how:
#
# Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

import codecs
import numpy as np
import os
import itertools
import set1_ch3
import set1_ch5

# ----------------------------------------------------------------------------------
# Write a function to compute the edit distance/Hamming distance between two strings.
# The Hamming distance is just the number of differing bits. The distance between:
# this is a test
# and
# wokka wokka!!!
# is 37. Make sure your code agrees before you proceed.

# Convert bytes to binary
def byte_to_bin(byte_str):
    return bin(int.from_bytes(byte_str, byteorder="big"))[2:]

# Calculate hamming/edit distance
def edit_distance(str1, str2):
    bin1 = byte_to_bin(str1)
    bin2 = byte_to_bin(str2)
    maxlen = max(len(bin1), len(bin2))
    bin1 = bin1.zfill(maxlen)
    bin2 = bin2.zfill(maxlen)
    diff = [s1 != s2 for s1,s2 in zip(bin1, bin2)]
    return sum(diff)

def test_edit_distance():
    t1 = b'this is a test'
    t2 = b'wokka wokka!!!'
    t_distance = edit_distance(t1,t2)
    return t_distance == 37

# ----------------------------------------------------------------------------------
# For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE
# worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
#
# The KEYSIZE with the smallest normalized edit distance is probably the key.
# You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks
# instead of 2 and average the distances.

# Yield successive n-sized chunks from text
def chunks(text, n):
    for i in range(0, len(text), n):
        yield text[i:i + n]

# Calculate edit distance for KEYSIZE
def key_distance(KEYSIZE, s):
    # get first 4 KEYSIZE blocks
    chunk_keysize = list(chunks(s, KEYSIZE))[:4]
    # calculte edit distance between each pair
    norm = [edit_distance(a,b) for a,b in itertools.combinations(chunk_keysize, 2)]
    return np.mean(norm)/KEYSIZE # average and normalized

# Return 10 "smallest" KEYSIZE values
def top_keysize(text):
    distances = [key_distance(i, text) for i in range(2,41)]
    return np.argsort(distances)[0] + 2

def test_key_size():
    rand = os.urandom(100)
    dist = key_distance(5, rand)
    return top_10_keysize(rand)

# ----------------------------------------------------------------------------------
# Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
# Now transpose the blocks: make a block that is the first byte of every block, and a block
# that is the second byte of every block, and so on.
#
# Solve each block as if it was single-character XOR. You already have code to do this.
#
# For each block, the single-byte XOR key that produces the best looking histogram is
# the repeating-key XOR key byte for that block. Put them together and you have the key.
#
# This code is going to turn out to be surprisingly useful later on. Breaking repeating-key
# XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing.
# But more people "know how" to break it than can actually break it, and a similar technique
# breaks something much more important.

# Decrypt ciphertext given predicted keysize
def decrypt_with_keysize(content, k):
    chunked = list(chunks(content, k))[:-1]
    t_chunked = [bytes(z) for z in zip(*chunked)]

    block_key = []
    # get single-byte XOR key that produces best histogram for each block
    for b in t_chunked:
        encode = codecs.encode(b, 'hex')
        block_key.append(set1_ch3.single_byte_xor_cipher_info(encode)[1])
    # decrypt using key and repeating xor
    result = set1_ch5.repeat_xor(block_key, content)
    return codecs.decode(result, 'hex')

# Decrypt repeated-key xor ciphertext
def decrypt_repeat_xor(filename):
    with open(filename, "rb") as file:
        content = codecs.decode(file.read(), 'base64')

    keysize = top_keysize(content)
    result = decrypt_with_keysize(content, keysize)
    return result

def main():
    test_edit_distance()
    test_key_size()
    decrypted = decrypt_repeat_xor("set1_ch6_file.txt")
    print(decrypted)

if __name__ == "__main__":
    main()
