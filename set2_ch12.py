# Byte-at-a-time ECB decryption (Simple)
# Copy your oracle function to a new function that encrypts buffers under ECB mode
# using a consistent but unknown key (for instance, assign a single random key,
# once, to a global variable).

# Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING,
# the following string:
#
# Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
# aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
# dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
# YnkK
# Spoiler alert.
# Do not decode this string now. Don't do it.
#
# Base64 decode the string before appending it. Do not base64 decode the string by
# hand; make your code do it. The point is that you don't know its contents.
#
# What you have now is a function that produces:
#
# AES-128-ECB(your-string || unknown-string, random-key)

import set2_ch11
import set2_ch10
import set2_ch9
import set1_ch7
import set1_ch6
import codecs

key = b'\xfdp \x14\x8a\x80W\xc2\xe6\xfec\x99\x9d^\xf4\x82'

def byte_ecb_encrypt(message, key):
    unknown_string = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    message += codecs.decode(unknown_string, 'base64')
    message = set2_ch9.padding(message, 16)
    return set1_ch7.encrypt(key, message)

# It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
#
# Here's roughly how:
#
# 1. Feed identical bytes of your-string to the function 1 at a time --- start with
# 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher.
# You know it, but do this step anyway.

def detect_block_size():
    block_size = 1
    while(byte_ecb_encrypt(b'A' * block_size * 2, key)[:block_size] !=
          byte_ecb_encrypt(b'A' * block_size * 2, key)[block_size:block_size*2]):
        block_size += 1
    return block_size

block_size = detect_block_size()

# 2. Detect that the function is using ECB. You already know, but do this step anyways.

test_pt = byte_ecb_encrypt(b'A' * 32, key)
detected_cipher = set2_ch11.detect_cipher(test_pt)

# 3. Knowing the block size, craft an input block that is exactly 1 byte short (for
# instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the
# oracle function is going to put in that last byte position.

# 4. Make a dictionary of every possible last byte by feeding different strings to the oracle;
# for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

# 5. Match the output of the one-byte-short input to one of the entries in your dictionary.
# You've now discovered the first byte of unknown-string.

# 6. Repeat for the next byte.

def prepend(unknown):
    unknown_len = len(unknown)
    pad_len = block_size - (unknown_len % block_size) - 1
    pre = b'A' * pad_len
    return pre, (unknown_len + pad_len) // block_size

def byte_ecb_decrypt():
    output_dict = {} # dictionary holding blocks with shortened byte and character
    unknown = b'' # uncovered secret string

    while unknown == b'' or unknown[-1] != 1:
        pre, block_num = prepend(unknown)
        for i in range(128): # every possible ascii character
            single_chr = bytes(chr(i), 'ascii')
            pt = pre + unknown + single_chr
            ct = list(set1_ch6.chunks(byte_ecb_encrypt(pt, key), block_size))[block_num]
            output_dict[ct] = single_chr # find matching chunk
        single_block = list(set1_ch6.chunks(byte_ecb_encrypt(pre, key), block_size))
        unknown += output_dict[single_block[block_num]]

    return unknown[:-1]

def main():
    print(byte_ecb_decrypt())

if __name__ == "__main__":
    main()
