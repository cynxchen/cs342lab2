# Byte-at-a-time ECB decryption (Harder)
# Take your oracle function from #12. Now generate a random count of random bytes
# and prepend this string to every plaintext. You are now doing:
#
# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
# Same goal: decrypt the target-bytes.

import set2_ch9
import set1_ch7
import codecs
import set1_ch6
import set2_ch11

key = b'\xfdp \x14\x8a\x80W\xc2\xe6\xfec\x99\x9d^\xf4\x82'
random_prefix = set2_ch11.random_append() # needs to be consistent
block_size = 16

# ecb encrypts with random prefix and unknown string
def byte_ecb_encrypt_hard(message, key):
    unknown_string = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    message = random_prefix + message + codecs.decode(unknown_string, 'base64')
    message = set2_ch9.padding(message, 16)
    return set1_ch7.encrypt(key, message)

# detect length of random prefix
def detect_prefix_len():
    counter = 0
    cipher = byte_ecb_encrypt_hard(b'A' * (counter + 32), key)
    blocks = list(set1_ch6.chunks(cipher, 16))
    init_repeat = repeats = len(blocks) - len(set(blocks))
    # increment num A's until there are duplicate ciphertext blocks
    while (init_repeat == repeats):
        counter += 1
        cipher = byte_ecb_encrypt_hard(b'A' * (counter + 32), key)
        blocks = list(set1_ch6.chunks(cipher, 16))
        repeats = len(blocks) - len(set(blocks))
    # find which blocks are repeated
    repeat_block = 0
    while repeat_block < len(blocks)-1 and blocks[repeat_block] != blocks[repeat_block+1]:
        repeat_block += 1
    # return number of extra A's, and which block is repeated
    return counter, repeat_block

def prepend_hard(unknown):
    extra_pad, full_control_block = detect_prefix_len()
    unknown_len = len(unknown)
    pad_len = block_size - (unknown_len % block_size) - 1
    pre = b'A' * (pad_len + extra_pad) # add extra padding
    return pre, ((unknown_len + pad_len) // block_size) + full_control_block # increase block num

# same concept as challenge 12, but use prepend_hard to create plaintext to encrypt
def byte_ecb_decrypt_hard():
    output_dict = {}
    unknown = b''
    while unknown == b'' or unknown[-1] != 1:
        pre, block_num = prepend_hard(unknown)
        for i in range(128):
            single_chr = bytes(chr(i), 'ascii')
            pt = pre + unknown + single_chr
            ct = list(set1_ch6.chunks(byte_ecb_encrypt_hard(pt, key), block_size))[block_num]
            output_dict[ct] = single_chr
        single_block = list(set1_ch6.chunks(byte_ecb_encrypt_hard(pre, key), block_size))
        unknown += output_dict[single_block[block_num]]
    return unknown[:-1]

def main():
    print(byte_ecb_decrypt_hard())

if __name__ == "__main__":
    main()
