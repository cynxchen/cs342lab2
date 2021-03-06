# Implement PKCS#7 padding
# A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
# plaintext into ciphertext. But we almost never want to transform a single block;
# we encrypt irregularly-sized messages.
#
# One way we account for irregularly-sized messages is by padding, creating a
# plaintext that is an even multiple of the blocksize. The most popular padding
# scheme is called PKCS#7.
#
# So: pad any block to a specific block length, by appending the number of bytes
# of padding to the end of the block. For instance,
#
# "YELLOW SUBMARINE"
# ... padded to 20 bytes would be:
#
# "YELLOW SUBMARINE\x04\x04\x04\x04"

def padding(message, block_len):
    pad_len = block_len - (len(message) % block_len)
    append = bytearray([pad_len] * pad_len)
    return message + bytes(append)

def main():
    print(padding(b"YELLOW SUBMARINE", 20))

if __name__ == "__main__":
    main()
