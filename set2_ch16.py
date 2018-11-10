# CBC bitflipping attacks
# Generate a random AES key.
#
# Combine your padding code and CBC code to write two functions.
#
# The first function should take an arbitrary input string, prepend the string:
#
# "comment1=cooking%20MCs;userdata="
# .. and append the string:
#
# ";comment2=%20like%20a%20pound%20of%20bacon"
# The function should quote out the ";" and "=" characters.
#
# The function should then pad out the input to the 16-byte AES block length and
# encrypt it under the random AES key.

import set2_ch10
import set1_ch6

key = b'\xfdp \x14\x8a\x80W\xc2\xe6\xfec\x99\x9d^\xf4\x82'
iv = b"\x00" * 16

def encrypt_cbc_bitflip(input):
    input = input.replace(b";", b"';'")
    input = input.replace(b"=", b"'='")
    input = b"comment1=cooking%20MCs;userdata=" + input + b";comment2=%20like%20a%20pound%20of%20bacon"
    encrypted = set2_ch10.cbc_encrypt(key, input, iv)
    return encrypted

# The second function should decrypt the string and look for the characters ";admin=true;"
# (or, equivalently, decrypt, split the string on ";", convert each resulting string
# into 2-tuples, and look for the "admin" tuple).
#
# Return true or false based on whether the string exists.

def decrypt_cbc_bitflip(encrypted):
    plaintext = set2_ch10.cbc_decrypt(key, encrypted, iv)
    # split on ";" and convert to tuples
    converted = [tuple(p.split(b'=')) for p in plaintext.split(b';')]
    # search for "admin tuple"
    return any(map(lambda tup: tup[0] == b'admin', converted))

# If you've written the first function properly, it should not be possible to provide
# user input to it that will generate the string the second function is looking for.
# We'll have to break the crypto to do that.
#
# Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
#
# You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

def modify_ciphertext(encrypted):
    blocks = list(set1_ch6.chunks(encrypted, 16))
    prev_block = list(blocks[1])
    prev_block[4] ^= 1 # bit flip to make ';'
    prev_block[10] ^= 1 # bit flip to make '='
    blocks[1] = bytes(prev_block)
    encrypted2 = b''.join(blocks)
    return encrypted2

# Completely scrambles the block the error occurs in
# Produces the identical 1-bit error(/edit) in the next ciphertext block.
# Stop and think for a second.
# Before you implement this attack, answer this question: why does CBC mode have this property?

def main():
    ciphertext = encrypt_cbc_bitflip(b'data:admin<true')
    ciphertext2 = modify_ciphertext(ciphertext)
    print(decrypt_cbc_bitflip(ciphertext2))

if __name__ == "__main__":
    main()
