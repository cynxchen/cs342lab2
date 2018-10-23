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
import set1_ch2

# Decrypts cipher into plaintext
def single_byte_xor_cipher(cipher):
    return single_byte_xor_cipher_info(cipher)[0]

# Decrypts cipher into plaintext. Returns detailed information including
# decrypted message, key, and "score"
def single_byte_xor_cipher_info(cipher):
    poss = [single_xor_score(cipher, i) for i in range(256)]
    return max(poss, key = lambda x: x[2])

# Performs XOR and returns associated English plaintext score
def single_xor_score(cipher, key):
    decode = codecs.decode(cipher, 'hex')
    key_multiple = [key] * len(decode)
    res = set1_ch2.xor(decode, key_multiple)
    return res, key, scoring(str(res))

# Scoring function of English plaintext. English sentences should have more spaces
def scoring(s):
    s = s.upper()
    common = "ETAOINSHRDLU"
    count = 0
    for ch in s:
        if ch == " ":
            count += 20
        elif ch in common:
            count ++ 1
    return count

def main():
    cipher = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    decrypt = single_byte_xor_cipher(cipher)
    print(decrypt)

if __name__ == "__main__":
    main()
