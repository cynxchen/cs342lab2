# Detect AES in ECB mode
# In this file are a bunch of hex-encoded ciphertexts.
#
# One of them has been encrypted with ECB.
#
# Detect it.
#
# Remember that the problem with ECB is that it is stateless and deterministic;
# the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

import set1_ch6
from collections import Counter
import numpy as np

def detect_ECB(filename):
    unique = []
    content = []
    with open(filename, "rb") as file:
        for line in file:
            content.append(line)
            chunked = list(set1_ch6.chunks(line, 16))
            unique.append(len(Counter(chunked))) # number of unique chunks
    AES_encrypted = np.argmin(unique)
    return AES_encrypted, content[AES_encrypted]

def main():
    index, ciphertext = detect_ECB("set1_ch8_data.txt")
    print(index, ciphertext)

if __name__ == "__main__":
    main()
