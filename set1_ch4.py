# Detect single-character XOR
# One of the 60-character strings in this file has been encrypted by single-character XOR.
#
# Find it.
#
# (Your code from #3 should help.)

import set1_ch3

def detect_single_xor(filename):
    best = []
    with open(filename, "rb") as file:
        for line in file:
            if line.endswith(b'\n'):
                line = line[:-1]
            best.append(set1_ch3.single_byte_xor_cipher_score(line))
    return max(best, key = lambda x: x[2])

print(detect_single_xor('set1_ch4_data.txt'))
