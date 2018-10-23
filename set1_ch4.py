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
            line = line.strip()
            # Append best decrypted message for each line
            best.append(set1_ch3.single_byte_xor_cipher_info(line))
    # Return best of the best decrypted messages
    return max(best, key = lambda x: x[2])[0]

def main():
    detected = detect_single_xor('set1_ch4_data.txt')
    print(detected)

if __name__ == "__main__":
    main()
