# Fixed XOR
# Write a function that takes two equal-length buffers and produces their XOR combination.
#
# If your function works properly, then when you feed it the string:
#
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:
#
# 686974207468652062756c6c277320657965
# ... should produce:
#
# 746865206b696420646f6e277420706c6179

import codecs

def fixed_xor(first, second):
    decode1 = codecs.decode(first, 'hex')
    decode2 = codecs.decode(second, 'hex')
    res = xor(decode1, decode2)
    return codecs.encode(res, 'hex')

def xor(first, second):
    xor = bytes(a^b for a,b in zip(first,second))
    return xor

def main():
    input1 = b'1c0111001f010100061a024b53535009181c'
    input2 = b'686974207468652062756c6c277320657965'
    xored = fixed_xor(input1, input2)
    print(xored)

if __name__ == "__main__":
    main()
