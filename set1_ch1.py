# Convert hex to base64
# The string:
#
# 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
# Should produce:
#
# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
# So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
#
# Cryptopals Rule
# Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

import codecs

def hex_to_base64(hex):
    decode = codecs.decode(hex, 'hex')
    encode = codecs.encode(decode, 'base64')
    return encode

def base64_to_hex(base64):
    decode = codecs.decode(base64, 'base64')
    encode = codecs.encode(decode, 'hex')
    return encode

s = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
h = hex_to_base64(s)
base64_to_hex(h)
