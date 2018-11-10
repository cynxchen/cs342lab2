# ECB cut-and-paste
# Write a k=v parsing routine, as if for a structured cookie. The routine should take:
#
# foo=bar&baz=qux&zap=zazzle
# ... and produce:
#
# {
#   foo: 'bar',
#   baz: 'qux',
#   zap: 'zazzle'
# }
# (you know, the object; I don't care if you convert it to JSON).

import random
import set2_ch11
import set1_ch7
import set2_ch9
import set2_ch10

def parse_cookie(cookie):
    items = cookie.split(b'&')
    obj = {}
    for i in items:
        key_val = i.split(b'=')
        obj[key_val[0]] = key_val[1]
    return obj

# Now write a function that encodes a user profile in that format,
# given an email address. You should have something like:
#
# profile_for("foo@bar.com")
# ... and it should produce:
#
# {
#   email: 'foo@bar.com',
#   uid: 10,
#   role: 'user'
# }
# ... encoded as:
#
# email=foo@bar.com&uid=10&role=user
# Your "profile_for" function should not allow encoding metacharacters (& and =).
# Eat them, quote them, whatever you want to do, but don't let people set their
# email address to "foo@bar.com&role=admin".

def profile_for(email):
    clean_email = email.replace(b'&', b'').replace(b'=', b'')
    return b'email=' + clean_email + b'&uid=' + b'10' + b'&role=user'

# Now, two more easy functions. Generate a random AES key, then:
key = set2_ch11.random_16_bytes()

# Encrypt the encoded user profile under the key; "provide" that to the "attacker".
def encrypt_profile(key, profile):
    prof_padded = set2_ch9.padding(profile, 16)
    encrypted = set1_ch7.encrypt(key, prof_padded)
    return encrypted

# Decrypt the encoded user profile and parse it.
def decrypt_profile(key, cipher_prof):
    plain_prof = set1_ch7.decrypt(key, cipher_prof)
    plain_prof = set2_ch10.unpad(plain_prof)
    return plain_prof

# Using only the user input to profile_for() (as an oracle to generate "valid"
# ciphertexts) and the ciphertexts themselves, make a role=admin profile.
def create_admin():
    email1 = b'foo@bar.commm'
    email2 = b'c' * 10 + b'admin' + b'\x0b' * 11

    prof1 = profile_for(email1)
    prof2 = profile_for(email2)

    encrypted1 = encrypt_profile(key, prof1)
    encrypted2 = encrypt_profile(key, prof2)

    encrypted_admin = encrypted1[:32] + encrypted2[16:32] # concatenate cleverly
    decrypted_admin = decrypt_profile(key, encrypted_admin)

    return parse_cookie(decrypted_admin)

def main():
    print(parse_cookie(b'foo=bar&baz=qux&zap=zazzle'))
    profile = profile_for(b"foo@bar.com")
    print(profile)
    encrypted = encrypt_profile(key, profile)
    print(encrypted)
    decrypted = decrypt_profile(key, encrypted)
    print(decrypted)
    print(decrypted == profile)
    print(create_admin())

if __name__ == "__main__":
    main()
