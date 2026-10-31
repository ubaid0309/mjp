# ByteMart security helpers - DEMO DATA, intentionally vulnerable. Do not deploy.
import hashlib
import random
import string

import jwt
from Crypto.Cipher import DES


def hash_password(password):
    # Vulnerable: fast, unsalted hash
    return hashlib.md5(password.encode()).hexdigest()


def make_reset_token():
    # Vulnerable: predictable PRNG for a security token
    return "".join(random.choice(string.ascii_letters) for _ in range(24))


def encrypt_card_note(key, note):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(note.ljust(64).encode())


def read_token(token):
    # Vulnerable: signature never checked
    return jwt.decode(token, options={"verify_signature": False})
