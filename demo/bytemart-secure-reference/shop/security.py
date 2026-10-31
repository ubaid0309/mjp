# ByteMart security helpers - secure reference version (DEMO DATA)
import os
import secrets

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_hasher = PasswordHasher()  # argon2id with library defaults


def hash_password(password):
    return _hasher.hash(password)


def make_reset_token():
    return secrets.token_urlsafe(32)


def encrypt_card_note(key, note):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, note.encode(), None)


def read_token(token):
    return jwt.decode(token, os.environ["BYTEMART_JWT_KEY"], algorithms=["HS256"])
