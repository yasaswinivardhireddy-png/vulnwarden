"""Encryption of stored card tokens."""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_token(key: bytes, token: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(token) + encryptor.finalize()


def new_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
