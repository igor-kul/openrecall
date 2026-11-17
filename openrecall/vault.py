"""Encryption with a split between recording and viewing.

Recording only needs the public key, which is stored openly in auth.json, so
screenshots are captured without asking for the password. Viewing needs the
private key, which auth.json only holds encrypted with the user's password.
It is kept in memory while the web interface is unlocked and nowhere else.

Deleting auth.json therefore does not give access: without the private key
the recorded data cannot be decrypted at all.
"""

import base64
import hashlib
import json
import os
import secrets
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from openrecall.config import auth_path

# Marks data encrypted for the public key
MAGIC = b"openrecall-v2:"
PUBLIC_KEY_SIZE = 32
MIN_PASSWORD_LENGTH = 10

# scrypt makes every password guess cost ~100 ms and 32 MB, so a copied
# auth.json cannot be brute-forced quickly
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
SALT_SIZE = 16

_public_key: Optional[X25519PublicKey] = None
_private_key: Optional[X25519PrivateKey] = None


class VaultLocked(Exception):
    """Raised when recorded data is read while the password was not entered."""


def _password_cipher(password: str, salt: bytes) -> Fernet:
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM,
        dklen=32,
    )
    return Fernet(base64.urlsafe_b64encode(key))


def _message_cipher(
    private_key: X25519PrivateKey, public_key: X25519PublicKey
) -> Fernet:
    """Derives the key of one message from an X25519 key exchange."""
    shared_secret = private_key.exchange(public_key)
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"openrecall-v2"
    ).derive(shared_secret)
    return Fernet(base64.urlsafe_b64encode(key))


def _read_auth() -> dict:
    with open(auth_path, encoding="utf-8") as f:
        return json.load(f)


def is_set_up() -> bool:
    return os.path.exists(auth_path)


def set_up(password: str) -> None:
    """Creates the key pair and stores it in auth.json behind the password.

    Args:
        password: The password that will be needed to view the history.

    Raises:
        ValueError: If the password is too short.
        FileExistsError: If a password was already chosen.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"The password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    private_key = X25519PrivateKey.generate()
    salt = secrets.token_bytes(SALT_SIZE)
    cipher = _password_cipher(password, salt)
    auth = {
        "salt": salt.hex(),
        "public_key": private_key.public_key().public_bytes_raw().hex(),
        "private_key": cipher.encrypt(private_key.private_bytes_raw()).decode("ascii"),
    }
    # "x" refuses to overwrite: replacing the keys would make the history unreadable
    with open(auth_path, "x", encoding="utf-8") as f:
        json.dump(auth, f)


def unlock(password: str) -> bool:
    """Decrypts the private key with the password and keeps it in memory.

    Returns:
        bool: False if the password is wrong.
    """
    global _private_key
    auth = _read_auth()
    cipher = _password_cipher(password, bytes.fromhex(auth["salt"]))
    try:
        private_bytes = cipher.decrypt(auth["private_key"].encode("ascii"))
    except InvalidToken:
        return False
    _private_key = X25519PrivateKey.from_private_bytes(private_bytes)
    return True


def lock() -> None:
    """Forgets the private key, so nothing can be decrypted until the next unlock."""
    global _private_key
    _private_key = None


def is_unlocked() -> bool:
    return _private_key is not None


def _get_public_key() -> X25519PublicKey:
    global _public_key
    if _public_key is None:
        _public_key = X25519PublicKey.from_public_bytes(
            bytes.fromhex(_read_auth()["public_key"])
        )
    return _public_key


def encrypt(data: bytes) -> bytes:
    """Encrypts data so that only the holder of the private key can read it.

    A fresh key pair per message means the stored public key alone is
    enough to encrypt, but never to decrypt.
    """
    ephemeral_key = X25519PrivateKey.generate()
    token = _message_cipher(ephemeral_key, _get_public_key()).encrypt(data)
    return MAGIC + ephemeral_key.public_key().public_bytes_raw() + token


def decrypt(data: bytes) -> bytes:
    """Decrypts data from encrypt().

    Raises:
        VaultLocked: If the password has not been entered.
        InvalidToken: If the data was encrypted with other keys, e.g. after
            auth.json was deleted and a new password was chosen, or by a
            version of OpenRecall from before the recording/viewing split.
    """
    if _private_key is None:
        raise VaultLocked("Enter the password to view recorded data.")
    if not data.startswith(MAGIC):
        raise InvalidToken
    body = data[len(MAGIC) :]
    ephemeral_key = X25519PublicKey.from_public_bytes(body[:PUBLIC_KEY_SIZE])
    return _message_cipher(_private_key, ephemeral_key).decrypt(body[PUBLIC_KEY_SIZE:])
