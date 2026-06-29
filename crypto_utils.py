"""
crypto_utils.py
Shared helper functions for digital signatures (non-repudiation).

Used by:
- main.py        -> signs outgoing messages with the sender's PRIVATE key
- server_tls.py   -> verifies incoming messages with the sender's PUBLIC key
"""

import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def load_private_key(username):
    with open(f"{username}_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(username):
    with open(f"{username}_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_message(username, message: str) -> str:
    """Returns a base64-encoded RSA-PSS signature of the message."""
    private_key = load_private_key(username)
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_message(username, message: str, signature_b64: str) -> bool:
    """Returns True if the signature is valid for this message and user."""
    try:
        public_key = load_public_key(username)
        public_key.verify(
            base64.b64decode(signature_b64),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, FileNotFoundError, ValueError):
        return False
