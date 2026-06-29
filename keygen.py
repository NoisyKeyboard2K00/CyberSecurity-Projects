"""
keygen.py
Run this ONCE before starting the server/client.
Generates an RSA keypair for Alice and Bob.

Private keys -> stay with the respective client only.
Public keys  -> copied to the server so it can verify signatures.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Save private key (KEEP SECRET - client side only)
    with open(f"{username}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key (safe to share - goes to server)
    with open(f"{username}_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Generated {username}_private.pem and {username}_public.pem")

if __name__ == "__main__":
    generate_keys("Alice")
    generate_keys("Bob")
    print("\nDone. Keep the *_private.pem files safe and never share them.")
