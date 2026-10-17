"""Create the alert signing key (run once on the VM):

    python -m alerts.keygen

Writes keys/alert_ed25519.pem (PRIVATE, chmod 600, git-ignored, never share)
and data/alert_pubkey.pem (public, fine to share/serve from the API).
Refuses to overwrite an existing key unless you pass --force.
"""
import argparse
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from alerts.sign import KEY_PATH, PUB_PATH, key_id_of


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--force", action="store_true")
    args = p.parse_args()
    if os.path.exists(KEY_PATH) and not args.force:
        with open(KEY_PATH, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        print(f"key already exists: {KEY_PATH}  ({key_id_of(priv.public_key())})")
    else:
        priv = Ed25519PrivateKey.generate()
        os.makedirs(os.path.dirname(KEY_PATH), mode=0o700, exist_ok=True)
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(priv.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        print(f"created {KEY_PATH}  ({key_id_of(priv.public_key())})")
    os.makedirs(os.path.dirname(PUB_PATH), exist_ok=True)
    with open(PUB_PATH, "wb") as f:
        f.write(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"public key -> {PUB_PATH}")


if __name__ == "__main__":
    main()
