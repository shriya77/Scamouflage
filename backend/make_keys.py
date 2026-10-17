"""Generate the Ed25519 keypair that signs /api/blocklist (run once, on the VM):

    python -m backend.make_keys

Writes the PRIVATE key to keys/blocklist_ed25519.pem (chmod 600, git-ignored,
never share it) and prints the PUBLIC key in base64 for extension/config.js.
If the key already exists it is kept and its public key is printed again.

Options:
    --out PATH      where to write the private key
    --key-id ID     the key_id to show in the config snippet (default scamouflage-vm-1)
    --force         replace an existing key (every installed extension must then
                    get the new public key, or it will reject the list)
"""
import argparse
import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(REPO, "keys", "blocklist_ed25519.pem")


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    """The raw 32-byte public key, base64. This is the format tweetnacl wants."""
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def write_private_key(private_key: Ed25519PrivateKey, path: str) -> None:
    """Write the key so only the current user can read it (mode 600)."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))


def load_or_create(path: str, force: bool = False) -> tuple:
    """Return (private_key, created?)."""
    if os.path.exists(path) and not force:
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"{path} exists but is not an Ed25519 key")
        return key, False
    key = Ed25519PrivateKey.generate()
    write_private_key(key, path)
    return key, True


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default=DEFAULT_OUT)
    p.add_argument("--key-id", default="scamouflage-vm-1")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    key, created = load_or_create(args.out, args.force)
    print(("Created" if created else "Using existing") + f" private key: {args.out}")
    print()
    print("Public key (base64), safe to share:")
    print(f"  {public_key_b64(key)}")
    print()
    print("1) Put it in extension/config.js under LIVE_KEYS:")
    print(f"     '{args.key_id}': '{public_key_b64(key)}',")
    print("2) Tell the backend where the private key is before starting it:")
    print(f"     export TOLLTRAP_SIGNING_KEY={os.path.abspath(args.out)}")
    print(f"     export TOLLTRAP_KEY_ID={args.key_id}")


if __name__ == "__main__":
    main()
