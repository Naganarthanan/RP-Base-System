"""Key handling, payload encryption and block signing."""
import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode())


class Keys:
    """Ledger encryption key, block signing key and the session secret.

    Generated on first run. Losing this file makes every block unreadable, so it
    has to be backed up separately from the database.
    """

    def __init__(self, ledger_key: bytes, signing_key: Ed25519PrivateKey, session_secret: str):
        self.aead = AESGCM(ledger_key)
        self.signing_key = signing_key
        self.verify_key = signing_key.public_key()
        self.session_secret = session_secret

    @classmethod
    def load_or_create(cls, path: Path) -> "Keys":
        if path.exists():
            raw = json.loads(path.read_text())
        else:
            private = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            raw = {
                "ledger_key": _b64(AESGCM.generate_key(bit_length=256)),
                "signing_key": _b64(private),
                "session_secret": _b64(os.urandom(32)),
            }
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(raw, indent=2))
            try:
                path.chmod(0o600)
            except OSError:
                pass
        return cls(
            _unb64(raw["ledger_key"]),
            Ed25519PrivateKey.from_private_bytes(_unb64(raw["signing_key"])),
            raw["session_secret"],
        )

    def encrypt(self, payload: dict, aad: str) -> tuple[str, str]:
        nonce = os.urandom(12)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return _b64(nonce), _b64(self.aead.encrypt(nonce, body, aad.encode()))

    def decrypt(self, nonce: str, ciphertext: str, aad: str) -> dict:
        try:
            body = self.aead.decrypt(_unb64(nonce), _unb64(ciphertext), aad.encode())
        except InvalidTag as exc:
            raise ValueError("block payload failed authentication") from exc
        return json.loads(body)

    def sign(self, message: str) -> str:
        return _b64(self.signing_key.sign(message.encode()))

    def verify(self, signature: str, message: str) -> bool:
        try:
            self.verify_key.verify(_unb64(signature), message.encode())
            return True
        except (InvalidSignature, ValueError):
            return False
