"""Per-system secrets: the session secret and, for the Bloom filter system, the Bloom key."""
import base64
import json
import os
from pathlib import Path


class Keys:
    """Generated on first run. Anyone holding the Bloom key can test guesses against the
    Bloom filters, so it has to be kept as secret as a password database."""

    def __init__(self, session_secret: str, bloom_key: bytes):
        self.session_secret, self.bloom_key = session_secret, bloom_key

    @classmethod
    def load_or_create(cls, path: Path) -> "Keys":
        if path.exists():
            raw = json.loads(path.read_text())
        else:
            raw = {
                "session_secret": base64.b64encode(os.urandom(32)).decode(),
                "bloom_key": base64.b64encode(os.urandom(32)).decode(),
            }
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(raw, indent=2))
            try:
                path.chmod(0o600)
            except OSError:
                pass
        return cls(raw["session_secret"], base64.b64decode(raw["bloom_key"]))
