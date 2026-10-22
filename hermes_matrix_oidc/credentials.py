"""Profile-scoped persistence for OAuth credential rotation."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class CredentialBundle:
    """The complete token state needed for one public OAuth client."""

    client_id: str
    refresh_token: str
    access_token: str
    token_endpoint: str

    def __post_init__(self) -> None:
        if not self.client_id.strip():
            raise ValueError("client_id is required")
        if not self.refresh_token.strip():
            raise ValueError("refresh_token is required")
        if not self.access_token.strip():
            raise ValueError("access_token is required")
        if not self.token_endpoint.startswith(("https://", "http://")):
            raise ValueError("token_endpoint must be an HTTP(S) URL")


class CredentialStore:
    """Atomically replace token pairs so a crash cannot retain a stale refresh token."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> CredentialBundle | None:
        if not self.path.exists():
            return None
        with self.path.open("r", encoding="utf-8") as handle:
            return CredentialBundle(**json.load(handle))

    def save(self, bundle: CredentialBundle) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(asdict(bundle), sort_keys=True) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent, text=True
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
