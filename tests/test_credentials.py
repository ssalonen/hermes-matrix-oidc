import json
import tempfile
import unittest
from pathlib import Path

from hermes_matrix_oidc.credentials import CredentialBundle, CredentialStore


class CredentialStoreTest(unittest.TestCase):
    def test_persists_rotated_access_and_refresh_tokens_as_one_bundle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CredentialStore(Path(tmpdir) / "credentials.json")
            initial = CredentialBundle(
                client_id="public-client",
                refresh_token="first-refresh",
                access_token="first-access",
                token_endpoint="https://auth.example.test/token",
            )
            rotated = CredentialBundle(
                client_id="public-client",
                refresh_token="second-refresh",
                access_token="second-access",
                token_endpoint="https://auth.example.test/token",
            )

            store.save(initial)
            store.save(rotated)

            self.assertEqual(store.load(), rotated)
            raw = json.loads(store.path.read_text(encoding="utf-8"))
            self.assertEqual(raw["access_token"], "second-access")
            self.assertEqual(raw["refresh_token"], "second-refresh")

    def test_rejects_incomplete_credentials(self):
        with self.assertRaises(ValueError):
            CredentialBundle(
                client_id="public-client",
                refresh_token="",
                access_token="access",
                token_endpoint="https://auth.example.test/token",
            )


if __name__ == "__main__":
    unittest.main()
