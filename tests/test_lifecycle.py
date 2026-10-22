import tempfile
import unittest
from pathlib import Path

from hermes_matrix_oidc.credentials import CredentialBundle, CredentialStore
from hermes_matrix_oidc.lifecycle import RefreshLifecycle


class RefreshLifecycleTest(unittest.TestCase):
    def test_uses_rotated_bundle_for_next_refresh(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CredentialStore(Path(tmpdir) / "credentials.json")
            store.save(CredentialBundle(
                client_id="public-client",
                refresh_token="first-refresh",
                access_token="expired-access",
                token_endpoint="https://auth.example.test/token",
            ))
            requests = []

            def post_form(_url, form):
                requests.append(form.copy())
                return {
                    "access_token": f"access-{len(requests)}",
                    "refresh_token": f"refresh-{len(requests)}",
                }

            lifecycle = RefreshLifecycle(store, post_form)
            self.assertEqual(lifecycle.refresh().access_token, "access-1")
            self.assertEqual(lifecycle.refresh().access_token, "access-2")
            self.assertEqual(requests[1]["refresh_token"], "refresh-1")


if __name__ == "__main__":
    unittest.main()
