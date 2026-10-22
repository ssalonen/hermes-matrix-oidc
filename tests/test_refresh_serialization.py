import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from hermes_matrix_oidc.credentials import CredentialBundle, CredentialStore
from hermes_matrix_oidc.lifecycle import RefreshLifecycle


class RefreshSerializationTest(unittest.TestCase):
    def test_concurrent_refreshes_do_not_reuse_a_rotating_refresh_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CredentialStore(Path(tmpdir) / "credentials.json")
            store.save(CredentialBundle("client", "r0", "a0", "https://example.test/token"))
            used = []

            def post_form(_url, form):
                used.append(form["refresh_token"])
                time.sleep(0.02)
                return {
                    "access_token": f"a{len(used)}",
                    "refresh_token": f"r{len(used)}",
                }

            def refresh():
                return RefreshLifecycle(store, post_form).refresh().access_token

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _index: refresh(), range(2)))

            self.assertEqual(sorted(results), ["a1", "a2"])
            self.assertEqual(used, ["r0", "r1"])


if __name__ == "__main__":
    unittest.main()
