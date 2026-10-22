import unittest

from hermes_matrix_oidc.credentials import CredentialBundle
from hermes_matrix_oidc.oauth import refresh_bundle


class RefreshBundleTest(unittest.TestCase):
    def test_refresh_replaces_both_rotated_tokens(self):
        previous = CredentialBundle(
            client_id="public-client",
            refresh_token="old-refresh",
            access_token="old-access",
            token_endpoint="https://auth.example.test/token",
        )
        calls = []

        def post_form(url, form):
            calls.append((url, form))
            return {"access_token": "new-access", "refresh_token": "new-refresh"}

        refreshed = refresh_bundle(previous, post_form)

        self.assertEqual(refreshed.access_token, "new-access")
        self.assertEqual(refreshed.refresh_token, "new-refresh")
        self.assertEqual(refreshed.client_id, previous.client_id)
        self.assertEqual(
            calls,
            [
                (
                    "https://auth.example.test/token",
                    {
                        "grant_type": "refresh_token",
                        "client_id": "public-client",
                        "refresh_token": "old-refresh",
                    },
                )
            ],
        )

    def test_rejects_a_refresh_response_that_omits_rotation_token(self):
        previous = CredentialBundle(
            client_id="public-client",
            refresh_token="old-refresh",
            access_token="old-access",
            token_endpoint="https://auth.example.test/token",
        )

        with self.assertRaisesRegex(ValueError, "refresh_token"):
            refresh_bundle(previous, lambda _url, _form: {"access_token": "new-access"})


if __name__ == "__main__":
    unittest.main()
