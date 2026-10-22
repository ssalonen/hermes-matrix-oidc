# Hermes Matrix OAuth Refresh

A generic, no-fork Hermes platform plugin for Matrix homeservers that use
OAuth 2.0 delegated authentication with short-lived access tokens.

The plugin replaces only the `matrix` platform registration. It subclasses the
bundled Matrix adapter, refreshes its access token before connecting, and
retries a sync once after a structured Matrix authentication failure. Token
rotation is stored atomically in the active profile under
`platforms/matrix-oidc/credentials.json` with owner-only permissions.

## Background

This plugin is an independently maintained, no-fork implementation informed by
[Hermes PR #94096](https://github.com/NousResearch/hermes-agent/pull/94096),
which explored Matrix Authentication Service/OAuth refresh-token support but
was closed without merging. It intentionally keeps the scope to delegated OAuth
credential lifecycle rather than copying or modifying the bundled Matrix
adapter.

## Requirements

- Hermes with the Matrix platform extra and, for encrypted rooms, its E2EE
  dependencies installed.
- A Matrix homeserver that supports refresh tokens for a public OAuth client.
- A public OAuth client ID, refresh token, token endpoint, and an initial
  Matrix access token for one-time bootstrap.

## Install

```bash
hermes plugins install ssalonen/hermes-matrix-oidc
```

Configure the ordinary Matrix gateway settings through `hermes gateway setup`.
For the first OAuth bootstrap, provide these profile-scoped secrets through the
normal Hermes secret/configuration flow:

```text
MATRIX_OIDC_CLIENT_ID
MATRIX_OIDC_REFRESH_TOKEN
MATRIX_OIDC_TOKEN_ENDPOINT
```

The plugin uses the existing `MATRIX_ACCESS_TOKEN` only to establish the first
stored credential bundle. Thereafter each successful refresh rotates the access
and refresh tokens together in the profile-scoped store. Do not place OAuth
secrets in `config.yaml`.

## Safety and compatibility

- The plugin does not patch or fork the Hermes checkout.
- It fails closed if refresh token rotation is unavailable or incomplete.
- It does not copy the bundled Matrix adapter; the override is limited to
  OAuth credential lifecycle and its sync authentication-recovery path.
- Keep E2EE device state stable: request the OAuth Matrix device scope for the
  same device ID that the gateway uses.

## Development

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH="$HOME/.hermes/hermes-agent:$PWD" \
  python3 -c 'from hermes_matrix_oidc.adapter import OIDCMatrixAdapter'
hermes plugins validate .
```

The test suite covers credential validation, atomic replacement, required
refresh-token rotation, and use of the newest rotated refresh token on the next
exchange.
