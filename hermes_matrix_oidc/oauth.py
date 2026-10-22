"""OAuth refresh-token exchange with fail-closed token rotation."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from .credentials import CredentialBundle


FormPoster = Callable[[str, Mapping[str, str]], Mapping[str, object]]


def refresh_bundle(current: CredentialBundle, post_form: FormPoster) -> CredentialBundle:
    """Exchange a refresh token and require both replacement credentials in response."""

    response = post_form(
        current.token_endpoint,
        {
            "grant_type": "refresh_token",
            "client_id": current.client_id,
            "refresh_token": current.refresh_token,
        },
    )
    access_token = response.get("access_token")
    refresh_token = response.get("refresh_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise ValueError("OAuth token response omitted access_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise ValueError("OAuth token response omitted refresh_token")
    return CredentialBundle(
        client_id=current.client_id,
        refresh_token=refresh_token,
        access_token=access_token,
        token_endpoint=current.token_endpoint,
    )
