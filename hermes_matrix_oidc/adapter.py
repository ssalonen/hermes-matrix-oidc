"""Hermes platform override that refreshes Matrix OAuth access tokens."""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.parse
import urllib.request
from collections.abc import Mapping
from types import SimpleNamespace

# These modules are provided by the Hermes host, not installed with this plugin.
from gateway.platforms._shared import get_scoped_secret  # ty: ignore[unresolved-import]
from hermes_constants import get_hermes_home  # ty: ignore[unresolved-import]
from plugins.platforms.matrix import adapter as upstream  # ty: ignore[unresolved-import]

from .credentials import CredentialBundle, CredentialStore
from .lifecycle import RefreshLifecycle, SyncAuthRetryBudget

logger = logging.getLogger("hermes_matrix_oidc")


def _credential_store() -> CredentialStore:
    return CredentialStore(get_hermes_home() / "platforms" / "matrix-oidc" / "credentials.json")


def _post_form(url: str, form: Mapping[str, str]) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(form).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        # Invalid endpoint data retains the same validation error as other bad responses.
        raise ValueError("OAuth token endpoint returned a non-object response")  # noqa: TRY004
    return payload


def _seed_bundle(access_token: str) -> CredentialBundle | None:
    client_id = get_scoped_secret("MATRIX_OIDC_CLIENT_ID", "").strip()
    refresh_token = get_scoped_secret("MATRIX_OIDC_REFRESH_TOKEN", "").strip()
    token_endpoint = get_scoped_secret("MATRIX_OIDC_TOKEN_ENDPOINT", "").strip()
    if not any((client_id, refresh_token, token_endpoint)):
        return None
    if not all((client_id, refresh_token, token_endpoint, access_token)):
        raise ValueError("Matrix OIDC bootstrap requires client ID, refresh token, token endpoint, and access token")
    return CredentialBundle(
        client_id=client_id,
        refresh_token=refresh_token,
        access_token=access_token,
        token_endpoint=token_endpoint,
    )


def _is_auth_error(exc: BaseException) -> bool:
    errcode = getattr(exc, "errcode", None)
    if isinstance(errcode, str) and errcode.strip().lower() in {"m_unknown_token", "m_missing_token", "m_forbidden"}:
        return True
    return getattr(exc, "http_status", None) in {401, 403}


def _refresh_stored_access_token(access_token: str) -> str:
    store = _credential_store()
    with store.locked():
        if store.load() is None:
            seeded = _seed_bundle(access_token)
            if seeded is None:
                raise ValueError("No Matrix OIDC credential bundle is configured")
            store.save(seeded)
    return RefreshLifecycle(store, _post_form).refresh().access_token


async def _standalone_send(pconfig, chat_id, message, *, thread_id=None, media_files=None, force_document=False):
    """Refresh stored OAuth credentials before the bundled cron-delivery sender runs."""
    try:
        token = await asyncio.to_thread(
            _refresh_stored_access_token,
            getattr(pconfig, "token", "") or get_scoped_secret("MATRIX_ACCESS_TOKEN", ""),
        )
    except Exception as exc:  # noqa: BLE001 - Convert any refresh failure to a delivery error.
        return upstream.send_error(f"Matrix OAuth refresh for standalone delivery failed: {exc}")
    return await upstream._standalone_send(
        SimpleNamespace(token=token, extra=getattr(pconfig, "extra", {}) or {}),
        chat_id,
        message,
        thread_id=thread_id,
        media_files=media_files,
        force_document=force_document,
    )


class OIDCMatrixAdapter(upstream.MatrixAdapter):
    """The bundled Matrix adapter plus profile-scoped OAuth refresh-token rotation."""

    def _refresh_access_token(self) -> str:
        token = _refresh_stored_access_token(self._access_token)
        self._access_token = token
        return token

    async def _refresh_access_token_async(self) -> str:
        return await asyncio.to_thread(self._refresh_access_token)

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        try:
            await self._refresh_access_token_async()
        except Exception as exc:  # noqa: BLE001 - Any refresh failure must prevent connecting.
            logger.error("Matrix OAuth refresh before connect failed: %s", exc)
            return False
        return await super().connect(is_reconnect=is_reconnect)

    async def _sync_loop(self) -> None:
        client = self._client
        next_batch = await client.sync_store.get_next_batch()
        auth_retry = SyncAuthRetryBudget()
        while not self._closing:
            try:
                sync_data = await asyncio.wait_for(client.sync(since=next_batch, timeout=30000), timeout=45.0)
                if isinstance(sync_data, dict):
                    next_batch = await self._absorb_sync(client, sync_data) or next_batch
                    auth_retry.reset_after_success()
                    await asyncio.sleep(0)
            except asyncio.CancelledError:
                return
            except Exception as exc:  # noqa: BLE001 - Keep sync recovery for arbitrary client errors.
                if self._closing:
                    return
                if _is_auth_error(exc):
                    if not auth_retry.take():
                        logger.error("Matrix OAuth refreshed token was rejected; stopping sync to avoid credential churn")
                        return
                    while not self._closing:
                        try:
                            token = await self._refresh_access_token_async()
                            client.api.token = token
                            logger.info("Matrix OAuth access token refreshed after sync authentication failure")
                            break
                        except asyncio.CancelledError:
                            return
                        except Exception as refresh_exc:  # noqa: BLE001 - Retry any refresh failure until closed.
                            logger.warning("Matrix OAuth refresh failed; retrying in 5s: %s", refresh_exc)
                            await asyncio.sleep(5)
                    continue
                logger.warning("Matrix: sync error: %s — retrying in 5s", exc)
                await asyncio.sleep(5)


def register(ctx) -> None:
    """Replace the bundled Matrix registration without copying its adapter."""
    ctx.register_platform(
        name="matrix",
        label="Matrix",
        adapter_factory=OIDCMatrixAdapter,
        check_fn=upstream.matrix_deps_present,
        ensure_deps_fn=upstream.ensure_matrix_deps,
        is_connected=upstream._is_connected,
        required_env=["MATRIX_HOMESERVER", "MATRIX_ACCESS_TOKEN"],
        install_hint="pip install 'mautrix[encryption]'",
        setup_fn=upstream.interactive_setup,
        apply_yaml_config_fn=upstream._apply_yaml_config,
        allowed_users_env="MATRIX_ALLOWED_USERS",
        allow_all_env="MATRIX_ALLOW_ALL_USERS",
        cron_deliver_env_var="MATRIX_HOME_ROOM",
        standalone_sender_fn=_standalone_send,
        max_message_length=upstream.DEFAULT_MAX_MESSAGE_LENGTH,
        emoji="🔐",
        allow_update_command=True,
    )
