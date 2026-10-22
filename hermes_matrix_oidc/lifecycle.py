"""Apply refresh-token rotation transactionally to a profile-scoped store."""

from __future__ import annotations

from collections.abc import Mapping

from .credentials import CredentialBundle, CredentialStore
from .oauth import FormPoster, refresh_bundle


class SyncAuthRetryBudget:
    """Permit one refreshed-token retry per successful sync response."""

    def __init__(self) -> None:
        self._used = False

    def take(self) -> bool:
        if self._used:
            return False
        self._used = True
        return True

    def reset_after_success(self) -> None:
        self._used = False


class RefreshLifecycle:
    """Refresh one stored credential bundle and persist its replacement before use."""

    def __init__(self, store: CredentialStore, post_form: FormPoster) -> None:
        self._store = store
        self._post_form = post_form

    def refresh(self) -> CredentialBundle:
        current = self._store.load()
        if current is None:
            raise ValueError("No stored OAuth credential bundle")
        refreshed = refresh_bundle(current, self._post_form)
        self._store.save(refreshed)
        return refreshed
