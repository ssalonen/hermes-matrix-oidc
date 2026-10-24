"""Hermes plugin entry point."""  # noqa: N999 - Hermes loads the hyphenated plugin directory.

# Hermes loads this entry point as a package under its own module name.
from .hermes_matrix_oidc.adapter import register  # ty: ignore[unresolved-import]

__all__ = ["register"]
