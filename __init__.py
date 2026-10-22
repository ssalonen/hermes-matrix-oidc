"""Hermes plugin entry point."""

from .hermes_matrix_oidc.adapter import register

__all__ = ["register"]
