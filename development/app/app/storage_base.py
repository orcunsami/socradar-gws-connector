"""Backend-agnostic storage exceptions (shared by sqlite + firestore backends and the db facade)."""
from __future__ import annotations


class DuplicateTenantError(Exception):
    """Raised when creating a tenant whose customer_id already exists (any backend)."""
