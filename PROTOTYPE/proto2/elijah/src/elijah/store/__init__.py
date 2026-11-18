"""Evidence-store interfaces and the Phase 1 local implementation."""

from elijah.store.base import EvidenceStore
from elijah.store.local import LocalStore

__all__ = ["EvidenceStore", "LocalStore"]
