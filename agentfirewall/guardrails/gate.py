"""Check-before-act precondition gate (runtime guardrail).

`PreconditionGate` is the fix for the check-*after*-act authorization bug — the
Bolt.new refresh exploit, where the agent ran before the credit check and a page
refresh replayed the queued prompt. The gate:

1. **replay-protects** by an idempotency key — a retried/refreshed request with the
   same key returns the stored result instead of running (and charging) again;
2. **authorizes and atomically reserves quota BEFORE** the agent action runs, so a
   zero-quota user can never get the action to execute;
3. **refunds** the reservation if the action itself fails.

The bundled stores are single-process references; back them with Redis/a database
in production. The *contract* (atomic ``try_consume``, idempotent replay) is what
matters.
"""
from __future__ import annotations

import functools
import threading
from typing import Any, Callable, Optional

from .scope import GuardrailBlocked

_MISS = object()


class QuotaExceeded(GuardrailBlocked):
    """Raised when a user has insufficient quota for an action."""


class InMemoryQuota:
    """Reference, thread-safe, single-process quota store."""

    def __init__(self, default: int = 0, balances: Optional[dict[str, int]] = None):
        self._default = default
        self._bal: dict[str, int] = dict(balances or {})
        self._lock = threading.Lock()

    def set(self, user_id: str, amount: int) -> None:
        with self._lock:
            self._bal[user_id] = amount

    def balance(self, user_id: str) -> int:
        with self._lock:
            return self._bal.get(user_id, self._default)

    def try_consume(self, user_id: str, cost: int = 1) -> bool:
        """Atomically deduct ``cost`` if available. Returns True on success."""
        with self._lock:
            bal = self._bal.get(user_id, self._default)
            if bal < cost:
                return False
            self._bal[user_id] = bal - cost
            return True

    def refund(self, user_id: str, cost: int = 1) -> None:
        with self._lock:
            self._bal[user_id] = self._bal.get(user_id, self._default) + cost


class InMemoryIdempotencyStore:
    """Reference, thread-safe idempotency-key → result store."""

    def __init__(self) -> None:
        self._d: dict[str, Any] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any:
        with self._lock:
            return self._d.get(key, _MISS)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._d[key] = value


class PreconditionGate:
    """Authorize + reserve quota before an action, idempotent by request key."""

    def __init__(self, quota: InMemoryQuota,
                 idempotency: Optional[InMemoryIdempotencyStore] = None):
        self.quota = quota
        self.idem = idempotency or InMemoryIdempotencyStore()
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def _key_lock(self, key: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = self._locks[key] = threading.Lock()
            return lock

    def run(self, user_id: str, action: Callable[[], Any], *, cost: int = 1,
            idempotency_key: Optional[str] = None) -> Any:
        """Run ``action`` only if ``user_id`` has quota; charge before running.

        Raises :class:`QuotaExceeded` (never invoking ``action``) if the user
        can't afford it. With an ``idempotency_key``, a replay returns the stored
        result without re-running or re-charging.
        """
        if idempotency_key is None:
            return self._reserve_and_run(user_id, action, cost)

        # Serialize same-key requests so a concurrent/refresh replay sees the cache.
        with self._key_lock(idempotency_key):
            cached = self.idem.get(idempotency_key)
            if cached is not _MISS:
                return cached
            result = self._reserve_and_run(user_id, action, cost)
            self.idem.set(idempotency_key, result)
            return result

    def _reserve_and_run(self, user_id: str, action: Callable[[], Any], cost: int) -> Any:
        if not self.quota.try_consume(user_id, cost):
            raise QuotaExceeded(
                f"user {user_id!r} is out of quota (needs {cost}, "
                f"has {self.quota.balance(user_id)})")
        try:
            return action()
        except Exception:
            self.quota.refund(user_id, cost)  # don't charge for a failed action
            raise

    def guard(self, *, cost: int = 1):
        """Decorator form. The wrapped fn must be called with ``user_id`` (and
        optionally ``idempotency_key``) as keyword arguments."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(fn)
            def wrapper(*args: Any, user_id: str,
                        idempotency_key: Optional[str] = None, **kwargs: Any) -> Any:
                return self.run(user_id, lambda: fn(*args, **kwargs),
                                cost=cost, idempotency_key=idempotency_key)
            return wrapper
        return decorator
