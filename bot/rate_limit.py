"""Per-user rate limiting using in-memory sliding window."""
from __future__ import annotations

import time
from collections import defaultdict, deque

import config


class RateLimiter:
    """Thread-safe sliding-window rate limiter for Telegram users."""

    def __init__(self, max_requests: int = config.MAX_SCANS_PER_USER_PER_HOUR, window_seconds: int = 3600):
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: dict[int, deque] = defaultdict(deque)
        self._active_scans: set[int] = set()

    def is_allowed(self, user_id: int) -> tuple[bool, int]:
        """
        Check if the user is allowed to start a new scan.
        Returns (allowed, seconds_until_reset).
        """
        now = time.monotonic()
        window = self._timestamps[user_id]

        # Remove old timestamps outside the window
        while window and window[0] < now - self._window:
            window.popleft()

        if len(window) >= self._max:
            oldest = window[0]
            reset_in = int(oldest + self._window - now) + 1
            return False, reset_in

        return True, 0

    def record(self, user_id: int) -> None:
        """Record a scan start for this user."""
        self._timestamps[user_id].append(time.monotonic())

    def mark_active(self, user_id: int) -> bool:
        """Mark user as having an active scan. Returns False if already active."""
        if user_id in self._active_scans:
            return False
        self._active_scans.add(user_id)
        return True

    def mark_done(self, user_id: int) -> None:
        """Remove active scan marker for user."""
        self._active_scans.discard(user_id)

    def is_active(self, user_id: int) -> bool:
        return user_id in self._active_scans

    def remaining(self, user_id: int) -> int:
        """How many scans remain in the current window."""
        now = time.monotonic()
        window = self._timestamps[user_id]
        while window and window[0] < now - self._window:
            window.popleft()
        return max(0, self._max - len(window))


# Global singleton
rate_limiter = RateLimiter()
