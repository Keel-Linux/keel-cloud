# Copyright (c) 2026 KeelLinux maintainers
"""A limit on failed authentications per client address

A key has 256 bits of entropy, so the limit is not what keeps a key from
being guessed; it keeps a client that keeps sending bad keys from costing
the service a database lookup each time. After `limit` failures within
`window` seconds a client is refused with 429 until the window passes.
"""

import time
from collections import deque


class FailureLimiter:
    def __init__(self, limit: int = 20, window: float = 60.0,
                 clock=time.monotonic, max_clients: int = 10000):
        self.limit = limit
        self.window = window
        self.clock = clock
        self.max_clients = max_clients
        self.failures: dict[str, deque] = {}

    def _recent(self, client: str) -> deque:
        times = self.failures.get(client)
        if times is None:
            return deque()
        cutoff = self.clock() - self.window
        while times and times[0] < cutoff:
            times.popleft()
        if not times:
            del self.failures[client]
        return times

    def blocked(self, client: str) -> bool:
        return len(self._recent(client)) >= self.limit

    def failed(self, client: str) -> None:
        if client not in self.failures and \
                len(self.failures) >= self.max_clients:
            for stale in list(self.failures):
                self._recent(stale)
            if len(self.failures) >= self.max_clients:
                self.failures.pop(next(iter(self.failures)))
        self.failures.setdefault(client, deque()).append(self.clock())
