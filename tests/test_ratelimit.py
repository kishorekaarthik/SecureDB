import pytest

from securedb.api.ratelimit import FixedWindowRateLimiter
from securedb.errors import RateLimited


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_allows_up_to_the_limit_then_rejects_with_retry_after() -> None:
    clock = FakeClock()
    limiter = FixedWindowRateLimiter(limit=3, window_seconds=60, clock=clock)
    for _ in range(3):
        limiter.hit("key-a")
    clock.now += 15
    with pytest.raises(RateLimited) as exc_info:
        limiter.hit("key-a")
    assert exc_info.value.headers["Retry-After"] == str(60 - (1000 + 15) % 60)


def test_limits_are_per_key() -> None:
    limiter = FixedWindowRateLimiter(limit=1, window_seconds=60, clock=FakeClock())
    limiter.hit("key-a")
    limiter.hit("key-b")
    with pytest.raises(RateLimited):
        limiter.hit("key-a")


def test_new_window_resets_the_count() -> None:
    clock = FakeClock()
    limiter = FixedWindowRateLimiter(limit=1, window_seconds=60, clock=clock)
    limiter.hit("key-a")
    clock.now += 60
    limiter.hit("key-a")


def test_limit_must_be_positive() -> None:
    with pytest.raises(ValueError):
        FixedWindowRateLimiter(limit=0)
