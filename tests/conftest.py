# Shared pytest fixtures.
import pytest
from fastapi.testclient import TestClient

from app.main import app


class FakeRedis:
    # Minimal in-memory Redis replacement for API tests.
    def __init__(self):
        self.store = {}
        self.lists = {}

    def setex(self, key, ttl, value):
        self.store[key] = value

    def get(self, key):
        return self.store.get(key)

    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def ltrim(self, key, start, stop):
        if key in self.lists:
            self.lists[key] = self.lists[key][start:stop + 1]

    def lrange(self, key, start, stop):
        return self.lists.get(key, [])[start:stop + 1]

    def expire(self, key, ttl):
        return True

    def incr(self, key):
        n = int(self.store.get(key, 0)) + 1
        self.store[key] = n
        return n

    def delete(self, key):
        self.store.pop(key, None)
        self.lists.pop(key, None)
        return 1

    def set(self, key, value, ex=None):
        self.store[key] = value
        return True

    def exists(self, key):
        return 1 if (key in self.store or key in self.lists) else 0

    def ping(self):
        return True


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def fake_redis():
    return FakeRedis()
