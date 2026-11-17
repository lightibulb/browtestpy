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

    def ping(self):
        return True


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def fake_redis():
    return FakeRedis()
