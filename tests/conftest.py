"""Fixtures that apply to every test automatically."""

import pytest

import cache


@pytest.fixture(autouse=True)
def fake_api_keys(monkeypatch):
    """Use fake keys so a real key from .env is never sent anywhere."""
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuseipdb-key")


@pytest.fixture(autouse=True)
def temp_cache_path(tmp_path, monkeypatch):
    """Point the default cache at a throwaway file, never the real one."""
    path = tmp_path / "test_cache.sqlite3"
    monkeypatch.setattr(cache, "DEFAULT_CACHE_PATH", path)
    return path
