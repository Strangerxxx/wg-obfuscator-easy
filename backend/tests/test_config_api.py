"""Integration tests for the config API using mocked managers."""

import pytest

from tests.test_clients_api import AUTH, FakeTokenManager, FakeWG, FakeObf


class FakeConfigManager:
    def __init__(self):
        self.main = {
            "subnet": "10.6.13",
            "own_ip": 1,
            "obfuscation": True,
            "masking_type": "STUN",
            "masking_forced": False,
        }
        self.clients = {}

    def set(self, key, value, save=True):
        self.main[key] = value

    def save_config(self):
        pass


@pytest.fixture
def config_manager():
    return FakeConfigManager()


@pytest.fixture
def client(monkeypatch, config_manager):
    from app.api import create_app
    from app.api import config_routes

    monkeypatch.setattr(config_routes, "apply_config_changes", lambda app: None)
    app = create_app(
        config_manager, None, FakeWG(), FakeObf(),
        FakeTokenManager(), "vpn.example.com", 51820,
    )
    return app.test_client()


def test_get_config_mtu_defaults(client):
    body = client.get("/api/config", headers=AUTH).get_json()
    assert body["mtu"] is None
    assert body["mtu_effective"] == 1396
    assert body["client_mtu_direct"] is None
    assert body["client_mtu_direct_effective"] == 1420
    assert body["client_mtu_obfuscated"] is None
    assert body["client_mtu_obfuscated_effective"] == 1396


def test_patch_config_sets_and_clears_mtu(client, config_manager):
    resp = client.patch("/api/config", headers=AUTH, json={"mtu": 1400, "client_mtu_obfuscated": 1380})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["mtu"] == 1400
    assert body["mtu_effective"] == 1400
    assert body["client_mtu_obfuscated_effective"] == 1380

    resp = client.patch("/api/config", headers=AUTH, json={"mtu": None})
    assert resp.status_code == 200
    assert config_manager.main["mtu"] is None
    assert resp.get_json()["mtu_effective"] == 1396


@pytest.mark.parametrize("key", ["mtu", "client_mtu_direct", "client_mtu_obfuscated"])
@pytest.mark.parametrize("value", [True, "1400", 1400.0, 1279, 1501])
def test_patch_config_rejects_invalid_mtu(client, key, value):
    resp = client.patch("/api/config", headers=AUTH, json={key: value})
    assert resp.status_code == 400
    assert key in resp.get_json()["error"]


HOOK_KEYS = ["pre_up", "post_up", "pre_down", "post_down"]


def test_get_config_hooks_default_null(client):
    body = client.get("/api/config", headers=AUTH).get_json()
    for key in HOOK_KEYS:
        assert body[key] is None


def test_patch_config_sets_strips_and_clears_hooks(client, config_manager):
    resp = client.patch("/api/config", headers=AUTH, json={
        "post_up": "  ip route add 192.168.88.0/24 dev %i  ",
        "pre_down": "\techo down",
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["post_up"] == "ip route add 192.168.88.0/24 dev %i"
    assert body["pre_down"] == "echo down"
    assert body["pre_up"] is None
    assert config_manager.main["post_up"] == "ip route add 192.168.88.0/24 dev %i"

    resp = client.patch("/api/config", headers=AUTH, json={"post_up": None, "pre_down": "   "})
    assert resp.status_code == 200
    assert config_manager.main["post_up"] is None
    assert config_manager.main["pre_down"] is None


def test_patch_config_accepts_max_length_hook(client, config_manager):
    resp = client.patch("/api/config", headers=AUTH, json={"post_up": "x" * 2048})
    assert resp.status_code == 200
    assert config_manager.main["post_up"] == "x" * 2048


@pytest.mark.parametrize("key", HOOK_KEYS)
@pytest.mark.parametrize("value", [
    1, True, ["echo"], {"cmd": "echo"},
    "echo a\necho b", "echo a\recho b", "echo a\r\n[Peer]", "echo\n",
    "x" * 2049,
])
def test_patch_config_rejects_invalid_hook(client, config_manager, key, value):
    resp = client.patch("/api/config", headers=AUTH, json={key: value})
    assert resp.status_code == 400
    assert key in resp.get_json()["error"]
    assert key not in config_manager.main
