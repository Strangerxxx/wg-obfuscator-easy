"""Tests for MTU computation and its use in generated configs."""

import pytest

from app.clients.manager import ClientManager
from app.obfuscator.config import ObfuscatorConfigGenerator
from app.services import ServiceManager
from app.wireguard.config import WireGuardConfigGenerator
from app.wireguard.mtu import get_effective_server_mtu, get_effective_client_mtu


@pytest.mark.parametrize("config, expected", [
    ({"obfuscation": False, "masking_type": "STUN", "masking_forced": True}, 1420),
    ({"obfuscation": True, "masking_type": "NONE", "masking_forced": True}, 1420),
    ({"obfuscation": True, "masking_type": "STUN", "masking_forced": True}, 1396),
    ({"obfuscation": True, "masking_type": "NONE", "masking_forced": False}, 1396),
    ({"obfuscation": True, "masking_type": "STUN", "masking_forced": False}, 1396),
    ({"obfuscation": True, "masking_type": "STUN", "masking_forced": True, "mtu": 1300}, 1300),
    ({"obfuscation": False, "mtu": None}, 1420),
])
def test_effective_server_mtu(config, expected):
    assert get_effective_server_mtu(config) == expected


def test_direct_client_mtu_ignores_masking():
    config = {"obfuscation": True, "masking_type": "STUN", "masking_forced": True}
    assert get_effective_client_mtu(config, {}, obfuscation=False) == 1420


def test_direct_client_mtu_stored():
    config = {"client_mtu_direct": 1380, "client_mtu_obfuscated": 1300}
    assert get_effective_client_mtu(config, {}, obfuscation=False) == 1380


@pytest.mark.parametrize("masking_type, expected", [("NONE", 1420), ("STUN", 1396)])
def test_obfuscated_client_mtu_default_masking(masking_type, expected):
    config = {"masking_type": masking_type, "masking_forced": False}
    assert get_effective_client_mtu(config, {}, obfuscation=True) == expected


@pytest.mark.parametrize("masking_type, override, expected", [
    ("NONE", "STUN", 1396),
    ("STUN", "NONE", 1420),
])
def test_obfuscated_client_mtu_follows_override(masking_type, override, expected):
    config = {"masking_type": masking_type, "masking_forced": False}
    client = {"masking_type_override": override}
    assert get_effective_client_mtu(config, client, obfuscation=True) == expected


def test_obfuscated_client_mtu_forced_masking_ignores_override():
    config = {"masking_type": "NONE", "masking_forced": True}
    client = {"masking_type_override": "STUN"}
    assert get_effective_client_mtu(config, client, obfuscation=True) == 1420


def test_obfuscated_client_mtu_stored():
    config = {"masking_type": "STUN", "client_mtu_obfuscated": 1350, "client_mtu_direct": 1300}
    assert get_effective_client_mtu(config, {}, obfuscation=True) == 1350


MAIN_CONFIG = {
    "server_private_key": "SERVER_PRIV",
    "server_public_key": "SERVER_PUB",
    "subnet": "10.6.13",
    "own_ip": 1,
    "wg_interface": "wg0",
    "wan_interface": "eth0",
    "enabled": True,
    "obfuscation": True,
    "obfuscation_key": "k",
    "masking_type": "NONE",
    "masking_forced": False,
}

CLIENT = {
    "ip": 2,
    "private_key": "PRIV",
    "public_key": "PUB",
    "allowed_ips": ["0.0.0.0/0"],
    "keep_server_in_allowed_ips": True,
    "obfuscator_port": 13255,
    "masking_type_override": "STUN",
    "enabled": True,
}


class FakeConfigManager:
    def __init__(self, main):
        self.main = main
        self.clients = {"alice": dict(CLIENT)}

    def has_client(self, username):
        return username in self.clients

    def get_client(self, username):
        return dict(self.clients[username])


def test_client_wg_config_mtu_per_connection_type():
    manager = ClientManager(FakeConfigManager(dict(MAIN_CONFIG)), None, None)
    obfuscated = manager.get_client_wg_config("alice", "vpn.example.com", 51820)
    direct = manager.get_client_wg_config("alice", "vpn.example.com", 51820, direct=True)
    assert "\nMTU = 1396\n" in obfuscated
    assert "\nMTU = 1420\n" in direct


def test_generate_configs_writes_server_mtu(monkeypatch):
    saved = {}
    monkeypatch.setattr(
        WireGuardConfigGenerator, "save_config_file",
        staticmethod(lambda content, interface: saved.setdefault("wg", content)),
    )
    monkeypatch.setattr(ObfuscatorConfigGenerator, "save_config_file", staticmethod(lambda content: None))
    config_manager = FakeConfigManager(dict(MAIN_CONFIG, mtu=1350))
    ServiceManager(config_manager, None, None, None, "1.2.3.4", 51820).generate_configs()
    assert "\nMTU = 1350\n" in saved["wg"]
