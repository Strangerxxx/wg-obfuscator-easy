"""Tests for WireGuard and obfuscator config generators."""

from app.wireguard.config import WireGuardConfigGenerator
from app.obfuscator.config import ObfuscatorConfigGenerator


BASE_CONFIG = {
    "server_private_key": "SERVER_PRIV",
    "server_public_key": "SERVER_PUB",
    "subnet": "10.6.13",
    "own_ip": 1,
    "wg_interface": "wg0",
    "wan_interface": "eth0",
}


def test_server_config_skips_disabled_clients():
    clients = {
        "alice": {"ip": 2, "public_key": "PUB_A", "enabled": True},
        "bob": {"ip": 3, "public_key": "PUB_B", "enabled": False},
    }
    out = WireGuardConfigGenerator.generate_server_config(
        BASE_CONFIG, clients, external_port=51820, obfuscation=False, mtu=1420, hooks={}
    )
    assert "PUB_A" in out
    assert "PUB_B" not in out
    assert "ListenPort = 51820" in out


def test_server_config_includes_preshared_key():
    clients = {
        "alice": {"ip": 2, "public_key": "PUB_A", "enabled": True, "preshared_key": "PSK"},
    }
    out = WireGuardConfigGenerator.generate_server_config(
        BASE_CONFIG, clients, external_port=51820, obfuscation=True, mtu=1420, hooks={}
    )
    assert "PresharedKey = PSK" in out


def test_server_config_sanitises_client_name_newline():
    clients = {
        "evil\n[Peer]\nPublicKey = attacker": {"ip": 2, "public_key": "PUB_A", "enabled": True},
    }
    out = WireGuardConfigGenerator.generate_server_config(
        BASE_CONFIG, clients, external_port=51820, obfuscation=False, mtu=1420, hooks={}
    )
    # The forged section must not appear on its own line.
    assert "\nPublicKey = attacker" not in out


def test_client_config_obfuscation_uses_localhost():
    client = {"ip": 2, "private_key": "PRIV", "obfuscator_port": 13255}
    out = WireGuardConfigGenerator.generate_client_config(
        BASE_CONFIG, client, "vpn.example.com", 51820,
        obfuscation=True, allowed_ips=["0.0.0.0/0"], mtu=1420,
    )
    assert "Endpoint = 127.0.0.1:13255" in out


def test_client_config_direct_uses_external_endpoint():
    client = {"ip": 2, "private_key": "PRIV"}
    out = WireGuardConfigGenerator.generate_client_config(
        BASE_CONFIG, client, "vpn.example.com", 51820,
        obfuscation=False, allowed_ips=["0.0.0.0/0"], mtu=1420,
    )
    assert "Endpoint = vpn.example.com:51820" in out


def test_obfuscator_client_config_target_and_key():
    client = {"obfuscator_port": 13255}
    out = ObfuscatorConfigGenerator.generate_client_config(
        client, "vpn.example.com", 51820, "SECRETKEY", "NONE", False, "INFO"
    )
    assert "target = vpn.example.com:51820" in out
    assert "key = SECRETKEY" in out


def test_server_config_writes_mtu():
    out = WireGuardConfigGenerator.generate_server_config(
        BASE_CONFIG, {}, external_port=51820, obfuscation=True, mtu=1396, hooks={}
    )
    assert "\nMTU = 1396\n" in out


def test_client_config_writes_mtu():
    client = {"ip": 2, "private_key": "PRIV"}
    out = WireGuardConfigGenerator.generate_client_config(
        BASE_CONFIG, client, "vpn.example.com", 51820,
        obfuscation=False, allowed_ips=["0.0.0.0/0"], mtu=1400,
    )
    assert "\nMTU = 1400\n" in out


HOOKS = {
    "pre_up": "echo pre-up %i",
    "post_up": "ip route add 192.168.88.0/24 dev %i",
    "pre_down": "echo pre-down %i",
    "post_down": "ip route del 192.168.88.0/24 dev %i",
}


def test_server_config_writes_custom_hooks_after_builtin_rules():
    clients = {"alice": {"ip": 2, "public_key": "PUB_A", "enabled": True}}
    out = WireGuardConfigGenerator.generate_server_config(
        BASE_CONFIG, clients, external_port=51820, obfuscation=False, mtu=1420, hooks=HOOKS
    )
    lines = out.split("\n")
    post_up = [line for line in lines if line.startswith("PostUp = ")]
    post_down = [line for line in lines if line.startswith("PostDown = ")]
    assert post_up[0].startswith("PostUp = iptables -A FORWARD -i wg0")
    assert post_up[1] == "PostUp = ip route add 192.168.88.0/24 dev %i"
    assert post_down[0].startswith("PostDown = iptables -D FORWARD -i wg0")
    assert post_down[1] == "PostDown = ip route del 192.168.88.0/24 dev %i"
    assert "PreUp = echo pre-up %i" in lines
    assert "PreDown = echo pre-down %i" in lines
    # Hooks belong to [Interface], before the first [Peer]
    assert lines.index("PostDown = ip route del 192.168.88.0/24 dev %i") < lines.index("[Peer]")


def test_server_config_omits_unset_hooks():
    hooks = {"pre_up": None, "post_up": "echo up", "pre_down": None, "post_down": None}
    out = WireGuardConfigGenerator.generate_server_config(
        BASE_CONFIG, {}, external_port=51820, obfuscation=False, mtu=1420, hooks=hooks
    )
    assert "PreUp" not in out
    assert "PreDown" not in out
    assert out.count("PostUp = ") == 2
    assert out.count("PostDown = ") == 1
