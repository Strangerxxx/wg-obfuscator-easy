"""
Copyright (C) 2025 Alexey Cluster <cluster@cluster.wtf>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""WireGuard MTU computation"""

from typing import Dict

from ..config.constants import DEFAULT_WG_MTU, DEFAULT_MASKING_TYPE, MASKING_OVERHEAD


def get_client_masking_type(config: Dict, client: Dict) -> str:
    """Return the masking type the client's obfuscator uses"""
    masking_type = config.get("masking_type", DEFAULT_MASKING_TYPE)
    if config.get("masking_forced", False):
        return masking_type
    override = client.get("masking_type_override")
    if override is None:
        return masking_type
    return override


def get_effective_server_mtu(config: Dict) -> int:
    """Return stored mtu, or the MTU that fits the server's masking settings"""
    mtu = config.get("mtu")
    if mtu is not None:
        return int(mtu)
    if not config.get("obfuscation", False):
        return DEFAULT_WG_MTU
    if config.get("masking_forced", False):
        return DEFAULT_WG_MTU - MASKING_OVERHEAD[config.get("masking_type", DEFAULT_MASKING_TYPE)]
    # Without forced masking the server obfuscator accepts any masking type
    return DEFAULT_WG_MTU - max(MASKING_OVERHEAD.values())


def get_effective_client_mtu(config: Dict, client: Dict, obfuscation: bool) -> int:
    """Return stored client MTU, or the MTU that fits the client's masking type"""
    if not obfuscation:
        mtu = config.get("client_mtu_direct")
        return DEFAULT_WG_MTU if mtu is None else int(mtu)
    mtu = config.get("client_mtu_obfuscated")
    if mtu is not None:
        return int(mtu)
    return DEFAULT_WG_MTU - MASKING_OVERHEAD[get_client_masking_type(config, client)]
