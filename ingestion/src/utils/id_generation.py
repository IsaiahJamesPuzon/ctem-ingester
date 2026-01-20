"""
ID generation utilities for deterministic asset IDs, exposure IDs, and unique event IDs.
"""

import hashlib
from typing import Optional
from uuid_utils import uuid7


def generate_asset_id(
    mac: Optional[str] = None,
    hostname: Optional[str] = None,
    ip: Optional[str] = None
) -> str:
    """
    Generate deterministic asset ID based on available identifiers.
    
    Uses priority order: MAC address > Hostname > IP address
    This ensures the same physical device gets the same asset_id
    across different scans (nmap, nuclei) and over time.
    
    Args:
        mac: MAC address (preferred identifier, most stable)
        hostname: Hostname (second preference)
        ip: IP address (fallback)
    
    Returns:
        Asset ID string in format "aid_{hash}" (16 hex characters)
    
    Raises:
        ValueError: If no identifier is provided
    
    Examples:
        >>> generate_asset_id(mac="AA:BB:CC:DD:EE:FF")
        'aid_a1b2c3d4e5f6a7b8'
        
        >>> generate_asset_id(hostname="web-server-01")
        'aid_1234567890abcdef'
        
        >>> generate_asset_id(ip="10.0.0.1")
        'aid_fedcba0987654321'
    """
    # Priority: MAC > Hostname > IP
    if mac:
        # Normalize MAC: remove colons, dashes, and uppercase
        hash_input = mac.upper().replace(':', '').replace('-', '')
    elif hostname:
        # Normalize hostname: lowercase
        hash_input = hostname.lower()
    elif ip:
        # Use IP as-is
        hash_input = ip
    else:
        raise ValueError("At least one identifier (mac, hostname, or ip) is required")
    
    # Generate SHA256 hash and truncate to 16 hex characters
    hash_bytes = hashlib.sha256(hash_input.encode('utf-8')).digest()
    hash_hex = hash_bytes.hex()[:16]
    
    return f"aid_{hash_hex}"


def generate_exposure_id(
    office_id: str,
    asset_id: str,
    dst_ip: str,
    dst_port: int | None,
    protocol: str,
    exposure_class: str
) -> str:
    """
    Generate deterministic exposure ID for deduplication.
    
    Same inputs always produce the same exposure ID, allowing
    multiple observations of the same exposure to be correlated.
    
    Args:
        office_id: Office identifier
        asset_id: Asset identifier
        dst_ip: Destination IP address
        dst_port: Destination port (or None for ICMP etc)
        protocol: Protocol name
        exposure_class: Exposure classification
    
    Returns:
        32-character hex string (SHA256 truncated)
    """
    # Use empty string for None port to ensure deterministic hashing
    port_str = str(dst_port) if dst_port is not None else ""
    
    components = f"{office_id}|{asset_id}|{dst_ip}|{port_str}|{protocol}|{exposure_class}"
    hash_bytes = hashlib.sha256(components.encode('utf-8')).digest()
    
    # Return first 32 hex characters (16 bytes)
    return "exp_"+hash_bytes.hex()[:32]


def generate_event_id() -> str:
    """
    Generate unique event ID using UUIDv7 (time-ordered).
    
    UUIDv7 provides monotonically increasing IDs with embedded timestamps,
    useful for time-series queries and debugging.
    
    Returns:
        UUIDv7 string
    """
    return "evt_"+str(uuid7())


def generate_dedupe_key(
    office_id: str,
    asset_id: str,
    dst_ip: str,
    dst_port: int | None,
    protocol: str,
    exposure_class: str,
    service_product: str | None = None
) -> str:
    """
    Generate deduplication key for identifying same finding.
    
    Similar to exposure_id but may include additional fields
    for more granular deduplication (e.g., service version).
    
    Args:
        office_id: Office identifier
        asset_id: Asset identifier  
        dst_ip: Destination IP address
        dst_port: Destination port (or None)
        protocol: Protocol name
        exposure_class: Exposure classification
        service_product: Optional service product name
    
    Returns:
        32-character hex string (SHA256 truncated)
    """
    port_str = str(dst_port) if dst_port is not None else ""
    product_str = service_product or ""
    
    components = (
        f"{office_id}|{asset_id}|{dst_ip}|{port_str}|"
        f"{protocol}|{exposure_class}|{product_str}"
    )
    hash_bytes = hashlib.sha256(components.encode('utf-8')).digest()
    
    return hash_bytes.hex()[:32]
