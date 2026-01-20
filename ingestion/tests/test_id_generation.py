"""
Unit tests for ID generation utilities.

Tests deterministic asset ID generation, exposure ID generation,
and deduplication key generation.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.utils.id_generation import generate_asset_id, generate_exposure_id, generate_dedupe_key


class TestAssetIDGeneration:
    """Test asset ID generation with various inputs."""
    
    def test_deterministic_mac(self):
        """Asset ID should be deterministic for same MAC."""
        mac = "AA:BB:CC:DD:EE:FF"
        id1 = generate_asset_id(mac=mac)
        id2 = generate_asset_id(mac=mac)
        assert id1 == id2
        assert id1.startswith("aid_")
    
    def test_deterministic_hostname(self):
        """Asset ID should be deterministic for same hostname."""
        hostname = "web-server-01"
        id1 = generate_asset_id(hostname=hostname)
        id2 = generate_asset_id(hostname=hostname)
        assert id1 == id2
        assert id1.startswith("aid_")
    
    def test_deterministic_ip(self):
        """Asset ID should be deterministic for same IP."""
        ip = "10.0.0.1"
        id1 = generate_asset_id(ip=ip)
        id2 = generate_asset_id(ip=ip)
        assert id1 == id2
        assert id1.startswith("aid_")
    
    def test_priority_mac_over_hostname(self):
        """MAC should take priority over hostname."""
        mac = "AA:BB:CC:DD:EE:FF"
        hostname = "web-server-01"
        ip = "10.0.0.1"
        
        id_all = generate_asset_id(mac=mac, hostname=hostname, ip=ip)
        id_mac = generate_asset_id(mac=mac)
        
        assert id_all == id_mac
    
    def test_priority_hostname_over_ip(self):
        """Hostname should take priority over IP."""
        hostname = "web-server-01"
        ip = "10.0.0.1"
        
        id_both = generate_asset_id(hostname=hostname, ip=ip)
        id_hostname = generate_asset_id(hostname=hostname)
        
        assert id_both == id_hostname
    
    def test_different_inputs_different_ids(self):
        """Different inputs should produce different asset IDs."""
        id1 = generate_asset_id(mac="AA:BB:CC:DD:EE:FF")
        id2 = generate_asset_id(mac="11:22:33:44:55:66")
        id3 = generate_asset_id(hostname="server-01")
        id4 = generate_asset_id(ip="10.0.0.1")
        
        assert len({id1, id2, id3, id4}) == 4
    
    def test_requires_at_least_one_identifier(self):
        """Should raise error if no identifier provided."""
        with pytest.raises(ValueError):
            generate_asset_id()
    
    def test_mac_normalization(self):
        """MAC addresses should be normalized."""
        id1 = generate_asset_id(mac="AA:BB:CC:DD:EE:FF")
        id2 = generate_asset_id(mac="aa:bb:cc:dd:ee:ff")
        id3 = generate_asset_id(mac="AA-BB-CC-DD-EE-FF")
        
        # All formats should produce the same ID
        assert id1 == id2 == id3
    
    def test_hostname_case_insensitive(self):
        """Hostnames should be case-insensitive."""
        id1 = generate_asset_id(hostname="Web-Server-01")
        id2 = generate_asset_id(hostname="web-server-01")
        id3 = generate_asset_id(hostname="WEB-SERVER-01")
        
        assert id1 == id2 == id3


class TestExposureIDGeneration:
    """Test exposure ID generation."""
    
    def test_deterministic(self):
        """Exposure ID should be deterministic."""
        id1 = generate_exposure_id(
            office_id="office-1",
            asset_id="aid_abc123",
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol="http",
            exposure_class="http_content_leak"
        )
        id2 = generate_exposure_id(
            office_id="office-1",
            asset_id="aid_abc123",
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol="http",
            exposure_class="http_content_leak"
        )
        assert id1 == id2
        assert id1.startswith("exp_")
    
    def test_different_ports_different_ids(self):
        """Different ports should produce different exposure IDs."""
        id1 = generate_exposure_id(
            office_id="office-1",
            asset_id="aid_abc123",
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol="http",
            exposure_class="http_content_leak"
        )
        id2 = generate_exposure_id(
            office_id="office-1",
            asset_id="aid_abc123",
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="https",
            exposure_class="http_content_leak"
        )
        assert id1 != id2
    
    def test_none_port_handling(self):
        """Should handle None port for ICMP etc."""
        id1 = generate_exposure_id(
            office_id="office-1",
            asset_id="aid_abc123",
            dst_ip="10.0.0.1",
            dst_port=None,
            protocol="icmp",
            exposure_class="egress_tunnel_indicator"
        )
        assert id1.startswith("exp_")


class TestDedupeKeyGeneration:
    """Test deduplication key generation."""
    
    def test_includes_product(self):
        """Dedupe key should include product for granular deduplication."""
        key1 = generate_dedupe_key(
            office_id="office-1",
            asset_id="aid_abc123",
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol="http",
            exposure_class="http_content_leak",
            service_product="nginx"
        )
        key2 = generate_dedupe_key(
            office_id="office-1",
            asset_id="aid_abc123",
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol="http",
            exposure_class="http_content_leak",
            service_product="apache"
        )
        assert key1 != key2
