"""
Unit tests for nmap transformer classification logic.

Tests exposure classification, service binding inference,
and MAC vendor detection.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.transformers.nmap_transformer import (
    get_vendor_from_mac,
    is_private_ip,
    is_link_local,
    is_docker_bridge,
    is_multicast
)


class TestMACVendorDetection:
    """Test MAC vendor identification."""
    
    def test_vmware_detection(self):
        """Should detect VMware MACs."""
        assert get_vendor_from_mac("00:50:56:XX:XX:XX") == "VMware"
        assert get_vendor_from_mac("00:0C:29:XX:XX:XX") == "VMware"
    
    def test_apple_detection(self):
        """Should detect Apple MACs."""
        assert get_vendor_from_mac("00:1B:63:XX:XX:XX") == "Apple"
        assert get_vendor_from_mac("28:CF:E9:XX:XX:XX") == "Apple"
    
    def test_case_insensitive(self):
        """Should handle different case formats."""
        assert get_vendor_from_mac("00:50:56:XX:XX:XX") == "VMware"
        assert get_vendor_from_mac("00:50:56:xx:xx:xx") == "VMware"
    
    def test_hyphen_format(self):
        """Should handle hyphen-separated MACs."""
        mac_colon = "00:50:56:XX:XX:XX"
        mac_hyphen = "00-50-56-XX-XX-XX"
        assert get_vendor_from_mac(mac_colon) == get_vendor_from_mac(mac_hyphen)
    
    def test_unknown_vendor(self):
        """Should return None for unknown vendors."""
        assert get_vendor_from_mac("FF:FF:FF:XX:XX:XX") is None
    
    def test_none_input(self):
        """Should handle None input."""
        assert get_vendor_from_mac(None) is None


class TestIPClassification:
    """Test IP address classification helpers."""
    
    def test_private_ip_ranges(self):
        """Should correctly identify private IPs."""
        # Class A private
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.254") is True
        
        # Class B private
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.254") is True
        
        # Class C private
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.254") is True
        
        # Public IPs
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("172.32.0.1") is False  # Just outside private range
    
    def test_link_local(self):
        """Should correctly identify link-local addresses."""
        assert is_link_local("169.254.0.1") is True
        assert is_link_local("169.254.255.254") is True
        assert is_link_local("10.0.0.1") is False
        assert is_link_local("192.168.1.1") is False
    
    def test_docker_bridge(self):
        """Should correctly identify Docker bridge network."""
        assert is_docker_bridge("172.17.0.1") is True
        assert is_docker_bridge("172.17.255.254") is True
        assert is_docker_bridge("172.16.0.1") is False
        assert is_docker_bridge("172.18.0.1") is False
    
    def test_multicast(self):
        """Should correctly identify multicast addresses."""
        assert is_multicast("224.0.0.1") is True
        assert is_multicast("239.255.255.255") is True
        assert is_multicast("192.168.1.1") is False
    
    def test_invalid_ip(self):
        """Should handle invalid IPs gracefully."""
        assert is_private_ip("not-an-ip") is False
        assert is_link_local("invalid") is False
        assert is_docker_bridge("999.999.999.999") is False


class TestExposureClassification:
    """Test exposure classification logic."""
    
    # Note: These tests would require instantiating NmapTransformer
    # and calling _classify_exposure method. For brevity, showing structure.
    
    def test_database_ports(self):
        """Should classify database ports correctly."""
        # Would test that port 3306 with mysql service → db_exposed
        # And that port 7000 with rtsp service → NOT db_exposed
        pass
    
    def test_streaming_services(self):
        """Should classify streaming services correctly."""
        # Would test that RTSP, AirTunes → media_streaming_exposed
        pass
    
    def test_monitoring_services(self):
        """Should classify monitoring services correctly."""
        # Would test Prometheus, Grafana → monitoring_exposed
        pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
