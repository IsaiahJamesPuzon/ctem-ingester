"""
Unit tests for nuclei JSON transformer.
Tests parsing, classification, and canonical model generation.
"""

import pytest
import json
from pathlib import Path
import tempfile

from src.transformers.nuclei_transformer import NucleiTransformer
from src.transformers.base import TransformerError
from src.models.canonical import ExposureClass, ServiceBindScope


@pytest.fixture
def transformer():
    return NucleiTransformer()


@pytest.fixture
def sample_nuclei_json():
    """Sample nuclei JSON output."""
    return [
        {
            "template-id": "exposed-panel-laravel",
            "info": {
                "name": "Laravel Debug Mode",
                "severity": "high",
                "tags": ["exposure", "laravel", "debug"]
            },
            "type": "http",
            "host": "http://10.0.2.131:80",
            "matched-at": "http://10.0.2.131:80/debug",
            "extracted-results": ["Laravel v8.0"],
            "timestamp": "2024-01-13T10:30:00Z"
        },
        {
            "template-id": "mongodb-unauth",
            "info": {
                "name": "MongoDB Unauth",
                "severity": "critical",
                "tags": ["database", "mongodb"]
            },
            "type": "network",
            "host": "tcp://10.0.2.169:27017",
            "timestamp": "2024-01-13T10:31:00Z"
        }
    ]


def test_parse_valid_json(transformer, sample_nuclei_json):
    """Test parsing valid nuclei JSON."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(sample_nuclei_json, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Should have 2 events
        assert len(events) == 2
        
        # Check first event (Laravel debug panel)
        laravel_event = next(e for e in events if e.exposure.service.name == "exposed-panel-laravel")
        assert laravel_event.exposure.class_ == ExposureClass.DEBUG_PORT_EXPOSED
        assert laravel_event.target.asset.ip == ["10.0.2.131"]
        assert laravel_event.exposure.vector.dst.port == 80
        assert laravel_event.scanner.type == "nuclei"
        
        # Check second event (MongoDB)
        mongo_event = next(e for e in events if e.exposure.service.name == "mongodb-unauth")
        assert mongo_event.exposure.class_ == ExposureClass.DB_EXPOSED
        assert mongo_event.target.asset.ip == ["10.0.2.169"]
        assert mongo_event.exposure.vector.dst.port == 27017
        
    finally:
        temp_path.unlink()


def test_parse_empty_json(transformer):
    """Test parsing empty JSON array."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump([], f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        assert len(events) == 0
    finally:
        temp_path.unlink()


def test_reject_invalid_json(transformer):
    """Test that invalid JSON is rejected."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        f.write("{invalid json")
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(TransformerError):
            transformer.transform(
                file_path=temp_path,
                office_id="office-1",
                scanner_id="scanner-1"
            )
    finally:
        temp_path.unlink()


def test_reject_non_array_json(transformer):
    """Test that non-array JSON is rejected."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump({"not": "an array"}, f)
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(TransformerError) as exc_info:
            transformer.transform(
                file_path=temp_path,
                office_id="office-1",
                scanner_id="scanner-1"
            )
        assert "Expected JSON array" in str(exc_info.value)
    finally:
        temp_path.unlink()


def test_extract_host_info_http(transformer):
    """Test extracting host info from HTTP URL."""
    host_info = transformer._extract_host_info("http://10.0.2.131:80")
    assert host_info['ip'] == "10.0.2.131"
    assert host_info['port'] == 80
    assert host_info['protocol'] == "http"


def test_extract_host_info_https(transformer):
    """Test extracting host info from HTTPS URL."""
    host_info = transformer._extract_host_info("https://192.168.1.100:443")
    assert host_info['ip'] == "192.168.1.100"
    assert host_info['port'] == 443
    assert host_info['protocol'] == "https"


def test_extract_host_info_tcp(transformer):
    """Test extracting host info from TCP URL."""
    host_info = transformer._extract_host_info("tcp://10.0.2.169:27017")
    assert host_info['ip'] == "10.0.2.169"
    assert host_info['port'] == 27017
    assert host_info['protocol'] == "tcp"


def test_extract_host_info_default_port(transformer):
    """Test default port assignment for HTTP."""
    host_info = transformer._extract_host_info("http://10.0.2.131")
    assert host_info['ip'] == "10.0.2.131"
    assert host_info['port'] == 80
    assert host_info['protocol'] == "http"


def test_extract_host_info_hostname(transformer):
    """Test extracting hostname instead of IP."""
    host_info = transformer._extract_host_info("http://example.com:8080")
    assert host_info['ip'] == "example.com"  # Falls back to hostname
    assert host_info['port'] == 8080


def test_classify_database_mongodb(transformer):
    """Test MongoDB classification."""
    exposure_class = transformer._classify_exposure(
        severity="critical",
        tags=["database", "mongodb"],
        template_id="mongodb-unauth",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.DB_EXPOSED


def test_classify_database_mysql(transformer):
    """Test MySQL classification."""
    exposure_class = transformer._classify_exposure(
        severity="critical",
        tags=["database", "mysql"],
        template_id="mysql-default",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.DB_EXPOSED


def test_classify_remote_admin_ssh(transformer):
    """Test SSH classification."""
    exposure_class = transformer._classify_exposure(
        severity="high",
        tags=["ssh", "admin"],
        template_id="ssh-weak-algo",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.REMOTE_ADMIN_EXPOSED


def test_classify_remote_admin_vnc(transformer):
    """Test VNC classification."""
    exposure_class = transformer._classify_exposure(
        severity="high",
        tags=["vnc", "admin"],
        template_id="vnc-no-auth",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.REMOTE_ADMIN_EXPOSED


def test_classify_debug_panel(transformer):
    """Test debug panel classification."""
    exposure_class = transformer._classify_exposure(
        severity="high",
        tags=["exposure", "laravel", "debug"],
        template_id="exposed-panel-laravel",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.DEBUG_PORT_EXPOSED


def test_classify_debug_console(transformer):
    """Test debug console classification via template-id."""
    exposure_class = transformer._classify_exposure(
        severity="medium",
        tags=["web"],
        template_id="debug-console-exposed",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.DEBUG_PORT_EXPOSED


def test_classify_container_docker(transformer):
    """Test Docker API classification."""
    exposure_class = transformer._classify_exposure(
        severity="critical",
        tags=["docker", "container"],
        template_id="docker-api-unauth",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.CONTAINER_API_EXPOSED


def test_classify_container_kubernetes(transformer):
    """Test Kubernetes classification."""
    exposure_class = transformer._classify_exposure(
        severity="high",
        tags=["k8s", "kubernetes"],
        template_id="kubernetes-dashboard",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.CONTAINER_API_EXPOSED


def test_classify_fileshare_smb(transformer):
    """Test SMB classification."""
    exposure_class = transformer._classify_exposure(
        severity="medium",
        tags=["smb", "fileshare"],
        template_id="smb-signing-disabled",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.FILESHARE_EXPOSED


def test_classify_vcs_git(transformer):
    """Test Git VCS classification."""
    exposure_class = transformer._classify_exposure(
        severity="medium",
        tags=["exposure", "git", "vcs"],
        template_id="git-config-exposure",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.VCS_PROTOCOL_EXPOSED


def test_classify_http_content_leak(transformer):
    """Test HTTP content leak classification."""
    exposure_class = transformer._classify_exposure(
        severity="info",
        tags=["exposure", "disclosure"],
        template_id="env-file-disclosure",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.HTTP_CONTENT_LEAK


def test_classify_unknown(transformer):
    """Test unknown service classification."""
    exposure_class = transformer._classify_exposure(
        severity="info",
        tags=["misconfiguration"],
        template_id="some-generic-check",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.UNKNOWN_SERVICE_EXPOSED


def test_severity_critical(transformer):
    """Test severity calculation for critical findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="critical",
        exposure_class=ExposureClass.DB_EXPOSED
    )
    assert severity == 95


def test_severity_high(transformer):
    """Test severity calculation for high findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="high",
        exposure_class=ExposureClass.REMOTE_ADMIN_EXPOSED
    )
    assert severity == 80


def test_severity_medium(transformer):
    """Test severity calculation for medium findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="medium",
        exposure_class=ExposureClass.HTTP_CONTENT_LEAK
    )
    assert severity == 60


def test_severity_low(transformer):
    """Test severity calculation for low findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="low",
        exposure_class=ExposureClass.UNKNOWN_SERVICE_EXPOSED
    )
    assert severity == 40


def test_severity_info(transformer):
    """Test severity calculation for info findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="info",
        exposure_class=ExposureClass.HTTP_CONTENT_LEAK
    )
    assert severity == 50  # Class severity (50) > nuclei severity (20)


def test_severity_uses_higher_value(transformer):
    """Test that severity uses higher of nuclei vs class severity."""
    # Class severity (90) should override low nuclei severity (40)
    severity = transformer._calculate_severity(
        nuclei_severity="low",
        exposure_class=ExposureClass.DB_EXPOSED
    )
    assert severity == 90


def test_deterministic_exposure_ids(transformer, sample_nuclei_json):
    """Test that same scan produces same exposure IDs."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(sample_nuclei_json, f)
        temp_path = Path(f.name)
    
    try:
        events1 = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        events2 = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Same inputs should produce same exposure IDs
        ids1 = sorted([e.exposure.id for e in events1])
        ids2 = sorted([e.exposure.id for e in events2])
        assert ids1 == ids2
        
    finally:
        temp_path.unlink()


def test_handle_missing_fields(transformer):
    """Test graceful handling of findings with missing fields."""
    minimal_finding = [
        {
            "template-id": "test-finding",
            "host": "http://10.0.2.1:80"
            # Missing info, timestamp, etc.
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(minimal_finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Should still produce an event with defaults
        assert len(events) == 1
        assert events[0].exposure.service.name == "test-finding"
        
    finally:
        temp_path.unlink()


def test_skip_finding_without_ip(transformer):
    """Test that findings without extractable IP are skipped."""
    bad_finding = [
        {
            "template-id": "test-finding",
            "info": {"name": "Test", "severity": "low"},
            "host": "invalid-host-format"
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(bad_finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Should skip the finding
        assert len(events) == 0
        
    finally:
        temp_path.unlink()


def test_version_extraction_from_extracted_results(transformer):
    """Test version extraction from extracted-results field."""
    finding = [
        {
            "template-id": "version-detect",
            "info": {"name": "Laravel Detection", "severity": "info", "description": "Detected Laravel framework"},
            "host": "http://10.0.2.1:80",
            "extracted-results": ["Laravel v8.0.2"]
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        # Version is extracted from extracted-results
        assert events[0].exposure.service.version == "8.0.2"
        # Product is now info.name + description (not extracted-results)
        assert "Laravel Detection" in events[0].exposure.service.product
        assert "Detected Laravel framework" in events[0].exposure.service.product
        
    finally:
        temp_path.unlink()


def test_tls_detection_from_https(transformer):
    """Test TLS detection from HTTPS protocol."""
    finding = [
        {
            "template-id": "test",
            "info": {"name": "Test", "severity": "info"},
            "host": "https://10.0.2.1:443"
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        assert events[0].exposure.service.tls is True
        
    finally:
        temp_path.unlink()


def test_scanner_type(transformer):
    """Test that transformer returns correct scanner type."""
    assert transformer.get_scanner_type() == "nuclei"


def test_file_size_limit(transformer):
    """Test that oversized files are rejected."""
    # Create a file larger than 10MB
    large_data = [{"template-id": f"test-{i}", "host": "http://10.0.0.1"} for i in range(500000)]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(large_data, f)
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(TransformerError) as exc_info:
            transformer.transform(
                file_path=temp_path,
                office_id="office-1",
                scanner_id="scanner-1"
            )
        assert "too large" in str(exc_info.value).lower()
    finally:
        temp_path.unlink()


# ============================================================
# ENRICHMENT TESTS - Verify nmap2nuclei.py enrichment handling
# ============================================================

def test_enrichment_mac_hostname_os_extraction(transformer):
    """Test extraction of MAC, hostname, and OS from _ctem_enrichment."""
    finding = [
        {
            "template-id": "tech-detect",
            "info": {
                "name": "Technology Detection",
                "severity": "info",
                "tags": ["tech", "discovery"]
            },
            "type": "http",
            "host": "http://10.0.0.1:8080",
            "matched-at": "http://10.0.0.1:8080",
            "timestamp": "2026-01-20T18:05:41.755116+04:00",
            "_ctem_enrichment": {
                "resource_type": "http_path",
                "resource_identifier": "/",
                "data_classifications": ["unknown"],
                "template_id": "tech-detect",
                "template_name": "Technology Detection",
                "severity": "info",
                "tags": ["tech", "discovery"],
                "transport": "tcp",
                "mac": "48:A9:8A:18:6E:74",
                "hostname": "router.local",
                "os": "Linux 2.6.32 - 3.10"
            }
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Verify MAC address is extracted
        assert event.target.asset.mac == "48:A9:8A:18:6E:74"
        
        # Verify hostname is extracted
        assert event.target.asset.hostname == "router.local"
        
        # Verify OS is extracted
        assert event.target.asset.os == "Linux 2.6.32 - 3.10"
        
        # Verify asset ID uses MAC (not IP)
        # MAC-based asset IDs should start with "aid_" and be different from IP-based
        assert event.target.asset.id.startswith("aid_")
        
    finally:
        temp_path.unlink()


def test_enrichment_resource_extraction(transformer):
    """Test extraction of resource type and identifier from enrichment."""
    finding = [
        {
            "template-id": "git-config-exposure",
            "info": {
                "name": "Git Config Exposed",
                "severity": "medium",
                "tags": ["exposure", "git", "vcs"]
            },
            "type": "http",
            "host": "http://10.0.2.100:8080",
            "matched-at": "http://10.0.2.100:8080/.git/config",
            "timestamp": "2026-01-20T10:00:00Z",
            "_ctem_enrichment": {
                "resource_type": "repo",
                "resource_identifier": "/.git/config",
                "data_classifications": ["source_code"],
                "transport": "tcp",
                "mac": None,
                "hostname": None,
                "os": None
            }
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Verify resource is populated
        assert event.exposure.resource is not None
        assert event.exposure.resource.type.value == "repo"
        assert event.exposure.resource.identifier == "/.git/config"
        assert event.exposure.resource.evidence_hash is not None
        
    finally:
        temp_path.unlink()


def test_enrichment_data_classification_extraction(transformer):
    """Test extraction of data classifications from enrichment."""
    finding = [
        {
            "template-id": "exposed-credentials",
            "info": {
                "name": "Credentials Exposed",
                "severity": "critical",
                "tags": ["exposure", "credentials", "leak"]
            },
            "type": "http",
            "host": "http://10.0.2.100:80",
            "matched-at": "http://10.0.2.100:80/.env",
            "timestamp": "2026-01-20T10:00:00Z",
            "_ctem_enrichment": {
                "resource_type": "http_path",
                "resource_identifier": "/.env",
                "data_classifications": ["credentials", "secrets"],
                "transport": "tcp",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": None,
                "os": None
            }
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Verify data classifications are populated
        assert event.exposure.data_class is not None
        assert len(event.exposure.data_class) == 2
        
        from src.models.canonical import DataClassification
        assert DataClassification.CREDENTIALS in event.exposure.data_class
        assert DataClassification.SECRETS in event.exposure.data_class
        
    finally:
        temp_path.unlink()


def test_enrichment_transport_extraction(transformer):
    """Test extraction of transport protocol from enrichment."""
    # Test UDP transport
    finding_udp = [
        {
            "template-id": "dns-detect",
            "info": {
                "name": "DNS Detection",
                "severity": "info",
                "tags": ["network", "dns"]
            },
            "type": "dns",
            "host": "udp://10.0.2.100:53",
            "matched-at": "udp://10.0.2.100:53",
            "timestamp": "2026-01-20T10:00:00Z",
            "_ctem_enrichment": {
                "transport": "udp",
                "mac": None,
                "hostname": None,
                "os": None
            }
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding_udp, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Verify UDP transport is used
        from src.models.canonical import Transport
        assert event.exposure.vector.transport == Transport.UDP
        
    finally:
        temp_path.unlink()


def test_enrichment_fallback_without_enrichment(transformer):
    """Test that transformer works without _ctem_enrichment (fallback mode)."""
    finding = [
        {
            "template-id": "test-finding",
            "info": {
                "name": "Test Finding",
                "severity": "medium",
                "tags": ["test"]
            },
            "type": "http",
            "host": "http://10.0.2.100:80",
            "timestamp": "2026-01-20T10:00:00Z"
            # No _ctem_enrichment field
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Without enrichment, MAC and hostname should be None
        assert event.target.asset.mac is None
        assert event.target.asset.hostname is None
        assert event.target.asset.os is None
        
        # Asset ID should be based on IP
        assert event.target.asset.ip == ["10.0.2.100"]
        
        # Should still have valid event
        assert event.exposure.id is not None
        assert event.event.id is not None
        
    finally:
        temp_path.unlink()


def test_enrichment_asset_id_prioritization(transformer):
    """Test that asset ID generation prioritizes MAC over IP."""
    # Finding with MAC
    finding_with_mac = [
        {
            "template-id": "test",
            "info": {"name": "Test", "severity": "info"},
            "host": "http://10.0.2.100:80",
            "timestamp": "2026-01-20T10:00:00Z",
            "_ctem_enrichment": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "device.local",
                "os": "Linux"
            }
        }
    ]
    
    # Finding without MAC (same IP)
    finding_without_mac = [
        {
            "template-id": "test",
            "info": {"name": "Test", "severity": "info"},
            "host": "http://10.0.2.100:80",
            "timestamp": "2026-01-20T10:00:00Z",
            "_ctem_enrichment": {
                "mac": None,
                "hostname": None,
                "os": None
            }
        }
    ]
    
    # Test with MAC
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding_with_mac, f)
        temp_path_mac = Path(f.name)
    
    # Test without MAC
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding_without_mac, f)
        temp_path_no_mac = Path(f.name)
    
    try:
        events_with_mac = transformer.transform(
            file_path=temp_path_mac,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        events_without_mac = transformer.transform(
            file_path=temp_path_no_mac,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Asset IDs should be different (MAC-based vs IP-based)
        asset_id_with_mac = events_with_mac[0].target.asset.id
        asset_id_without_mac = events_without_mac[0].target.asset.id
        
        assert asset_id_with_mac != asset_id_without_mac
        
        # Both should have same IP
        assert events_with_mac[0].target.asset.ip == ["10.0.2.100"]
        assert events_without_mac[0].target.asset.ip == ["10.0.2.100"]
        
        # Only MAC version should have MAC
        assert events_with_mac[0].target.asset.mac == "AA:BB:CC:DD:EE:FF"
        assert events_without_mac[0].target.asset.mac is None
        
    finally:
        temp_path_mac.unlink()
        temp_path_no_mac.unlink()


def test_enrichment_multiple_data_classifications(transformer):
    """Test handling of multiple data classifications."""
    finding = [
        {
            "template-id": "multi-leak",
            "info": {
                "name": "Multiple Data Leak",
                "severity": "high",
                "tags": ["exposure", "leak"]
            },
            "type": "http",
            "host": "http://10.0.2.100:80",
            "timestamp": "2026-01-20T10:00:00Z",
            "_ctem_enrichment": {
                "resource_type": "repo",
                "resource_identifier": "/.git/",
                "data_classifications": ["source_code", "secrets", "credentials", "pii"],
                "transport": "tcp",
                "mac": None,
                "hostname": None,
                "os": None
            }
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Verify all data classifications are present
        from src.models.canonical import DataClassification
        assert event.exposure.data_class is not None
        assert len(event.exposure.data_class) == 4
        assert DataClassification.SOURCE_CODE in event.exposure.data_class
        assert DataClassification.SECRETS in event.exposure.data_class
        assert DataClassification.CREDENTIALS in event.exposure.data_class
        assert DataClassification.PII in event.exposure.data_class
        
    finally:
        temp_path.unlink()


def test_enrichment_invalid_data_skipped(transformer):
    """Test that invalid enrichment data types are handled gracefully."""
    finding = [
        {
            "template-id": "test",
            "info": {"name": "Test", "severity": "info"},
            "host": "http://10.0.2.100:80",
            "timestamp": "2026-01-20T10:00:00Z",
            "_ctem_enrichment": {
                "mac": 12345,  # Invalid: should be string
                "hostname": ["invalid"],  # Invalid: should be string
                "os": {"invalid": "dict"},  # Invalid: should be string
                "data_classifications": ["invalid_classification"]  # Invalid enum value
            }
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Invalid data should be ignored/skipped
        assert event.target.asset.mac is None  # Invalid type ignored
        assert event.target.asset.hostname is None  # Invalid type ignored
        assert event.target.asset.os is None  # Invalid type ignored
        
        # Invalid enum values should be skipped
        # data_class might be None or empty list
        if event.exposure.data_class:
            assert len(event.exposure.data_class) == 0
        
    finally:
        temp_path.unlink()


def test_duplicate_exposure_id_deduplication(transformer):
    """
    Test that findings with identical exposure_ids are deduplicated within a batch.
    
    This scenario occurs when the same template tests multiple variations
    (e.g., different passwords) against the same service, resulting in
    multiple findings with identical exposure parameters.
    
    Example: redis-default-logins testing 5 different passwords against
    the same Redis instance at 10.0.1.188:6379.
    """
    # Simulate 5 findings from redis-default-logins with different passwords
    # All targeting the same Redis instance, so they'll have the same exposure_id
    nuclei_findings = [
        {
            "template-id": "redis-default-logins",
            "info": {
                "name": "Redis - Default Logins",
                "severity": "high",
                "tags": ["redis", "default-login", "database"]
            },
            "type": "javascript",
            "host": "javascript://10.0.1.188:6379",
            "port": "6379",
            "matched-at": "10.0.1.188:6379",
            "timestamp": "2024-01-13T10:30:00.000001Z",
            "meta": {"passwords": "admin"},
            "_ctem_enrichment": {
                "mac": "60:3E:5F:67:7A:DC",
                "hostname": None,
                "os": None,
                "transport": "tcp"
            }
        },
        {
            "template-id": "redis-default-logins",
            "info": {
                "name": "Redis - Default Logins",
                "severity": "high",
                "tags": ["redis", "default-login", "database"]
            },
            "type": "javascript",
            "host": "javascript://10.0.1.188:6379",
            "port": "6379",
            "matched-at": "10.0.1.188:6379",
            "timestamp": "2024-01-13T10:30:00.000002Z",
            "meta": {"passwords": "password"},
            "_ctem_enrichment": {
                "mac": "60:3E:5F:67:7A:DC",
                "hostname": None,
                "os": None,
                "transport": "tcp"
            }
        },
        {
            "template-id": "redis-default-logins",
            "info": {
                "name": "Redis - Default Logins",
                "severity": "high",
                "tags": ["redis", "default-login", "database"]
            },
            "type": "javascript",
            "host": "javascript://10.0.1.188:6379",
            "port": "6379",
            "matched-at": "10.0.1.188:6379",
            "timestamp": "2024-01-13T10:30:00.000003Z",
            "meta": {"passwords": "root"},
            "_ctem_enrichment": {
                "mac": "60:3E:5F:67:7A:DC",
                "hostname": None,
                "os": None,
                "transport": "tcp"
            }
        }
    ]
    
    # Write to temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(nuclei_findings, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="test-office",
            scanner_id="nuclei"
        )
        
        # Should only get 1 event despite 3 findings with the same exposure_id
        assert len(events) == 1, f"Expected 1 event, got {len(events)}"
        
        event = events[0]
        
        # Verify it's a Redis exposure
        assert event.exposure.class_ == ExposureClass.DB_EXPOSED
        assert event.exposure.service.name == "redis-default-logins"
        
        # Verify all exposure_ids are unique (no duplicates)
        exposure_ids = [e.exposure.id for e in events]
        assert len(exposure_ids) == len(set(exposure_ids)), "Found duplicate exposure_ids in output"
        
    finally:
        temp_path.unlink()


def test_multiple_templates_same_service_different_classes(transformer):
    """
    Test that different templates hitting the same service but classified
    into different exposure classes generate separate exposures.
    """
    nuclei_findings = [
        {
            "template-id": "tech-detect",
            "info": {
                "name": "Technology Detection",
                "severity": "info",
                "tags": ["tech", "discovery"]
            },
            "type": "http",
            "host": "http://10.0.0.1:8080",
            "port": "8080",
            "matched-at": "http://10.0.0.1:8080",
            "timestamp": "2024-01-13T10:30:00Z",
            "_ctem_enrichment": {
                "mac": "48:A9:8A:18:6E:74",
                "hostname": None,
                "os": "Linux 2.6.32",
                "transport": "tcp"
            }
        },
        {
            "template-id": "admin-panel-detect",
            "info": {
                "name": "Admin Panel",
                "severity": "medium",
                "tags": ["admin", "panel"]
            },
            "type": "http",
            "host": "http://10.0.0.1:8080",
            "port": "8080",
            "matched-at": "http://10.0.0.1:8080/admin",
            "timestamp": "2024-01-13T10:30:01Z",
            "_ctem_enrichment": {
                "mac": "48:A9:8A:18:6E:74",
                "hostname": None,
                "os": "Linux 2.6.32",
                "transport": "tcp"
            }
        }
    ]
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(nuclei_findings, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="test-office",
            scanner_id="nuclei"
        )
        
        # Should get 2 events because they have different template_ids and classes
        assert len(events) == 2, f"Expected 2 events, got {len(events)}"
        
        # Verify all exposure_ids are unique
        exposure_ids = [e.exposure.id for e in events]
        assert len(exposure_ids) == len(set(exposure_ids)), "Found duplicate exposure_ids in output"
        
        # Verify different classifications (enhanced logic provides better classification)
        classes = [e.exposure.class_ for e in events]
        # tech-detect on port 8080 → HTTP_CONTENT_LEAK
        assert ExposureClass.HTTP_CONTENT_LEAK in classes
        # admin-panel-detect with "panel" tag → DEBUG_PORT_EXPOSED
        assert ExposureClass.DEBUG_PORT_EXPOSED in classes
        
    finally:
        temp_path.unlink()


def test_enhanced_classification_with_enrichment_http_service(transformer):
    """
    Test that enrichment service data enhances classification to match nmap.
    
    When nuclei finding has enrichment with service='http', it should be
    classified as HTTP_CONTENT_LEAK (not UNKNOWN_SERVICE_EXPOSED).
    """
    nuclei_findings = [
        {
            "template-id": "tech-detect",
            "info": {
                "name": "Wappalyzer Technology Detection",
                "severity": "info",  # Low severity
                "tags": ["tech", "discovery"]  # No specific classification tags
            },
            "type": "http",
            "host": "http://10.0.0.1:8080",
            "port": "8080",
            "matched-at": "http://10.0.0.1:8080",
            "timestamp": "2024-01-13T10:30:00Z",
            "_ctem_enrichment": {
                "mac": "48:A9:8A:18:6E:74",
                "hostname": None,
                "os": "Linux 2.6.32",
                "transport": "tcp"
            },
            "_service": {
                "host": "10.0.0.1",
                "port": 8080,
                "protocol": "tcp",
                "service": "http",  # Key: enrichment says it's HTTP
                "version": "MikroTik router config httpd",
                "product": "MikroTik router config httpd",
                "state": "open"
            }
        }
    ]
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(nuclei_findings, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="test-office",
            scanner_id="nuclei"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Should be classified as HTTP_CONTENT_LEAK (like nmap would)
        assert event.exposure.class_ == ExposureClass.HTTP_CONTENT_LEAK
        
        # Severity should be 50 (matching exposure class, not template "info")
        assert event.event.severity == 50
        
        # Bind scope should be inferred as LOCAL_SUBNET (private IP + http)
        assert event.exposure.service.bind_scope == ServiceBindScope.LOCAL_SUBNET
        
    finally:
        temp_path.unlink()


def test_enhanced_classification_redis_from_enrichment(transformer):
    """
    Test that redis service is classified as DB_EXPOSED using enrichment.
    """
    nuclei_findings = [
        {
            "template-id": "redis-default-logins",
            "info": {
                "name": "Redis - Default Logins",
                "severity": "high",
                "tags": ["redis", "default-login", "database"]
            },
            "type": "javascript",
            "host": "javascript://10.0.1.188:6379",
            "port": "6379",
            "matched-at": "10.0.1.188:6379",
            "timestamp": "2024-01-13T10:30:00Z",
            "_ctem_enrichment": {
                "mac": "60:3E:5F:67:7A:DC",
                "transport": "tcp"
            },
            "_service": {
                "host": "10.0.1.188",
                "port": 6379,
                "service": "redis",  # Enrichment confirms it's Redis
                "state": "open"
            }
        }
    ]
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(nuclei_findings, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="test-office",
            scanner_id="nuclei"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Should be DB_EXPOSED (from both tags and enrichment)
        assert event.exposure.class_ == ExposureClass.DB_EXPOSED
        
        # High severity should be maintained
        assert event.event.severity >= 80
        
        # Redis is internal service, should be LOCAL_SUBNET
        assert event.exposure.service.bind_scope == ServiceBindScope.LOCAL_SUBNET
        
    finally:
        temp_path.unlink()


def test_enhanced_classification_rtsp_media_streaming(transformer):
    """
    Test that RTSP service is classified as MEDIA_STREAMING_EXPOSED.
    """
    nuclei_findings = [
        {
            "template-id": "rtsp-detect",
            "info": {
                "name": "RTSP - Detect",
                "severity": "info",
                "tags": ["network", "rtsp", "detect"]
            },
            "type": "tcp",
            "host": "tcp://10.0.5.32:7000",
            "port": "7000",
            "matched-at": "10.0.5.32:7000",
            "timestamp": "2024-01-13T10:30:00Z",
            "_ctem_enrichment": {
                "mac": "52:3E:49:27:6E:A6",
                "transport": "tcp"
            },
            "_service": {
                "host": "10.0.5.32",
                "port": 7000,
                "service": "rtsp",  # RTSP streaming service
                "state": "open"
            }
        }
    ]
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(nuclei_findings, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="test-office",
            scanner_id="nuclei"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Should be MEDIA_STREAMING_EXPOSED (from enrichment service='rtsp')
        assert event.exposure.class_ == ExposureClass.MEDIA_STREAMING_EXPOSED
        
        # Should infer LOCAL_SUBNET for private IP
        assert event.exposure.service.bind_scope == ServiceBindScope.LOCAL_SUBNET
        
    finally:
        temp_path.unlink()


def test_bind_scope_private_ip_detection(transformer):
    """Test that private IPs are correctly detected for bind scope inference."""
    nuclei_findings = [
        {
            "template-id": "test-template",
            "info": {"name": "Test", "severity": "info", "tags": []},
            "type": "http",
            "host": "http://192.168.1.100:80",
            "port": "80",
            "matched-at": "http://192.168.1.100:80",
            "timestamp": "2024-01-13T10:30:00Z",
            "_ctem_enrichment": {"transport": "tcp"},
            "_service": {
                "host": "192.168.1.100",
                "port": 80,
                "service": "http",
                "state": "open"
            }
        }
    ]
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(nuclei_findings, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="test-office",
            scanner_id="nuclei"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # HTTP on private IP should be LOCAL_SUBNET, not ANY
        assert event.exposure.service.bind_scope == ServiceBindScope.LOCAL_SUBNET
        
    finally:
        temp_path.unlink()


def test_aggregation_metadata_for_merged_findings(transformer):
    """Test that aggregation metadata is added when findings are merged."""
    findings = [
        {
            "template-id": "exposed-redis",
            "info": {
                "name": "Redis Exposed",
                "severity": "high",
                "tags": ["database", "redis"]
            },
            "type": "javascript",
            "host": "javascript://10.0.1.188:6379",
            "port": "6379",
            "matched-at": "10.0.1.188:6379",
            "timestamp": "2024-01-13T10:30:00Z",
            "_service": {
                "service": "redis",
                "product": "Redis",
                "version": "7.4.7"
            }
        },
        {
            "template-id": "redis-default-logins",
            "info": {
                "name": "Redis Default Logins",
                "severity": "high",
                "tags": ["database", "redis", "default-login"]
            },
            "type": "javascript",
            "host": "javascript://10.0.1.188:6379",
            "port": "6379",
            "matched-at": "10.0.1.188:6379",
            "timestamp": "2024-01-13T10:30:01Z",
            "meta": {
                "passwords": "admin"
            },
            "_service": {
                "service": "redis",
                "product": "Redis",
                "version": "7.4.7"
            }
        },
        {
            "template-id": "redis-default-logins",
            "info": {
                "name": "Redis Default Logins",
                "severity": "critical",  # Higher severity
                "tags": ["database", "redis", "default-login"]
            },
            "type": "javascript",
            "host": "javascript://10.0.1.188:6379",
            "port": "6379",
            "matched-at": "10.0.1.188:6379",
            "timestamp": "2024-01-13T10:30:02Z",
            "meta": {
                "passwords": "root"
            },
            "_service": {
                "service": "redis",
                "product": "Redis",
                "version": "7.4.7"
            }
        }
    ]
    
    # Write to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(findings, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="test-office",
            scanner_id="nuclei"
        )
        
        # Should have only 1 event (3 findings merged)
        assert len(events) == 1
        event = events[0]
        
        # Check that aggregation metadata was added
        assert hasattr(event, '_ctem_aggregation'), "Event should have _ctem_aggregation attribute"
        
        agg = event._ctem_aggregation
        assert agg['finding_count'] == 3, "Should have merged 3 findings"
        assert agg['max_severity'] == 95, "Should track max severity (critical=95)"
        assert agg['original_severity'] == 90, "Should track original first finding severity (high=90)"
        
        # Check merged templates
        assert len(agg['merged_templates']) == 3
        assert 'exposed-redis' in agg['merged_templates']
        assert agg['merged_templates'].count('redis-default-logins') == 2
        
        # Event severity should be updated to max
        assert event.event.severity == 95, "Event severity should be updated to max (95)"
        
    finally:
        temp_path.unlink()


def test_no_aggregation_for_single_finding(transformer):
    """Test that no aggregation metadata is added for single findings."""
    findings = [
        {
            "template-id": "exposed-redis",
            "info": {
                "name": "Redis Exposed",
                "severity": "high",
                "tags": ["database", "redis"]
            },
            "type": "javascript",
            "host": "javascript://10.0.1.188:6379",
            "port": "6379",
            "matched-at": "10.0.1.188:6379",
            "timestamp": "2024-01-13T10:30:00Z",
            "_service": {
                "service": "redis",
                "product": "Redis"
            }
        }
    ]
    
    # Write to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(findings, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="test-office",
            scanner_id="nuclei"
        )
        
        assert len(events) == 1
        event = events[0]
        
        # Should NOT have aggregation metadata for single finding
        assert not hasattr(event, '_ctem_aggregation'), "Single finding should not have aggregation metadata"
        
    finally:
        temp_path.unlink()
