"""
Shared scoring utilities for CTEM exposure events.

Provides consistent calculation of:
- risk_score: Contextual risk assessment (0-100)
- confidence: Detection confidence level (0-1)
- severity: Exposure class-based severity (0-100)

These calculations are aligned across:
- nmap_transformer.py
- nuclei_transformer.py  
- nmap2nuclei.py (external scanner wrapper)
"""

import ipaddress
from typing import Optional, List, Set

from src.models.canonical import ExposureClass, ServiceBindScope, DataClassification


# ============================================================
# SEVERITY MAPPING (aligned across all transformers)
# ============================================================
EXPOSURE_CLASS_SEVERITY_MAP = {
    ExposureClass.DB_EXPOSED: 90,
    ExposureClass.CONTAINER_API_EXPOSED: 85,
    ExposureClass.QUEUE_EXPOSED: 80,
    ExposureClass.CACHE_EXPOSED: 75,
    ExposureClass.REMOTE_ADMIN_EXPOSED: 70,
    ExposureClass.FILESHARE_EXPOSED: 65,
    ExposureClass.DEBUG_PORT_EXPOSED: 60,
    ExposureClass.VCS_PROTOCOL_EXPOSED: 55,
    ExposureClass.HTTP_CONTENT_LEAK: 50,
    ExposureClass.MONITORING_EXPOSED: 45,
    ExposureClass.EGRESS_TUNNEL_INDICATOR: 45,
    ExposureClass.SERVICE_ADVERTISED_MDNS: 40,
    ExposureClass.MEDIA_STREAMING_EXPOSED: 35,
    ExposureClass.UNKNOWN_SERVICE_EXPOSED: 30,
}

# Nuclei severity string to numeric score mapping
NUCLEI_SEVERITY_MAP = {
    'critical': 95,
    'high': 80,
    'medium': 60,
    'low': 40,
    'info': 20,
    'unknown': 30
}


def calculate_severity_from_class(
    exposure_class: ExposureClass,
    product: Optional[str] = None
) -> int:
    """
    Calculate severity score (0-100) based on exposure class.
    
    Args:
        exposure_class: The classified exposure type
        product: Optional product name for high-risk adjustments
    
    Returns:
        Severity score between 0 and 100
    """
    base_severity = EXPOSURE_CLASS_SEVERITY_MAP.get(exposure_class, 30)
    
    # Adjust for specific high-risk products
    if product:
        product_lower = product.lower()
        if any(keyword in product_lower for keyword in ['docker', 'kubernetes', 'jenkins']):
            base_severity = min(base_severity + 10, 100)
    
    return base_severity


def calculate_severity_with_nuclei(
    nuclei_severity: str,
    exposure_class: ExposureClass
) -> int:
    """
    Calculate severity score combining nuclei severity and exposure class.
    Uses the higher of the two for comprehensive risk assessment.
    
    Args:
        nuclei_severity: Nuclei severity level (critical, high, medium, low, info)
        exposure_class: The classified exposure type
    
    Returns:
        Severity score between 0 and 100
    """
    nuclei_score = NUCLEI_SEVERITY_MAP.get(nuclei_severity.lower(), 30)
    class_score = EXPOSURE_CLASS_SEVERITY_MAP.get(exposure_class, 30)
    return max(nuclei_score, class_score)


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private (RFC 1918) ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def calculate_risk_score(
    severity: int,
    exposure_class: ExposureClass,
    bind_scope: Optional[ServiceBindScope] = None,
    data_classifications: Optional[List[DataClassification]] = None,
    asset_ip: Optional[str] = None
) -> float:
    """
    Calculate risk score (0-100) based on severity and contextual factors.
    
    Risk Score = Base Severity × Bind Scope Multiplier × Data Classification Multiplier
    
    Args:
        severity: Base severity score (0-100)
        exposure_class: The classified exposure type
        bind_scope: Service binding scope (affects exposure risk)
        data_classifications: Types of data potentially exposed
        asset_ip: Asset IP for private/public determination
    
    Returns:
        Risk score between 0.0 and 100.0
    """
    base_score = float(severity)
    
    # Bind scope multiplier
    if bind_scope:
        bind_multipliers = {
            ServiceBindScope.ANY: 1.2,           # Public exposure is higher risk
            ServiceBindScope.LOCAL_SUBNET: 1.0,  # Internal network baseline
            ServiceBindScope.LOOPBACK_ONLY: 0.5, # Localhost only is lower risk
            ServiceBindScope.UNKNOWN: 1.0
        }
        base_score *= bind_multipliers.get(bind_scope, 1.0)
    elif asset_ip:
        # Fallback: use IP privacy if bind_scope not available
        if not is_private_ip(asset_ip):
            base_score *= 1.2  # Public IP increases risk
    
    # Data classification multiplier
    if data_classifications:
        if DataClassification.SECRETS in data_classifications or DataClassification.CREDENTIALS in data_classifications:
            base_score *= 1.3
        elif DataClassification.PII in data_classifications or DataClassification.SOURCE_CODE in data_classifications:
            base_score *= 1.2
        elif DataClassification.INTERNAL_ONLY in data_classifications:
            base_score *= 1.1
    
    return min(round(base_score, 2), 100.0)


def calculate_confidence(
    service_name: Optional[str] = None,
    port: Optional[int] = None,
    service_product: Optional[str] = None,
    service_version: Optional[str] = None,
    nuclei_severity: Optional[str] = None,
    has_mac: bool = False,
    has_hostname: bool = False
) -> float:
    """
    Calculate detection confidence (0-1) based on available evidence.
    
    Confidence factors:
    - Service identification quality
    - Product/version detection
    - Well-known port correlation
    - Nuclei finding severity (higher severity = more confident detection)
    - Asset identification quality (MAC/hostname availability)
    
    Args:
        service_name: Detected service name
        port: Port number
        service_product: Detected product name
        service_version: Detected version string
        nuclei_severity: Nuclei finding severity (if applicable)
        has_mac: Whether MAC address is available
        has_hostname: Whether hostname is available
    
    Returns:
        Confidence score between 0.0 and 1.0
    """
    confidence = 0.4  # Base confidence for any detection
    
    # Service name identification
    if service_name and service_name not in ('unknown', 'tcpwrapped', ''):
        confidence += 0.15
    
    # Product identification
    if service_product and service_product not in ('unknown', ''):
        confidence += 0.12
    
    # Version identification
    if service_version and service_version not in ('unknown', ''):
        confidence += 0.08
    
    # Nuclei finding boost (actual vulnerability detection)
    if nuclei_severity:
        severity_boost = {
            'critical': 0.15,
            'high': 0.12,
            'medium': 0.08,
            'low': 0.05,
            'info': 0.03
        }
        confidence += severity_boost.get(nuclei_severity.lower(), 0.02)
    
    # Well-known unambiguous ports boost confidence
    unambiguous_ports = {
        22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 443: 'https', 445: 'smb', 
        1433: 'mssql', 1521: 'oracle',
        3306: 'mysql', 3389: 'rdp',
        5432: 'postgresql', 5900: 'vnc',
        6379: 'redis', 27017: 'mongodb'
    }
    if port in unambiguous_ports:
        # Extra boost if service name matches expected
        expected = unambiguous_ports[port]
        if service_name and expected in service_name.lower():
            confidence += 0.08
        else:
            confidence += 0.04
    
    # Asset identification quality
    if has_mac:
        confidence += 0.03
    if has_hostname:
        confidence += 0.02
    
    return min(round(confidence, 3), 1.0)
