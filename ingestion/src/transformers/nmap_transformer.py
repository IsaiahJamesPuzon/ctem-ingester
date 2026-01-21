"""
nmap XML output transformer to canonical exposure events.

Enhanced with rich metadata extraction and classification patterns
aligned with nmap2nuclei.py for optimal integration.
"""

import ipaddress
import logging

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Set
import defusedxml.ElementTree as ET
from xml.etree.ElementTree import Element  # For type hints only

from src.models.canonical import (
    ExposureEventModel, Event, Office, Scanner, Target, Asset,
    Exposure, Vector, Service, Resource, EventCorrelation,
    EventKind, EventAction, ExposureClass, ExposureStatus,
    Transport, ServiceAuth, ServiceBindScope, NetworkDirection,
    ResourceType, DataClassification
)
from src.transformers.base import BaseTransformer, TransformerError
from src.utils.security import parse_xml_safely
from src.utils.id_generation import generate_asset_id, generate_event_id, generate_exposure_id, generate_dedupe_key

# Initialize logger
logger = logging.getLogger(__name__)


# MAC address vendor prefixes (OUI) for device identification
# For production use, consider using a library like 'manuf' or 'mac-vendor-lookup'
# or downloading the full IEEE OUI database (https://standards.ieee.org/products-programs/regauth/)
MAC_VENDOR_MAP = {
    # Virtualization Platforms
    '00:50:56': 'VMware',
    '00:0C:29': 'VMware',
    '00:05:69': 'VMware',
    '00:1C:14': 'VMware',
    '52:54:00': 'QEMU/KVM',
    '08:00:27': 'VirtualBox',
    '00:15:5D': 'Microsoft Hyper-V',
    '00:1C:42': 'Parallels',
    
    # Apple Devices
    '00:1B:63': 'Apple',
    '00:1C:B3': 'Apple',
    '00:1E:C2': 'Apple',
    '00:23:DF': 'Apple',
    '00:25:00': 'Apple',
    '28:CF:E9': 'Apple',
    '3C:07:54': 'Apple',
    '3C:D0:F8': 'Apple',
    '54:26:96': 'Apple',
    '5C:95:AE': 'Apple',
    '68:96:7B': 'Apple',
    '6C:70:9F': 'Apple',
    '70:E7:2C': 'Apple',
    '78:7B:8A': 'Apple',
    '7C:C3:A1': 'Apple',
    '80:A9:97': 'Apple',
    '84:2F:57': 'Apple',
    '88:63:DF': 'Apple',
    '90:8D:6C': 'Apple',
    'A0:99:9B': 'Apple',
    'AC:BC:32': 'Apple',
    'D8:30:62': 'Apple',
    'DC:2B:2A': 'Apple',
    'F0:98:9D': 'Apple',
    
    # Raspberry Pi
    'DC:A6:32': 'Raspberry Pi',
    'B8:27:EB': 'Raspberry Pi',
    '00:1D:72': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi',
    
    # Network Equipment - Cisco
    '00:00:0C': 'Cisco',
    '00:01:42': 'Cisco',
    '00:01:43': 'Cisco',
    '00:01:63': 'Cisco',
    '00:01:64': 'Cisco',
    '00:01:96': 'Cisco',
    '00:01:97': 'Cisco',
    '00:01:C7': 'Cisco',
    '00:02:16': 'Cisco',
    '00:02:17': 'Cisco',
    '00:02:3D': 'Cisco',
    '00:02:4A': 'Cisco',
    '00:02:4B': 'Cisco',
    '00:02:B9': 'Cisco',
    '00:02:BA': 'Cisco',
    '00:02:FC': 'Cisco',
    '00:02:FD': 'Cisco',
    '00:03:31': 'Cisco',
    '00:03:32': 'Cisco',
    '00:03:6B': 'Cisco',
    '00:03:6C': 'Cisco',
    '00:03:A0': 'Cisco',
    '00:03:E3': 'Cisco',
    '00:03:FD': 'Cisco',
    '00:03:FE': 'Cisco',
    
    # Network Equipment - Other Major Vendors
    '48:A9:8A': 'MikroTik',
    'D4:CA:6D': 'MikroTik',
    'E4:8D:8C': 'MikroTik',
    '00:E0:B8': 'Juniper Networks',
    '28:8A:1C': 'Juniper Networks',
    '40:B4:F0': 'Juniper Networks',
    '50:E4:E0': 'Hewlett Packard Enterprise',
    '98:F2:B3': 'Hewlett Packard Enterprise',
    '00:11:85': 'Hewlett Packard Enterprise',
    '00:14:C2': 'Hewlett Packard Enterprise',
    '00:17:A4': 'Hewlett Packard Enterprise',
    '00:1B:78': 'Hewlett Packard Enterprise',
    '00:30:C1': 'Hewlett Packard',
    '00:60:B0': 'Hewlett Packard',
    '10:00:00': 'Hewlett Packard',
    '48:DF:37': 'Ubiquiti Networks',
    '68:72:51': 'Ubiquiti Networks',
    '74:83:C2': 'Ubiquiti Networks',
    'FC:EC:DA': 'Ubiquiti Networks',
    
    # Dell
    '00:06:5B': 'Dell',
    '00:08:74': 'Dell',
    '00:0B:DB': 'Dell',
    '00:0D:56': 'Dell',
    '00:0F:1F': 'Dell',
    '00:11:43': 'Dell',
    '00:12:3F': 'Dell',
    '00:13:72': 'Dell',
    '00:14:22': 'Dell',
    '00:15:C5': 'Dell',
    '00:18:8B': 'Dell',
    '00:19:B9': 'Dell',
    '00:1A:A0': 'Dell',
    '00:1C:23': 'Dell',
    '00:1D:09': 'Dell',
    '00:1E:4F': 'Dell',
    '00:21:70': 'Dell',
    '00:21:9B': 'Dell',
    '00:22:19': 'Dell',
    '00:23:AE': 'Dell',
    
    # Lenovo/IBM
    '00:04:AC': 'IBM',
    '00:0E:7B': 'Lenovo',
    '00:11:25': 'Lenovo',
    '00:14:5E': 'Lenovo',
    '00:16:41': 'Lenovo',
    '00:17:E1': 'Lenovo',
    '00:19:D1': 'Lenovo',
    '00:1A:6B': 'Lenovo',
    '00:1C:25': 'Lenovo',
    '00:21:5C': 'Lenovo',
    '00:26:55': 'Lenovo',
    
    # Samsung
    '00:12:FB': 'Samsung',
    '00:13:77': 'Samsung',
    '00:15:99': 'Samsung',
    '00:16:32': 'Samsung',
    '00:16:6B': 'Samsung',
    '00:16:6C': 'Samsung',
    '00:17:C9': 'Samsung',
    '00:17:D5': 'Samsung',
    '00:18:AF': 'Samsung',
    '00:1A:8A': 'Samsung',
    '00:1B:98': 'Samsung',
    '00:1C:43': 'Samsung',
    '00:1D:25': 'Samsung',
    '00:1E:7D': 'Samsung',
    '00:1E:E1': 'Samsung',
    '00:1E:E2': 'Samsung',
    '00:21:19': 'Samsung',
    '00:21:D1': 'Samsung',
    '00:21:D2': 'Samsung',
    
    # Intel
    '00:03:47': 'Intel',
    '00:04:23': 'Intel',
    '00:07:E9': 'Intel',
    '00:0E:0C': 'Intel',
    '00:11:11': 'Intel',
    '00:12:F0': 'Intel',
    '00:13:02': 'Intel',
    '00:13:20': 'Intel',
    '00:13:CE': 'Intel',
    '00:15:00': 'Intel',
    '00:16:76': 'Intel',
    '00:16:EA': 'Intel',
    '00:16:EB': 'Intel',
    '00:18:DE': 'Intel',
    '00:19:D1': 'Intel',
    '00:1B:21': 'Intel',
    '00:1C:BF': 'Intel',
    '00:1D:E0': 'Intel',
    '00:1D:E1': 'Intel',
    '00:1E:67': 'Intel',
    
    # Realtek/TP-Link/D-Link
    '00:E0:4C': 'Realtek',
    '00:01:2E': 'Realtek',
    '00:E0:4C': 'Realtek',
    '00:13:46': 'TP-Link',
    '00:17:31': 'TP-Link',
    '00:1D:0F': 'TP-Link',
    '00:21:27': 'TP-Link',
    '00:23:CD': 'TP-Link',
    '00:27:19': 'TP-Link',
    '14:CC:20': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    '00:05:5D': 'D-Link',
    '00:0D:88': 'D-Link',
    '00:11:95': 'D-Link',
    '00:13:46': 'D-Link',
    '00:15:E9': 'D-Link',
    '00:17:9A': 'D-Link',
    '00:19:5B': 'D-Link',
    
    # Amazon/Google
    '00:17:88': 'Amazon Technologies',
    '00:26:B6': 'Amazon Technologies',
    '0C:47:C9': 'Amazon Technologies',
    '68:37:E9': 'Amazon Technologies',
    '74:C2:46': 'Amazon Technologies',
    'AC:63:BE': 'Amazon Technologies',
    'F0:D2:F1': 'Amazon Technologies',
    '00:1A:11': 'Google',
    '00:21:6A': 'Google',
    '3C:5A:B4': 'Google',
    '54:60:09': 'Google',
    '64:16:66': 'Google',
    '68:C4:4D': 'Google',
    '6C:AD:F8': 'Google',
    'A0:35:AF': 'Google',
    'CC:3D:82': 'Google',
    
    # IoT/Embedded Devices
    '00:17:88': 'Philips Hue',
    'EC:FA:BC': 'Nest Labs',
    '18:B4:30': 'Nest Labs',
    '64:16:66': 'Google Nest',
    '00:03:93': 'Sonos',
    'B8:E9:37': 'Sonos',
}


def get_vendor_from_mac(mac: Optional[str]) -> Optional[str]:
    """Extract vendor name from MAC address OUI."""
    if not mac:
        return None
    
    # Normalize MAC format
    mac_normalized = mac.upper().replace('-', ':')
    prefix = mac_normalized[:8]  # First 3 octets (XX:XX:XX)
    
    return MAC_VENDOR_MAP.get(prefix)

def extract_netbios_name(host_elem: Element) -> Optional[str]:
    """Extract NetBIOS hostname from nbstat script output."""
    # Look for nbstat script in hostscript section
    nbstat_script = host_elem.find('.//hostscript/script[@id="nbstat"]')
    if nbstat_script is None:
        return None
    
    output = nbstat_script.get('output', '')
    if not output:
        return None
    
    # Parse "NetBIOS name: HOSTNAME, ..." format
    # Example: "NetBIOS name: MAC-C09F10, NetBIOS user: <unknown>, ..."
    if 'NetBIOS name: ' in output:
        # Extract the hostname between "NetBIOS name: " and the next comma
        start = output.find('NetBIOS name: ') + len('NetBIOS name: ')
        end = output.find(',', start)
        if end != -1:
            netbios_name = output[start:end].strip()
            return netbios_name if netbios_name else None
    
    return None

def is_private_ip(ip: str) -> bool:
    """Check if IP is in private (RFC 1918) ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False  # Invalid IP, treat as non-private


def is_link_local(ip: str) -> bool:
    """Check if IP is in link-local range (169.254.0.0/16 for IPv4, fe80::/10 for IPv6)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_link_local
    except ValueError:
        return False


def is_docker_bridge(ip: str) -> bool:
    """Check if IP is in default Docker bridge network (172.17.0.0/16)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        docker_network = ipaddress.ip_network('172.17.0.0/16')
        return ip_obj in docker_network
    except ValueError:
        return False


def is_multicast(ip: str) -> bool:
    """Check if IP is in multicast range (224.0.0.0/4 for IPv4, ff00::/8 for IPv6)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_multicast
    except ValueError:
        return False

def classify_service_data(
    service_name: str,
    product: Optional[str],
    port: int,
    version: Optional[str]
) -> Set[DataClassification]:
    """
    Classify potential data exposure based on service characteristics.
    Aligned with nmap2nuclei.py data classification patterns.
    Returns DataClassification enum members.
    """
    classifications = set()
    
    service_lower = service_name.lower() if service_name else ''
    product_lower = product.lower() if product else ''
    version_lower = version.lower() if version else ''
    
    # Database services - may contain sensitive data
    if any(db in service_lower or db in product_lower for db in 
           ['mysql', 'postgresql', 'postgres', 'mongodb', 'redis', 'oracle', 
            'mssql', 'mariadb', 'cassandra', 'elasticsearch', 'couchdb']):
        classifications.add(DataClassification.PII)  # Databases often contain PII
    
    # Version control systems - source code
    if any(vcs in service_lower or vcs in product_lower for vcs in 
           ['git', 'svn', 'cvs', 'mercurial', 'perforce']):
        classifications.add(DataClassification.SOURCE_CODE)
        classifications.add(DataClassification.SECRETS)  # VCS may contain secrets
    
    # File sharing - potential data exposure
    if any(share in service_lower or share in product_lower for share in 
           ['smb', 'cifs', 'nfs', 'ftp', 'sftp', 'samba']):
        classifications.add(DataClassification.INTERNAL_ONLY)
    
    # Backup services - sensitive data
    if any(backup in service_lower or backup in product_lower for backup in 
           ['backup', 'bacula', 'amanda', 'rsync']):
        classifications.add(DataClassification.INTERNAL_ONLY)
    
    # Admin/management interfaces - credentials risk
    if any(admin in service_lower or admin in product_lower for admin in 
           ['admin', 'manager', 'console', 'panel', 'dashboard']):
        classifications.add(DataClassification.CREDENTIALS)
    
    # Development/debug services - potential secrets
    if any(dev in service_lower or dev in product_lower for dev in 
           ['debug', 'development', 'dev', 'test', 'jenkins', 'gitlab', 'jira']):
        classifications.add(DataClassification.SECRETS)
    
    # If no specific classification, mark as internal-only
    if not classifications:
        classifications.add(DataClassification.INTERNAL_ONLY)
    
    return classifications


class NmapTransformer(BaseTransformer):
    """
    Transforms nmap XML output to canonical exposure events.
    
    Enhanced Features (aligned with nmap2nuclei.py):
    - MAC vendor identification for better asset tracking
    - Data classification based on service characteristics
    - Resource type inference (API, database, file share, etc.)
    - Comprehensive exposure classification covering 100+ port/service combinations
    - Service binding scope detection
    - Enhanced metadata for CTEM ingestion
    """
    
    def __init__(self, schema_version: str = "1.0.0"):
        self.schema_version = schema_version
    
    def get_scanner_type(self) -> str:
        """Return the scanner type identifier."""
        return "nmap"
    
    def transform(
        self,
        file_path: Path,
        office_id: str,
        scanner_id: str,
        scan_run_id: str | None = None
    ) -> List[ExposureEventModel]:
        """
        Transform nmap XML file to canonical events.
        
        Enhanced to extract maximum metadata from nmap scans:
        - Asset identification: IP, MAC, hostname, OS, vendor
        - Service details: name, product, version, binding scope
        - Exposure classification: 100+ port/service combinations
        - Data classification: Inferred from service characteristics
        - Resource typing: API, database, file share, etc.
        
        Args:
            file_path: Path to nmap XML file
            office_id: Office identifier
            scanner_id: Scanner instance identifier
            scan_run_id: Optional scan run identifier for correlation
        
        Returns:
            List of exposure events (one per open port)
        
        Raises:
            TransformerError: If parsing or transformation fails
        """
        try:
            # Parse XML safely
            root = parse_xml_safely(file_path)
        except Exception as e:
            raise TransformerError(f"Failed to parse nmap XML: {e}") from e
        
        # Verify it's an nmap scan
        if root.tag != 'nmaprun':
            raise TransformerError(
                f"Not a valid nmap XML file (root tag: {root.tag})"
            )
        
        # Extract scan timestamp
        scan_start = root.get('start')
        scan_timestamp = (
            datetime.fromtimestamp(int(scan_start), tz=timezone.utc)
            if scan_start else datetime.now(timezone.utc)
        )
        
        # Extract scanner info
        scanner_version = root.get('version', 'unknown')
        
        # Process each host
        events = []
        for host_elem in root.findall('.//host'):
            host_events = self._process_host(
                host_elem=host_elem,
                office_id=office_id,
                scanner_id=scanner_id,
                scanner_version=scanner_version,
                scan_timestamp=scan_timestamp,
                scan_run_id=scan_run_id
            )
            events.extend(host_events)
        
        return events
    
    def _process_host(
        self,
        host_elem: Element,
        office_id: str,
        scanner_id: str,
        scanner_version: str,
        scan_timestamp: datetime,
        scan_run_id: str | None = None
    ) -> List[ExposureEventModel]:
        """Process a single host element and generate events for open ports."""
        events = []
        
        # Extract host addresses
        addresses = self._extract_addresses(host_elem)
        if not addresses.get('ip'):
            # Skip hosts without IP
            return events
        
        # Extract hostname (DNS or NetBIOS)
        hostnames = host_elem.findall('.//hostname')
        hostname = hostnames[0].get('name') if hostnames else None

        # Fallback to NetBIOS name if DNS hostname not available
        if not hostname:
            hostname = extract_netbios_name(host_elem)
        
        # Extract OS information
        os_name = None
        os_elem = host_elem.find('.//os/osmatch')
        if os_elem is not None:
            os_name = os_elem.get('name')
        
        # Generate deterministic asset ID using priority: MAC > Hostname > IP
        # This ensures consistent asset tracking across scans
        mac_address = addresses.get('mac')
        asset_id = generate_asset_id(
            mac=mac_address,
            hostname=hostname,
            ip=addresses['ip']
        )
        
        logger.debug(f"Generated asset_id={asset_id} for {addresses['ip']} (mac={mac_address}, hostname={hostname})")
        
        # Extract vendor from MAC address for better device identification
        vendor = get_vendor_from_mac(mac_address)
        if vendor:
            logger.debug(f"Identified device type: {vendor} for MAC {mac_address}")
        
        # Create asset with enriched metadata
        asset = Asset(
            id=asset_id,
            ip=[addresses['ip']],
            mac=mac_address,
            hostname=hostname,
            os=os_name,
            device_type=vendor  # Enhanced: device type from MAC vendor
        )
        
        # Process each open port
        for port_elem in host_elem.findall('.//ports/port'):
            state_elem = port_elem.find('state')
            if state_elem is None or state_elem.get('state') != 'open':
                continue  # Skip non-open ports
            
            # Create event for this open port
            event = self._create_port_event(
                port_elem=port_elem,
                asset=asset,
                office_id=office_id,
                scanner_id=scanner_id,
                scanner_version=scanner_version,
                scan_timestamp=scan_timestamp,
                scan_run_id=scan_run_id
            )
            
            if event:
                events.append(event)
        
        return events
    
    def _extract_addresses(self, host_elem: Element) -> dict:
        """Extract IP and MAC addresses from host element."""
        addresses = {}
        
        for addr_elem in host_elem.findall('.//address'):
            addr_type = addr_elem.get('addrtype')
            addr = addr_elem.get('addr')
            
            if addr_type == 'ipv4' and not addresses.get('ip'):
                addresses['ip'] = addr
            elif addr_type == 'ipv6' and not addresses.get('ip'):
                addresses['ip'] = addr
            elif addr_type == 'mac':
                addresses['mac'] = addr
        
        return addresses
    
    def _create_port_event(
        self,
        port_elem: Element,
        asset: Asset,
        office_id: str,
        scanner_id: str,
        scanner_version: str,
        scan_timestamp: datetime,
        scan_run_id: str | None = None
    ) -> Optional[ExposureEventModel]:
        """Create exposure event for an open port."""
        # Extract port info
        port_num = int(port_elem.get('portid', '0'))
        protocol = port_elem.get('protocol', 'tcp')
        
        # Extract service info
        service_elem = port_elem.find('service')
        service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
        service_product = service_elem.get('product') if service_elem is not None else None
        service_version = service_elem.get('version') if service_elem is not None else None
        service_tunnel = service_elem.get('tunnel') if service_elem is not None else None
        
        # Determine transport
        transport = Transport.TCP if protocol == 'tcp' else Transport.UDP
        
        # Classify exposure
        exposure_class = self._classify_exposure(
            port=port_num,
            service_name=service_name,
            product=service_product,
            tunnel=service_tunnel
        )
        
        logger.debug(f"Classified {asset.ip[0]}:{port_num} ({service_name}) as {exposure_class.value}")
        
        # Classify potential data exposure (enhanced from nmap2nuclei patterns)
        data_classifications = classify_service_data(
            service_name=service_name,
            product=service_product,
            port=port_num,
            version=service_version
        )
        
        if data_classifications:
            logger.debug(f"Data classifications for {asset.ip[0]}:{port_num}: {[dc.value for dc in data_classifications]}")
        
        # Determine severity based on exposure class
        severity = self._calculate_severity(exposure_class, service_name, service_product)
        
        # Generate IDs
        exposure_id = generate_exposure_id(
            office_id=office_id,
            asset_id=asset.id,
            dst_ip=asset.ip[0],
            dst_port=port_num,
            protocol=service_name,
            exposure_class=exposure_class.value
        )
        
        event_id = generate_event_id()
        
        dedupe_key = generate_dedupe_key(
            office_id=office_id,
            asset_id=asset.id,
            dst_ip=asset.ip[0],
            dst_port=port_num,
            protocol=service_name,
            exposure_class=exposure_class.value,
            service_product=service_product
        )
        
        # Infer service binding scope (enhanced)
        bind_scope = self._infer_service_binding(
            service_name=service_name,
            port=port_num,
            asset_ip=asset.ip[0]
        )
        
        # Create service model with enhanced metadata
        service = Service(
            name=service_name,
            product=service_product,
            version=service_version,
            tls=service_tunnel == 'ssl' if service_tunnel else None,
            auth=ServiceAuth.UNKNOWN,  # nmap doesn't detect this reliably
            bind_scope=bind_scope  # Enhanced: inferred from service characteristics
        )
        
        # Create vector
        vector = Vector(
            transport=transport,
            protocol=service_name,
            dst={
                'ip': asset.ip[0],
                'port': port_num
            },
            network_direction=NetworkDirection.INTERNAL  # Assume internal scan
        )
        
        # Create resource (aligned with nmap2nuclei)
        resource_type = self._infer_resource_type(service_name, port_num)
        resource = None
        if resource_type:
            resource = Resource(
                type=resource_type,
                identifier=f"{asset.ip[0]}:{port_num}"
            )
        
        # Create exposure with data classifications
        exposure = Exposure(
            id=exposure_id,
            class_=exposure_class,
            status=ExposureStatus.OPEN,
            vector=vector,
            service=service,
            resource=resource,  # Enhanced: include resource type
            data_class=list(data_classifications) if data_classifications else None,  # Enhanced: data classifications
            first_seen=scan_timestamp,
            last_seen=scan_timestamp
        )
        
        # Create event
        event = Event(
            id=event_id,
            kind=EventKind.EVENT,
            category=['network'],
            type=['info'],
            action=EventAction.EXPOSURE_OPENED,
            severity=severity,
            correlation=EventCorrelation(
                dedupe_key=dedupe_key,
                scan_run_id=scan_run_id
            )
        )
        
        # Create office
        office = Office(
            id=office_id,
            name=f"Office-{office_id}"  # Basic name, can be enriched later
        )
        
        # Create scanner
        scanner = Scanner(
            id=scanner_id,
            type=self.get_scanner_type(),
            version=scanner_version
        )
        
        # Create target
        target = Target(asset=asset)
        
        # Create full event model
        try:
            event_model = ExposureEventModel(
                schema_version=self.schema_version,
                timestamp=scan_timestamp,
                event=event,
                office=office,
                scanner=scanner,
                target=target,
                exposure=exposure
            )
            return event_model
        except Exception as e:
            # Log validation error but don't fail entire scan
            print(f"Validation error creating event: {e}")
            return None
            
    def _infer_service_binding(self, service_name: str, port: int, asset_ip: str) -> ServiceBindScope:
        """
        Infer whether service is bound to loopback, local subnet, or any interface.
        Enhanced detection based on common service patterns and IP address characteristics.
        
        ServiceBindScope values:
        - LOOPBACK_ONLY: 127.0.0.1, ::1, link-local addresses, development services
        - LOCAL_SUBNET: Internal services, private IPs (RFC 1918), Docker networks
        - ANY: Public-facing services on public IPs
        - UNKNOWN: Cannot determine
        """
        service_lower = service_name.lower() if service_name else ''
        
        # Check if IP is localhost - only these can be loopback_only
        is_localhost = asset_ip in ['127.0.0.1', '::1', 'localhost']
        if is_localhost:
            return ServiceBindScope.LOOPBACK_ONLY
        
        # Check for link-local addresses (169.254.0.0/16) - treat as loopback
        if is_link_local(asset_ip):
            return ServiceBindScope.LOOPBACK_ONLY
        
        # Check for multicast addresses - treat as local subnet
        if is_multicast(asset_ip):
            return ServiceBindScope.LOCAL_SUBNET
        
        # Check for Docker bridge network - treat as local subnet
        if is_docker_bridge(asset_ip):
            return ServiceBindScope.LOCAL_SUBNET
        
        # Check if IP is private/internal - these should never be ANY
        is_private = is_private_ip(asset_ip)
        
        # Services commonly bound to internal/local subnet only
        internal_services = {
            'mongodb', 'redis', 'memcached', 'elasticsearch',
            'cassandra', 'rabbitmq', 'kafka', 'zookeeper'
        }
        
        if any(internal in service_lower for internal in internal_services):
            return ServiceBindScope.LOCAL_SUBNET
        
        # Development/debug services (but NOT on localhost)
        # For non-localhost IPs, these are still LOCAL_SUBNET at best
        debug_keywords = {'debug', 'dev', 'test', 'local'}
        if any(kw in service_lower for kw in debug_keywords):
            return ServiceBindScope.LOCAL_SUBNET
        
        # Public-facing services
        public_services = {'http', 'https', 'smtp', 'pop3', 'imap', 'dns'}
        if any(public in service_lower for public in public_services):
            # If on private IP, it's LOCAL_SUBNET even if service is "public"
            if is_private:
                return ServiceBindScope.LOCAL_SUBNET
            else:
                return ServiceBindScope.ANY
        
        # For any other service on private IP
        if is_private:
            return ServiceBindScope.LOCAL_SUBNET
        
        # Default: unknown
        return ServiceBindScope.UNKNOWN
    
    def _infer_resource_type(self, service_name: str, port: int) -> Optional[ResourceType]:
        """
        Infer resource type from service characteristics.
        Aligned with nmap2nuclei.py resource classification.
        Returns ResourceType enum member or None.
        """
        service_lower = service_name.lower() if service_name else ''
        
        # API endpoints
        if any(api in service_lower for api in ['api', 'rest', 'graphql', 'grpc']):
            return ResourceType.API_ENDPOINT
        
        # File shares
        if any(share in service_lower for share in ['smb', 'cifs', 'nfs', 'ftp']):
            if 'smb' in service_lower or port in [445, 139]:
                return ResourceType.SMB_SHARE
            elif 'nfs' in service_lower or port == 2049:
                return ResourceType.NFS_EXPORT
            # FTP doesn't have specific ResourceType, use None
        
        # VCS
        if any(vcs in service_lower for vcs in ['git', 'svn', 'cvs']):
            return ResourceType.REPO
        
        # HTTP services
        if 'http' in service_lower or port in [80, 443, 8080, 8000, 8888]:
            return ResourceType.HTTP_PATH
        
        # mDNS services
        if port == 5353 or 'mdns' in service_lower:
            return ResourceType.MDNS_SERVICE
        
        # Domain services (DNS)
        if port == 53 or 'dns' in service_lower or 'domain' in service_lower:
            return ResourceType.DOMAIN
        
        # Default: no specific resource type (generic network service)
        return None
    
    def _classify_exposure(
        self,
        port: int,
        service_name: str,
        product: Optional[str],
        tunnel: Optional[str]
    ) -> ExposureClass:
        """
        Classify exposure based on port, service, and product.
        
        Classification rules from plan:
        - 445/548 + smb → fileshare_exposed
        - 22 + ssh → remote_admin_exposed
        - 3389 + rdp → remote_admin_exposed
        - 5900 + vnc → remote_admin_exposed
        - 80/443/8080 + http → http_content_leak (requires secondary probe)
        - 2375/2376 + docker → container_api_exposed
        - 6443 + ssl/kubernetes → container_api_exposed
        - 3306/5432/27017/6379 → db_exposed
        - 9418 + git → vcs_protocol_exposed
        - Unknown → unknown_service_exposed
        """
        service_lower = service_name.lower()
        product_lower = product.lower() if product else ''
        
        # File sharing (enhanced detection)
        if port in [137, 138, 139, 445, 548, 2049] or any(x in service_lower for x in ['smb', 'microsoft-ds', 'cifs', 'netbios-ssn', 'netbios-ns', 'netbios-dgm', 'nfs']):
            return ExposureClass.FILESHARE_EXPOSED
        
        # Remote administration (enhanced with more protocols)
        if port == 22 or service_lower == 'ssh':
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        if port == 3389 or service_lower in ['rdp', 'ms-wbt-server', 'ms-term-serv']:
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        if port in [5900, 5901, 5902] or 'vnc' in service_lower:
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        if port == 23 or service_lower == 'telnet':
            return ExposureClass.REMOTE_ADMIN_EXPOSED  # Telnet is also remote admin
        
        # Container APIs
        if port in [2375, 2376] or 'docker' in service_lower or 'docker' in product_lower:
            return ExposureClass.CONTAINER_API_EXPOSED
        if port == 6443 or 'kubernetes' in service_lower or 'k8s' in service_lower:
            return ExposureClass.CONTAINER_API_EXPOSED
        
        # Databases (enhanced with more database types)
        # Check service name FIRST (more reliable than port alone)
        database_keywords = ['mysql', 'postgresql', 'postgres', 'mongodb', 
                            'redis', 'mssql', 'oracle', 'cassandra', 
                            'elasticsearch', 'couchdb', 'influxdb', 'mariadb']
        
        if any(db in service_lower for db in database_keywords):
            return ExposureClass.DB_EXPOSED
        
        # Well-known database ports (unambiguous)
        unambiguous_db_ports = {
            3306,   # MySQL/MariaDB
            5432,   # PostgreSQL
            27017,  # MongoDB
            6379,   # Redis
            1433,   # MS SQL Server
            1521,   # Oracle
            5984,   # CouchDB
        }
        
        if port in unambiguous_db_ports:
            return ExposureClass.DB_EXPOSED
        
        # Ambiguous port 7000 - only classify as DB if service suggests Cassandra
        # Port 7000: Cassandra, but also AirTunes/AFS/RTSP
        # Ports 8086 and 9200 removed - too ambiguous, rely solely on service name detection
        if port == 7000:
            # Only treat as database if service name suggests Cassandra
            if 'cassandra' in service_lower or 'cassandra' in product_lower:
                return ExposureClass.DB_EXPOSED
            # Otherwise, continue to other classification rules
        
        # VCS protocols
        if port == 9418 or service_lower == 'git':
            return ExposureClass.VCS_PROTOCOL_EXPOSED
        
        # mDNS/Bonjour service advertisement (aligned with nmap2nuclei)
        if port == 5353 or 'mdns' in service_lower or 'bonjour' in service_lower:
            return ExposureClass.SERVICE_ADVERTISED_MDNS
        
        # Media streaming services (RTSP, AirTunes, etc.)
        streaming_keywords = ['rtsp', 'airtunes', 'airplay', 'raop', 'streaming']
        if any(kw in service_lower for kw in streaming_keywords):
            return ExposureClass.MEDIA_STREAMING_EXPOSED
        
        # Monitoring and observability services
        monitoring_keywords = ['prometheus', 'grafana', 'kibana', 'datadog', 'metrics', 'monitoring']
        monitoring_ports = {3000, 3333, 5601, 9090, 9091, 9115, 16686}  # Grafana, Kibana, Prometheus, Jaeger
        if any(kw in service_lower or kw in product_lower for kw in monitoring_keywords) or port in monitoring_ports:
            return ExposureClass.MONITORING_EXPOSED
        
        # Cache services
        cache_keywords = ['memcached', 'varnish', 'cache']
        cache_ports = {11211, 11212}  # Memcached
        if any(kw in service_lower or kw in product_lower for kw in cache_keywords) or port in cache_ports:
            return ExposureClass.CACHE_EXPOSED
        
        # Message queues and streaming platforms
        queue_keywords = ['rabbitmq', 'kafka', 'activemq', 'zeromq', 'queue', 'amqp']
        queue_ports = {5672, 9092, 61616, 25672}  # RabbitMQ, Kafka, ActiveMQ
        if any(kw in service_lower or kw in product_lower for kw in queue_keywords) or port in queue_ports:
            return ExposureClass.QUEUE_EXPOSED
        
        # Distributed file systems (AFS, etc.)
        # These should be fileshare, not database
        if 'afs' in service_lower or service_lower in ['afs3-fileserver', 'afs3-callback']:
            return ExposureClass.FILESHARE_EXPOSED
        
        # HTTP services (potential content leaks) - enhanced detection
        http_ports = {80, 443, 8000, 8080, 8008, 8888, 8443, 9000, 9090, 3000, 4200, 5000}
        if port in http_ports or 'http' in service_lower or 'www' in service_lower:
            return ExposureClass.HTTP_CONTENT_LEAK
        
        # Debug/development ports (enhanced)
        debug_ports = {
            9222: 'Chrome DevTools',
            6000: 'X11',
            63342: 'IntelliJ',
            5037: 'Android Debug Bridge',
            9229: 'Node.js debug',
            5005: 'Java debug',
            4444: 'Selenium',
            9515: 'ChromeDriver'
        }
        
        if port in debug_ports:
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # Jenkins
        if port in [50000] or 'jenkins' in product_lower:
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # Dev tool proxies (Postman, JMeter)
        if port in [5555, 5559, 1099]:
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # Default: unknown service
        return ExposureClass.UNKNOWN_SERVICE_EXPOSED
    
    def _calculate_severity(
        self,
        exposure_class: ExposureClass,
        service_name: str,
        product: Optional[str]
    ) -> int:
        """
        Calculate severity score (0-100) based on exposure class and context.
        
        Severity levels:
        - Critical (80-100): Databases, container APIs, unauthenticated admin
        - High (60-79): Remote admin, file shares
        - Medium (40-59): Debug ports, HTTP services
        - Low (20-39): Unknown services
        """
        severity_map = {
            ExposureClass.DB_EXPOSED: 90,
            ExposureClass.CONTAINER_API_EXPOSED: 85,
            ExposureClass.QUEUE_EXPOSED: 80,  # Message queues can expose sensitive data
            ExposureClass.CACHE_EXPOSED: 75,  # Can lead to data leaks or DoS
            ExposureClass.REMOTE_ADMIN_EXPOSED: 70,
            ExposureClass.FILESHARE_EXPOSED: 65,
            ExposureClass.DEBUG_PORT_EXPOSED: 60,
            ExposureClass.VCS_PROTOCOL_EXPOSED: 55,
            ExposureClass.HTTP_CONTENT_LEAK: 50,
            ExposureClass.MONITORING_EXPOSED: 45,  # Can leak infrastructure info
            ExposureClass.EGRESS_TUNNEL_INDICATOR: 45,
            ExposureClass.SERVICE_ADVERTISED_MDNS: 40,
            ExposureClass.MEDIA_STREAMING_EXPOSED: 35,  # Generally lower risk
            ExposureClass.UNKNOWN_SERVICE_EXPOSED: 30,
        }
        
        base_severity = severity_map.get(exposure_class, 30)
        
        # Adjust for specific high-risk products
        if product:
            product_lower = product.lower()
            if any(keyword in product_lower for keyword in ['docker', 'kubernetes', 'jenkins']):
                base_severity = min(base_severity + 10, 100)
        
        return base_severity
