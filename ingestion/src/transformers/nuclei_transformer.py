"""
Nuclei JSON output transformer to canonical exposure events.
Enhanced with comprehensive error handling and validation.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import re

from src.models.canonical import (
    ExposureEventModel, Event, Office, Scanner, Target, Asset,
    Exposure, Vector, Service, EventCorrelation, Resource,
    EventKind, EventAction, ExposureClass, ExposureStatus,
    Transport, ServiceAuth, ServiceBindScope, NetworkDirection,
    ResourceType, DataClassification
)
from src.transformers.base import BaseTransformer, TransformerError
from src.utils.id_generation import generate_asset_id, generate_event_id, generate_exposure_id, generate_dedupe_key

# Initialize logger
logger = logging.getLogger(__name__)


# Maximum JSON file size: 10MB
MAX_JSON_SIZE_BYTES = 10 * 1024 * 1024


class NucleiTransformer(BaseTransformer):
    """Transforms nuclei JSON output to canonical exposure events."""
    
    def __init__(self, schema_version: str = "1.0.0"):
        self.schema_version = schema_version
    
    def get_scanner_type(self) -> str:
        """Return the scanner type identifier."""
        return "nuclei"
    
    def transform(
        self,
        file_path: Path,
        office_id: str,
        scanner_id: str,
        scan_run_id: str | None = None
    ) -> List[ExposureEventModel]:
        """
        Transform nuclei JSON file to canonical events.
        
        Args:
            file_path: Path to nuclei JSON file
            office_id: Office identifier
            scanner_id: Scanner instance identifier
            scan_run_id: Optional scan run identifier for correlation
        
        Returns:
            List of exposure events (one per finding)
        
        Raises:
            TransformerError: If parsing or transformation fails
        """
        try:
            findings = self._parse_json_safely(file_path)
        except Exception as e:
            raise TransformerError(f"Failed to parse nuclei JSON: {e}") from e
        
        # Validate it's a list
        if not isinstance(findings, list):
            raise TransformerError(
                f"Expected JSON array, got {type(findings).__name__}"
            )
        
        # Process each finding with error tracking
        # Use dict to track first occurrence of each exposure_id and aggregate duplicates
        exposure_map = {}  # exposure_id -> (event, [finding_indices])
        scan_timestamp = datetime.now(timezone.utc)
        
        total_findings = len(findings)
        processed_count = 0
        error_count = 0
        skipped_count = 0
        duplicate_count = 0
        
        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                logger.warning(f"Skipping non-dict finding at index {idx}: {type(finding)}")
                skipped_count += 1
                continue
            
            try:
                event = self._process_finding(
                    finding=finding,
                    office_id=office_id,
                    scanner_id=scanner_id,
                    scan_timestamp=scan_timestamp,
                    scan_run_id=scan_run_id
                )
                
                if event:
                    exposure_id = event.exposure.id
                    
                    if exposure_id not in exposure_map:
                        # First occurrence of this exposure_id
                        template_id = finding.get('template-id', 'unknown')
                        exposure_map[exposure_id] = {
                            'event': event,
                            'indices': [idx],
                            'finding_count': 1,
                            'max_severity': event.event.severity,
                            'templates': [template_id],
                            'original_severity': event.event.severity
                        }
                        processed_count += 1
                    else:
                        # Duplicate exposure_id - aggregate metadata
                        duplicate_count += 1
                        template_id = finding.get('template-id', 'unknown')
                        host = finding.get('host', 'unknown')
                        logger.debug(
                            f"Deduplicating finding {idx+1}/{total_findings}: "
                            f"exposure_id={exposure_id[:16]}... already exists "
                            f"(template={template_id}, host={host})"
                        )
                        
                        # Aggregate metadata from duplicate finding
                        existing = exposure_map[exposure_id]
                        existing['indices'].append(idx)
                        existing['finding_count'] += 1
                        existing['templates'].append(template_id)
                        
                        # Track highest severity from all merged findings
                        if event.event.severity > existing['max_severity']:
                            existing['max_severity'] = event.event.severity
                else:
                    skipped_count += 1
                    
            except Exception as e:
                error_count += 1
                template_id = finding.get('template-id', 'unknown')
                host = finding.get('host', 'unknown')
                logger.error(f"Error processing finding {idx+1}/{total_findings} (template={template_id}, host={host}): {e}", exc_info=True)
                # Continue processing other findings
                continue
        
        # Extract unique events and inject aggregation metadata
        events = []
        for exposure_id, data in exposure_map.items():
            event = data['event']
            
            # Create aggregation metadata if findings were merged
            if data['finding_count'] > 1:
                aggregation_metadata = {
                    'finding_count': data['finding_count'],
                    'max_severity': data['max_severity'],
                    'original_severity': data['original_severity'],
                    'merged_templates': data['templates']
                }
                
                # Inject metadata into event using object.__setattr__ to bypass Pydantic validation
                # This will be picked up by the storage layer and added to raw_payload_json
                object.__setattr__(event, '_ctem_aggregation', aggregation_metadata)
                
                # Update event severity to reflect the highest severity from merged findings
                if data['max_severity'] > data['original_severity']:
                    event.event.severity = data['max_severity']
                    logger.debug(
                        f"Updated severity for exposure {exposure_id[:16]}... from "
                        f"{data['original_severity']} to {data['max_severity']} "
                        f"(merged {data['finding_count']} findings)"
                    )
            
            events.append(event)
        
        # Log summary statistics
        logger.info(
            f"Nuclei transformation complete: {processed_count} unique events, "
            f"{duplicate_count} duplicates merged, {skipped_count} skipped, "
            f"{error_count} errors (total {total_findings} findings)"
        )
        
        if duplicate_count > 0:
            logger.info(f"Deduplicated {duplicate_count} findings with identical exposure_ids")
        
        return events
    
    def _parse_json_safely(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse JSON file with size limits for security.
        
        Args:
            file_path: Path to JSON file
        
        Returns:
            Parsed JSON data
        
        Raises:
            TransformerError: If file is too large or invalid JSON
        """
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > MAX_JSON_SIZE_BYTES:
            raise TransformerError(
                f"JSON file too large: {file_size} bytes (max: {MAX_JSON_SIZE_BYTES})"
            )
        
        # Parse JSON
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _process_finding(
        self,
        finding: Dict[str, Any],
        office_id: str,
        scanner_id: str,
        scan_timestamp: datetime,
        scan_run_id: str | None = None
    ) -> Optional[ExposureEventModel]:
        """Process a single nuclei finding and generate an event."""
        try:
            # Extract basic info
            template_id = finding.get('template-id', 'unknown')
            info = finding.get('info', {})
            finding_type = finding.get('type', 'unknown')
            host = finding.get('host', '')
            matched_at = finding.get('matched-at', host)
            
            # Extract info fields
            name = info.get('name', template_id)
            severity = info.get('severity', 'info')
            tags = info.get('tags', [])
            
            # Use timestamp from finding if available
            timestamp_str = finding.get('timestamp')
            if timestamp_str:
                try:
                    finding_timestamp = datetime.fromisoformat(
                        timestamp_str.replace('Z', '+00:00')
                    )
                except (ValueError, AttributeError):
                    finding_timestamp = scan_timestamp
            else:
                finding_timestamp = scan_timestamp
            
            # Parse host information
            host_info = self._extract_host_info(host)
            if not host_info.get('ip'):
                logger.warning(f"Could not extract IP from host: {host}")
                return None
            
            # Extract enrichment metadata if available (from nmap2nuclei.py)
            enrichment = finding.get('_ctem_enrichment', {})
            
            # Validate enrichment structure if present
            if enrichment and not isinstance(enrichment, dict):
                logger.warning(f"Invalid enrichment data type: {type(enrichment)} for finding: {finding.get('template-id', 'unknown')}")
                enrichment = {}
            
            # Extract MAC, hostname, and OS from enrichment with validation
            mac_address = None
            hostname = None
            os_name = None
            
            try:
                mac_address = enrichment.get('mac')
                if mac_address and not isinstance(mac_address, str):
                    logger.warning(f"Invalid MAC address type: {type(mac_address)}, ignoring")
                    mac_address = None
                
                hostname = enrichment.get('hostname') or host_info.get('hostname')
                if hostname and not isinstance(hostname, str):
                    logger.warning(f"Invalid hostname type: {type(hostname)}, ignoring")
                    hostname = None
                
                os_name = enrichment.get('os')
                if os_name and not isinstance(os_name, str):
                    logger.warning(f"Invalid OS type: {type(os_name)}, ignoring")
                    os_name = None
                    
                # Log enrichment status for monitoring
                enrichment_fields = sum([
                    1 if mac_address else 0,
                    1 if hostname and hostname != host_info.get('ip') else 0,
                    1 if os_name else 0
                ])
                if enrichment_fields > 0:
                    logger.debug(f"Enrichment: {enrichment_fields}/3 fields populated for {host_info['ip']}")
                else:
                    logger.debug(f"No enrichment data for {host_info['ip']}")
                    
            except Exception as e:
                logger.error(f"Error parsing enrichment data: {e}", exc_info=True)
                # Continue with empty enrichment data
            
            # Generate deterministic asset ID using priority: MAC > Hostname > IP
            # This ensures same device across nmap and nuclei scans gets same asset_id
            try:
                asset_id = generate_asset_id(
                    mac=mac_address,
                    hostname=hostname,
                    ip=host_info['ip']
                )
                logger.debug(f"Generated asset_id={asset_id} for {host_info['ip']} (mac={mac_address}, hostname={hostname})")
            except Exception as e:
                logger.error(f"Error generating asset ID: {e}", exc_info=True)
                return None
            
            # Create asset
            try:
                asset = Asset(
                    id=asset_id,
                    ip=[host_info['ip']],
                    mac=mac_address,  # Real MAC or None
                    hostname=hostname,
                    os=os_name
                )
            except Exception as e:
                logger.error(f"Error creating asset: {e}", exc_info=True)
                return None
            
            # Extract service info from enrichment for better classification
            service_info = finding.get('_service', {})
            service_name = service_info.get('service', '')
            port_num = host_info.get('port', 0)
            
            # Classify exposure (enhanced with enrichment data)
            exposure_class = self._classify_exposure_enhanced(
                severity=severity,
                tags=tags,
                template_id=template_id,
                finding_type=finding_type,
                enrichment_service=service_name,
                port=port_num
            )
            
            # Calculate severity score
            severity_score = self._calculate_severity(severity, exposure_class)
            
            # Extract service information
            extracted_results = finding.get('extracted-results', [])
            service_product = None
            service_version = None
            
            if extracted_results:
                # Try to parse version from first extracted result
                result_str = str(extracted_results[0]) if extracted_results else None
                if result_str:
                    # Look for version patterns like "v8.0" or "8.0"
                    version_match = re.search(r'v?(\d+\.\d+(?:\.\d+)?)', result_str)
                    if version_match:
                        service_version = version_match.group(1)
                    service_product = result_str
            
            # Determine protocol and transport
            protocol = host_info.get('protocol', finding_type)
            
            # Use enrichment transport if available, otherwise intelligent default
            transport_str = enrichment.get('transport', 'tcp').lower()
            
            if transport_str == 'udp':
                transport = Transport.UDP
            elif transport_str == 'icmp':
                transport = Transport.ICMP
            else:
                transport = Transport.TCP
            
            service_product = info.get('name', template_id)
            description = info.get('description', '').strip()

            # Combine name and description for service_product
            if description and len(description) > 0:
                # Truncate description to keep field size reasonable
                desc_short = description[:150] + '...' if len(description) > 150 else description
                service_product = f"{service_product} | {desc_short}"

            # Infer service binding scope (aligned with nmap)
            bind_scope = self._infer_service_binding(
                service_name=service_name,
                port=port_num,
                asset_ip=host_info['ip']
            )
            
            # Create service model
            service = Service(
                name=template_id,
                product=service_product,  # Now includes description
                version=service_version,
                tls=protocol == 'https',
                auth=ServiceAuth.UNKNOWN,
                bind_scope=bind_scope
            )
            
            # Create vector
            vector = Vector(
                transport=transport,
                protocol=protocol,
                dst={
                    'ip': host_info['ip'],
                    'port': host_info.get('port')
                },
                network_direction=NetworkDirection.INTERNAL
            )
            
            # Extract service name from enrichment (already available at line 287)
            service_name = service_info.get('service', template_id)  # fallback to template_id

            # Generate IDs
            exposure_id = generate_exposure_id(
                office_id=office_id,
                asset_id=asset.id,
                dst_ip=host_info['ip'],
                dst_port=host_info.get('port', 0),
                protocol=service_name,  # ← Use "http" not "tech-detect"
                exposure_class=exposure_class.value
            )
            
            event_id = generate_event_id()
            
            dedupe_key = generate_dedupe_key(
                office_id=office_id,
                asset_id=asset.id,
                dst_ip=host_info['ip'],
                dst_port=host_info.get('port', 0),
                protocol=template_id,
                exposure_class=exposure_class.value,
                service_product=service_product
            )
            
            # Create resource model if enrichment provides resource info
            resource = None
            if enrichment.get('resource_type') and enrichment.get('resource_identifier'):
                from hashlib import sha256
                evidence = f"{enrichment['resource_identifier']}:{template_id}:{finding_type}"
                resource = Resource(
                    type=ResourceType(enrichment['resource_type']),
                    identifier=enrichment['resource_identifier'],
                    evidence_hash=sha256(evidence.encode()).hexdigest()[:16]
                )
            
            # Extract data classifications
            data_class = None
            if enrichment.get('data_classifications'):
                # Map string classifications to enum
                data_class = []
                for dc in enrichment['data_classifications']:
                    try:
                        data_class.append(DataClassification(dc.lower()))
                    except ValueError:
                        # If not a valid enum value, skip
                        pass
            
            # Create exposure
            exposure = Exposure(
                id=exposure_id,
                class_=exposure_class,
                status=ExposureStatus.OPEN,
                vector=vector,
                service=service,
                resource=resource,  # Now populated!
                data_class=data_class,  # Now populated!
                first_seen=finding_timestamp,
                last_seen=finding_timestamp
            )
            
            # Create event
            event = Event(
                id=event_id,
                kind=EventKind.EVENT,
                category=['network'],
                type=['info'],
                action=EventAction.EXPOSURE_OPENED,
                severity=severity_score,
                correlation=EventCorrelation(
                dedupe_key=dedupe_key,
                scan_run_id=scan_run_id
            )
            )
            
            # Create office
            office = Office(
                id=office_id,
                name=f"Office-{office_id}"
            )
            
            # Create scanner
            scanner = Scanner(
                id=scanner_id,
                type=self.get_scanner_type(),
                version="unknown"  # Nuclei doesn't provide scanner version in output
            )
            
            # Create target
            target = Target(asset=asset)
            
            # Create full event model
            event_model = ExposureEventModel(
                schema_version=self.schema_version,
                timestamp=finding_timestamp,
                event=event,
                office=office,
                scanner=scanner,
                target=target,
                exposure=exposure
            )
            
            return event_model
            
        except Exception as e:
            # Log validation error but don't fail entire scan
            print(f"Error creating event for finding {finding.get('template-id', 'unknown')}: {e}")
            return None
    
    def _extract_host_info(self, host_url: str) -> Dict[str, Any]:
        """
        Extract IP, port, hostname, and protocol from host URL.
        
        Args:
            host_url: URL string (e.g., "http://10.0.2.131:80", "tcp://192.168.1.5:3306")
        
        Returns:
            Dict with keys: ip, port, hostname, protocol
        """
        host_info = {}
        
        try:
            parsed = urlparse(host_url)
            
            # Extract protocol
            host_info['protocol'] = parsed.scheme or 'unknown'
            
            # Extract hostname (could be IP or domain)
            hostname = parsed.hostname or parsed.netloc.split(':')[0]
            
            # Check if hostname is an IP address
            if self._is_ip_address(hostname):
                host_info['ip'] = hostname
            else:
                host_info['hostname'] = hostname
                # If not an IP, we still need an IP for asset.id
                # Use hostname as fallback
                host_info['ip'] = hostname
            
            # Extract port
            if parsed.port:
                host_info['port'] = parsed.port
            else:
                # Default ports based on protocol
                default_ports = {
                    'http': 80,
                    'https': 443,
                    'ftp': 21,
                    'ssh': 22,
                    'telnet': 23,
                    'smtp': 25,
                    'dns': 53,
                }
                host_info['port'] = default_ports.get(parsed.scheme)
            
        except Exception as e:
            print(f"Warning: Failed to parse host URL '{host_url}': {e}")
            # Try simple regex as fallback
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', host_url)
            if ip_match:
                host_info['ip'] = ip_match.group(1)
            
            port_match = re.search(r':(\d+)', host_url)
            if port_match:
                host_info['port'] = int(port_match.group(1))
        
        return host_info
    
    def _is_ip_address(self, s: str) -> bool:
        """Check if string is an IPv4 address."""
        try:
            parts = s.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False
    
    def _classify_exposure(
        self,
        severity: str,
        tags: List[str],
        template_id: str,
        finding_type: str
    ) -> ExposureClass:
        """
        Classify exposure based on nuclei finding attributes.
        
        Args:
            severity: Nuclei severity (critical, high, medium, low, info)
            tags: List of template tags
            template_id: Template identifier
            finding_type: Type of finding (http, dns, network, etc.)
        
        Returns:
            ExposureClass enum value
        """
        # Convert to lowercase for comparison
        tags_lower = [tag.lower() for tag in tags]
        template_lower = template_id.lower()
        
        # Database exposures
        if any(keyword in tags_lower for keyword in ['database', 'mongodb', 'mysql', 'postgresql', 'redis', 'db']):
            return ExposureClass.DB_EXPOSED
        
        # Container APIs (check before debug panels since k8s dashboard should be container)
        if any(keyword in tags_lower for keyword in ['docker', 'kubernetes', 'k8s', 'container']):
            return ExposureClass.CONTAINER_API_EXPOSED
        
        # Remote admin interfaces
        if any(keyword in tags_lower for keyword in ['admin', 'ssh', 'rdp', 'vnc', 'telnet']):
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        
        # Debug/admin panels
        if any(keyword in template_lower for keyword in ['debug', 'console', 'panel', 'dashboard']):
            return ExposureClass.DEBUG_PORT_EXPOSED
        if any(keyword in tags_lower for keyword in ['debug', 'console', 'panel']):
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # File shares
        if any(keyword in tags_lower for keyword in ['smb', 'nfs', 'ftp', 'fileshare']):
            return ExposureClass.FILESHARE_EXPOSED
        
        # VCS protocols
        if any(keyword in tags_lower for keyword in ['git', 'svn', 'cvs', 'vcs']):
            return ExposureClass.VCS_PROTOCOL_EXPOSED
        
        # HTTP content leaks (exposure, disclosure, leak tags)
        if any(keyword in tags_lower for keyword in ['exposure', 'disclosure', 'leak', 'exposure']):
            return ExposureClass.HTTP_CONTENT_LEAK
        
        # mDNS service advertisement
        if any(keyword in tags_lower for keyword in ['mdns', 'bonjour', 'zeroconf']):
            return ExposureClass.SERVICE_ADVERTISED_MDNS
        
        # Egress tunnel indicators
        if any(keyword in tags_lower for keyword in ['tunnel', 'proxy', 'socks', 'vpn']):
            return ExposureClass.EGRESS_TUNNEL_INDICATOR
        
        # Default to unknown service exposed
        return ExposureClass.UNKNOWN_SERVICE_EXPOSED
    
    def _classify_exposure_enhanced(
        self,
        severity: str,
        tags: List[str],
        template_id: str,
        finding_type: str,
        enrichment_service: str = '',
        port: int = 0
    ) -> ExposureClass:
        """
        Enhanced exposure classification using enrichment data.
        
        Uses enrichment service name and port to align classification with nmap,
        while still respecting nuclei template-specific detections.
        
        Args:
            severity: Nuclei severity (critical, high, medium, low, info)
            tags: List of template tags
            template_id: Template identifier
            finding_type: Type of finding (http, dns, network, etc.)
            enrichment_service: Service name from nmap enrichment (_service.service)
            port: Port number from enrichment
        
        Returns:
            ExposureClass enum value
        """
        # Convert to lowercase for comparison
        tags_lower = [tag.lower() for tag in tags]
        template_lower = template_id.lower()
        service_lower = enrichment_service.lower() if enrichment_service else ''
        
        # Priority 1: Nuclei template-specific detections (highest confidence)
        # These indicate specific vulnerabilities/misconfigurations found by nuclei
        
        # Debug/admin panels (from template or tags - very specific)
        if any(keyword in template_lower for keyword in ['debug', 'console', 'panel', 'dashboard']):
            return ExposureClass.DEBUG_PORT_EXPOSED
        if any(keyword in tags_lower for keyword in ['debug', 'console', 'panel']):
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # Database exposures (from tags)
        if any(keyword in tags_lower for keyword in ['database', 'mongodb', 'mysql', 'postgresql', 'redis', 'db']):
            return ExposureClass.DB_EXPOSED
        
        # Container APIs (from tags)
        if any(keyword in tags_lower for keyword in ['docker', 'kubernetes', 'k8s', 'container']):
            return ExposureClass.CONTAINER_API_EXPOSED
        
        # Remote admin interfaces (from tags)
        if any(keyword in tags_lower for keyword in ['admin', 'ssh', 'rdp', 'vnc', 'telnet']):
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        
        # File shares (from tags)
        if any(keyword in tags_lower for keyword in ['smb', 'nfs', 'ftp', 'fileshare']):
            return ExposureClass.FILESHARE_EXPOSED
        
        # VCS protocols (from tags)
        if any(keyword in tags_lower for keyword in ['git', 'svn', 'cvs', 'vcs']):
            return ExposureClass.VCS_PROTOCOL_EXPOSED
        
        # mDNS (from tags)
        if any(keyword in tags_lower for keyword in ['mdns', 'bonjour', 'zeroconf']):
            return ExposureClass.SERVICE_ADVERTISED_MDNS
        
        # Egress tunnel indicators (from tags)
        if any(keyword in tags_lower for keyword in ['tunnel', 'proxy', 'socks', 'vpn']):
            return ExposureClass.EGRESS_TUNNEL_INDICATOR
        
        # HTTP content leaks (from tags - specific exposure/leak detection)
        if any(keyword in tags_lower for keyword in ['exposure', 'disclosure', 'leak']):
            return ExposureClass.HTTP_CONTENT_LEAK
        
        # Message queues (from tags)
        if any(keyword in tags_lower for keyword in ['kafka', 'rabbitmq', 'activemq', 'amqp', 'queue']):
            return ExposureClass.QUEUE_EXPOSED
        
        # Cache services (from tags)
        if any(keyword in tags_lower for keyword in ['memcached', 'redis-cache', 'varnish', 'cache']):
            return ExposureClass.CACHE_EXPOSED
        
        # Monitoring services (from tags)
        if any(keyword in tags_lower for keyword in ['prometheus', 'grafana', 'kibana', 'monitoring', 'metrics']):
            return ExposureClass.MONITORING_EXPOSED
        
        # Media streaming (from tags)
        if any(keyword in tags_lower for keyword in ['rtsp', 'streaming', 'media']):
            return ExposureClass.MEDIA_STREAMING_EXPOSED
        
        # Priority 2: Enrichment service names (reliable, from nmap)
        # These help align nuclei with nmap when enrichment is available
        
        # Databases (from enrichment service)
        database_keywords = ['mysql', 'postgresql', 'postgres', 'mongodb', 
                            'redis', 'mssql', 'oracle', 'cassandra', 
                            'elasticsearch', 'couchdb', 'influxdb', 'mariadb']
        if any(db in service_lower for db in database_keywords):
            return ExposureClass.DB_EXPOSED
        
        # Remote administration (from enrichment service)
        if service_lower in ['ssh', 'rdp', 'ms-wbt-server', 'ms-term-serv', 'vnc', 'telnet']:
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        
        # File sharing (from enrichment service)
        if service_lower in ['smb', 'microsoft-ds', 'cifs', 'netbios-ssn', 'nfs', 'ftp']:
            return ExposureClass.FILESHARE_EXPOSED
        
        # Container APIs
        if 'docker' in service_lower or 'kubernetes' in service_lower:
            return ExposureClass.CONTAINER_API_EXPOSED
        
        # Media streaming
        if service_lower in ['rtsp', 'airtunes', 'airplay', 'raop']:
            return ExposureClass.MEDIA_STREAMING_EXPOSED
        
        # Monitoring services
        monitoring_keywords = ['prometheus', 'grafana', 'kibana', 'datadog', 'metrics']
        if any(kw in service_lower for kw in monitoring_keywords):
            return ExposureClass.MONITORING_EXPOSED
        
        # Cache services
        if service_lower in ['memcached', 'varnish']:
            return ExposureClass.CACHE_EXPOSED
        
        # Message queues
        queue_keywords = ['rabbitmq', 'kafka', 'activemq', 'amqp']
        if any(kw in service_lower for kw in queue_keywords):
            return ExposureClass.QUEUE_EXPOSED
        
        # VCS protocols
        if service_lower == 'git':
            return ExposureClass.VCS_PROTOCOL_EXPOSED
        
        # mDNS service advertisement
        if 'mdns' in service_lower:
            return ExposureClass.SERVICE_ADVERTISED_MDNS
        
        # Priority 3: Well-known port-based classification (for enrichment without nuclei tags)
        # Only classify by port if we have enrichment data and no specific tag detection
        
        # Critical database ports (unambiguous)
        if port in [3306, 5432, 27017, 6379, 1433, 1521, 5984]:
            return ExposureClass.DB_EXPOSED
        
        # Remote admin ports (unambiguous)
        if port in [22, 3389, 5900, 5901, 5902, 23]:
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        
        # File share ports
        if port in [445, 548, 139, 2049]:
            return ExposureClass.FILESHARE_EXPOSED
        
        # Container API ports
        if port in [2375, 2376, 6443]:
            return ExposureClass.CONTAINER_API_EXPOSED
        
        # Monitoring ports
        if port in [3000, 3333, 5601, 9090, 9091, 9115]:
            return ExposureClass.MONITORING_EXPOSED
        
        # Cache ports
        if port in [11211, 11212]:
            return ExposureClass.CACHE_EXPOSED
        
        # Message queue ports
        if port in [5672, 9092, 61616, 25672]:
            return ExposureClass.QUEUE_EXPOSED
        
        # VCS ports
        if port == 9418:
            return ExposureClass.VCS_PROTOCOL_EXPOSED
        
        # mDNS port
        if port == 5353:
            return ExposureClass.SERVICE_ADVERTISED_MDNS
        
        # Priority 4: Generic HTTP classification (only if no specific detection above)
        # This is the least specific - generic HTTP service detection
        if service_lower in ['http', 'https', 'http-proxy', 'ssl/http', 'http-alt']:
            return ExposureClass.HTTP_CONTENT_LEAK
        if port in [80, 443, 8000, 8080, 8008, 8888, 8443]:
            return ExposureClass.HTTP_CONTENT_LEAK
        
        # Default to unknown service exposed
        return ExposureClass.UNKNOWN_SERVICE_EXPOSED
    
    def _infer_service_binding(
        self,
        service_name: str,
        port: int,
        asset_ip: str
    ) -> ServiceBindScope:
        """
        Infer service binding scope (aligned with nmap logic).
        
        Args:
            service_name: Service name from enrichment
            port: Port number
            asset_ip: Asset IP address
        
        Returns:
            ServiceBindScope enum value
        """
        service_lower = service_name.lower() if service_name else ''
        
        # Check if IP is localhost
        if asset_ip in ['127.0.0.1', '::1', 'localhost']:
            return ServiceBindScope.LOOPBACK_ONLY
        
        # Check if IP is private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        is_private = self._is_private_ip(asset_ip)
        
        # Services commonly bound to internal/local subnet only
        internal_services = {
            'mongodb', 'redis', 'memcached', 'elasticsearch',
            'cassandra', 'rabbitmq', 'kafka', 'zookeeper'
        }
        
        if any(internal in service_lower for internal in internal_services):
            return ServiceBindScope.LOCAL_SUBNET
        
        # Development/debug services
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
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private address space."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # 10.0.0.0/8
            if first_octet == 10:
                return True
            
            # 172.16.0.0/12
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
            
            # 192.168.0.0/16
            if first_octet == 192 and second_octet == 168:
                return True
            
            return False
        except (ValueError, IndexError):
            return False
    
    def _calculate_severity(
        self,
        nuclei_severity: str,
        exposure_class: ExposureClass
    ) -> int:
        """
        Calculate severity score (0-100) based on nuclei severity and exposure class.
        
        Args:
            nuclei_severity: Nuclei severity level (critical, high, medium, low, info)
            exposure_class: Classified exposure class
        
        Returns:
            Severity score (0-100)
        """
        # Base severity from nuclei
        severity_map = {
            'critical': 95,
            'high': 80,
            'medium': 60,
            'low': 40,
            'info': 20,
            'unknown': 30
        }
        
        base_severity = severity_map.get(nuclei_severity.lower(), 30)
        
        # Adjust based on exposure class if it's more severe
        # Severity map aligned with nmap_transformer for consistency
        class_severity_map = {
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
        
        class_severity = class_severity_map.get(exposure_class, 30)
        
        # Use the higher of the two
        return max(base_severity, class_severity)
