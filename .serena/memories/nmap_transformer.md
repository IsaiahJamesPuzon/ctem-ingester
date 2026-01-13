# nmap Transformer (src/transformers/nmap_transformer.py)

## Purpose
Parses nmap XML scan output and transforms to canonical ExposureEventModel instances. One event per open port.

## Class: NmapTransformer(BaseTransformer)

### Methods
- `transform(file_path, office_id, scanner_id)`: Main entry point, returns List[ExposureEventModel]
- `get_scanner_type()`: Returns "nmap"
- `_process_host(host_elem, ...)`: Processes single host, returns list of events
- `_extract_addresses(host_elem)`: Extracts IP and MAC from host
- `_create_port_event(port_elem, ...)`: Creates event for single open port
- `_classify_exposure(port, service, product, tunnel)`: Maps to ExposureClass
- `_calculate_severity(class, service, product)`: Returns severity score 0-100

## XML Parsing Security (uses src/utils/security.py)
- **Library**: defusedxml.ElementTree (prevents XXE, entity expansion attacks)
- **Function**: `parse_xml_safely(file_path)` returns root Element
- **Type hints**: Uses `xml.etree.ElementTree.Element` for annotations (defusedxml doesn't expose Element type)
- **Size limit**: 10MB max file size (MAX_XML_SIZE_BYTES)
- **Depth limit**: 50 levels max nesting (MAX_XML_DEPTH)
- **Errors**: Raises XMLSecurityError if limits exceeded

## Service Classification Logic (_classify_exposure method)

Maps port + service name + product to ExposureClass enum:

### Port-Based Rules
- **22, ssh**: remote_admin_exposed
- **3389, rdp/ms-wbt-server**: remote_admin_exposed
- **5900, vnc**: remote_admin_exposed
- **445/548, smb/microsoft-ds**: fileshare_exposed
- **3306, mysql**: db_exposed
- **5432, postgresql**: db_exposed
- **27017, mongodb**: db_exposed
- **6379, redis**: db_exposed
- **2375/2376, docker**: container_api_exposed
- **6443 + ssl/kubernetes**: container_api_exposed
- **80/443/8080/8000/8888, http**: http_content_leak
- **9418, git**: vcs_protocol_exposed
- **9222, 6000, 63342, 5037, 50000, 5555, 5559, 1099**: debug_port_exposed
- **Unknown**: unknown_service_exposed

### Severity Scoring (_calculate_severity method)
Base severity by class:
- db_exposed: 90
- container_api_exposed: 85
- remote_admin_exposed: 70
- fileshare_exposed: 65
- debug_port_exposed: 60
- vcs_protocol_exposed: 55
- http_content_leak: 50
- service_advertised_mdns: 40
- egress_tunnel_indicator: 45
- unknown_service_exposed: 30

**Adjustments**: +10 for high-risk products (docker, kubernetes, jenkins), capped at 100

## ID Generation (uses src/utils/id_generation.py)
- **event.id**: `generate_event_id()` - UUIDv7 (time-ordered, unique per observation)
- **exposure.id**: `generate_exposure_id(office_id, asset_id, dst_ip, dst_port, protocol, exposure_class)` - SHA256 hash for deterministic deduplication
- **dedupe_key**: `generate_dedupe_key(...)` - Similar to exposure.id but includes service_product for finer granularity

## XML Element Mapping
- `<nmaprun>` root: scanner version, start timestamp
- `<host>`: one host per scan target
- `<address addrtype="ipv4">`: target.asset.ip
- `<address addrtype="mac">`: target.asset.mac
- `<hostname>`: target.asset.hostname
- `<port protocol="tcp" portid="N">`: port number and protocol
- `<state state="open">`: only processes open ports
- `<service name="X" product="Y" version="Z" tunnel="ssl">`: exposure.service

## Transform Flow
1. `parse_xml_safely()` validates + parses XML file
2. Verify root tag is 'nmaprun', raise TransformerError if not
3. Extract scan timestamp from 'start' attribute
4. For each `<host>` element:
   - Extract addresses (IP, MAC) via `_extract_addresses()`
   - Skip hosts without IP address
   - Extract hostname from `<hostname>` element
   - Create Asset object with id=IP, ip=[IP], mac, hostname
   - For each `<port>` with `<state state="open">`:
     - Extract port number, protocol, service details
     - Classify exposure class via `_classify_exposure()`
     - Calculate severity via `_calculate_severity()`
     - Generate IDs (event, exposure, dedupe_key)
     - Build Service, Vector, Exposure, Event objects
     - Create ExposureEventModel
     - Handle validation errors gracefully (print error, skip event)
5. Return list of successfully created events

## Error Handling
- Validation errors during event creation are caught and logged
- Individual event failures don't stop processing of other events
- File parsing errors raise TransformerError
- Returns None for failed events, continues with next port
