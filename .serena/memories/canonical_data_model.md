# Canonical Data Model (src/models/canonical.py)

## Root Model: ExposureEventModel
Strict Pydantic v2 model with `ConfigDict(strict=True, extra="forbid", populate_by_name=True)`.

### Required Top-Level Fields
- `schema_version`: str (e.g., "1.0.0")
- `timestamp`: datetime (aliased as "@timestamp", observation time)
- `event`: Event object
- `office`: Office object
- `scanner`: Scanner object
- `target`: Target object (contains asset)
- `exposure`: Exposure object

### Optional Top-Level Fields
- `evidence`: List[EvidenceItem] (optional)
- `disposition`: Disposition (optional)

## Key Enums (Strict Validation)
- **EventKind**: alert, state, event
- **EventAction**: exposure_opened, exposure_observed, exposure_resolved, exposure_suppressed
- **ExposureClass**: http_content_leak, vcs_protocol_exposed, fileshare_exposed, remote_admin_exposed, db_exposed, container_api_exposed, debug_port_exposed, service_advertised_mdns, egress_tunnel_indicator, unknown_service_exposed
- **ExposureStatus**: open, observed, resolved, suppressed
- **Transport**: tcp, udp, icmp, other
- **NetworkDirection**: internal, inbound, outbound, unknown
- **ServiceAuth**: unknown, required, not_required
- **ServiceBindScope**: loopback_only, local_subnet, any, unknown
- **ResourceType**: http_path, smb_share, nfs_export, repo, api_endpoint, mdns_service, domain
- **DataClassification**: source_code, secrets, pii, credentials, internal_only, unknown

## Critical Validation Rules
1. **Severity bounds**: Field validator ensures `severity in [0, 100]`
2. **Confidence bounds**: Field validator ensures `confidence in [0, 1]`
3. **Timestamp logic**: Model validator ensures `last_seen >= first_seen`
4. **Status/action alignment**: Model validator ensures:
   - resolved status requires exposure_resolved action
   - suppressed status requires exposure_suppressed action
5. **Port requirement**: Model validator ensures TCP/UDP transports for port-based exposure classes must have dst.port
6. **Port range**: Field validator ensures `port in [0, 65535]`

## Field Aliases
- `timestamp` field aliased as `"@timestamp"` in JSON
- `exposure.class_` field aliased as `"class"` in JSON (Python keyword workaround)
- `populate_by_name=True` allows both field names and aliases to work

## Minimal Valid Event
Minimum required fields for an "unknown open port" finding:
```python
{
  "schema_version": "1.0.0",
  "@timestamp": "2026-01-13T10:00:00Z",
  "event": {
    "id": "uuid-here",
    "kind": "event",
    "category": ["network"],
    "type": ["info"],
    "action": "exposure_opened",
    "severity": 30
  },
  "office": {"id": "office-1", "name": "Office 1"},
  "scanner": {"id": "scanner-1", "type": "nmap"},
  "target": {"asset": {"id": "10.0.0.1"}},
  "exposure": {
    "id": "exposure-id-hash",
    "class": "unknown_service_exposed",
    "status": "open",
    "vector": {
      "transport": "tcp",
      "protocol": "unknown",
      "dst": {"ip": "10.0.0.1", "port": 8080}
    }
  }
}
```
