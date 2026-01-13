# Project Overview - Exposure Ingestion Service

## Purpose
Minimal Python CLI script that processes network scan outputs (nmap XML), validates them using strict Pydantic models, and stores exposures in DuckDB. Designed to be called directly by n8n Execute Command nodes.

## Architecture (Minimal Footprint)
```
n8n Execute Command → python ingest.py /path/to/scan.xml → Parse → Validate → Transform → Store in DuckDB
```

**Key principle**: Single Python CLI script, no web frameworks, no daemons, just on-demand processing.

## Quick Usage
```bash
# First run - initialize database
python ingest.py scan.xml --office-id=office-1 --scanner-id=scanner-1 --init-db

# Regular usage
python ingest.py scan.xml --office-id=office-1 --scanner-id=scanner-1 --json
```

**Exit codes**: 0 (success), 1 (error)

**JSON output format**:
```json
{
  "status": "success",
  "file": "/path/to/scan.xml",
  "events": 70,
  "exposures_new": 70,
  "exposures_updated": 0,
  "processing_ms": 189
}
```

## Technology Stack (Minimal)
- **Python 3.12+** with argparse (built-in CLI)
- **Pydantic 2.9.2** (strict validation with `extra="forbid"`, `populate_by_name=True`)
- **SQLAlchemy 2.0.35** (ORM)
- **DuckDB 1.1.3** + **duckdb-engine 0.17.0** (embedded database)
- **defusedxml 0.7.1** (secure XML parsing, XXE protection)
- **uuid-utils 0.9.0** (UUIDv7 ID generation)

**Total dependencies: 6 core packages** (no web frameworks, no heavyweight libraries)

## Project Structure (Minimal)
```
ingestion/
├── ingest.py                # Main CLI script (~200 lines)
├── requirements.txt         # 6 dependencies
├── data/                    # DuckDB storage (created automatically)
│   └── exposures.duckdb
└── src/
    ├── models/
    │   ├── canonical.py     # Pydantic validation models
    │   └── storage.py       # SQLAlchemy ORM models (String PKs)
    ├── transformers/
    │   ├── base.py          # BaseTransformer interface
    │   ├── registry.py      # Simple transformer registry
    │   └── nmap_transformer.py  # nmap XML → canonical
    ├── storage/
    │   ├── connection.py    # DatabaseManager (singleton)
    │   ├── database.py      # Engine/session management
    │   └── repository.py    # ExposureRepository (batch insert/upsert)
    └── utils/
        ├── id_generation.py # Deterministic IDs (SHA256 + UUIDv7)
        └── security.py      # XML security (defusedxml wrapper)
```

## Key Design Principles
1. **Minimal footprint**: No unnecessary dependencies or frameworks
2. **Strict validation**: Pydantic v2 with `extra="forbid"`, `strict=True`, `populate_by_name=True`
3. **Secure parsing**: defusedxml for XXE/entity expansion protection (10MB/50-level limits)
4. **Deterministic IDs**: SHA256-based exposure IDs for deduplication
5. **Dual-table storage**: append-only events + upserted current state
6. **String primary keys**: UUID-based (avoids DuckDB SERIAL compatibility issues)
7. **Manual upsert**: Find-or-create pattern for maximum compatibility
8. **Extensible**: Simple BaseTransformer interface for adding new scanners

## n8n Integration
Execute Command node:
```javascript
{
  "command": "python /app/ingest.py",
  "arguments": [
    "/data/scans/{{ $json.filename }}",
    "--office-id={{ $json.office_id }}",
    "--scanner-id={{ $json.scanner_id }}",
    "--json"
  ]
}
```

Parse output: `{{ JSON.parse($json.stdout) }}`
Check success: `{{ $json.exitCode === 0 }}`

## Database Tables
- **exposure_events**: Append-only audit log (event_id String PK)
- **exposures_current**: Upserted current state (id String PK, unique on office_id+exposure_id)
- **quarantined_files**: Failed processing log (id String PK)

## Performance
- **Typical scan** (70 exposures): ~190ms first run, ~500ms updates
- **Batch processing**: 500 events/chunk for optimal DuckDB performance
- **Verification**: 140 events logged, 70 unique exposures maintained on re-run
