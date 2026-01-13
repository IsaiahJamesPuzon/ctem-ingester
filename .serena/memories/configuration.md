# Configuration & Environment

## Environment Variables

### Database Configuration
- **DB_PATH**: Path to DuckDB file
  - Local development: `./data/exposures.duckdb` (default)
  - Docker deployment: `/app/data/exposures.duckdb`
- **DB_TYPE**: Database type (default: "duckdb")
- **DATABASE_URL**: Full connection string (overrides DB_PATH if set)

## CLI Usage

### Command Line Arguments
```bash
python ingest.py <file_path> --office-id=<id> --scanner-id=<id> [options]

Arguments:
  file_path              Path to scan file (required)
  --office-id            Office identifier (required)
  --scanner-id           Scanner identifier (required)
  --scanner-type         Scanner type (default: nmap)
  --json                 Output JSON format
  --init-db              Initialize database before processing

Exit Codes:
  0  Success
  1  Error (file not found, parsing error, validation error)
```

### JSON Output Format
```json
{
  "status": "success",
  "file": "/path/to/scan.xml",
  "events": 15,
  "exposures_new": 10,
  "exposures_updated": 5,
  "processing_ms": 234
}
```

## Docker Configuration

### Docker Deployment
```bash
# Direct execution
docker exec ctem-ingestion python ingest.py /data/scans/scan.xml \
  --office-id=office-1 --scanner-id=scanner-1 --json

# With volume mounts
docker run -v /path/to/data:/app/data \
           -v /path/to/scans:/data/scans \
           ctem-ingestion \
           python ingest.py /data/scans/scan.xml \
           --office-id=office-1 --scanner-id=scanner-1
```

### Volume Setup
- **scan_data**: Shared between n8n (write) and ingestion (read)
- **duckdb_data**: Shared between ingestion (write) and Metabase (read-only)

## n8n Integration

### Execute Command Node
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

## Local Development Setup

```bash
cd ingestion
pip install -r requirements.txt

# Set environment
export DB_PATH=./data/exposures.duckdb

# Initialize database
python ingest.py tests/fixtures/nmap_sample.xml \
  --office-id=test --scanner-id=test --init-db

# Process files
python ingest.py /path/to/scan.xml \
  --office-id=office-1 --scanner-id=scanner-1 --json
```
