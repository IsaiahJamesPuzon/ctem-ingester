#!/bin/sh
# Example: Ingest multi-stage nmap scans with automatic scan_run_id correlation
set -eu

DIR="/home/node/out_bigscan/03_enum"
INGEST="/home/node/ctem-ingester/ingestion/ingest.py"

# Read from environment variable (set during deployment)
OFFICE_ID="${CTEM_OFFICE_ID:-default-office}"

# Check if directory exists and has XML files
first="$(find "$DIR" -type f -name '*.xml' -print -quit 2>/dev/null || true)"
if [ -z "$first" ]; then
  echo "No .xml files found under: $DIR" >&2
  exit 0
fi

echo "Starting ingestion for office: $OFFICE_ID"
echo "---"

# Process all XML files with automatic scan_run_id from filename
count=0
find "$DIR" -type f -name '*.xml' -print | sort | while IFS= read -r f; do
  count=$((count + 1))
  
  # Extract filename without path or extension for scan_run_id
  basename_file=$(basename "$f" .xml)
  
  printf '[%d] Ingesting: %s\n' "$count" "$basename_file"
  printf '    Office: %s, Scanner: nmap, Scan Run: %s\n' "$OFFICE_ID" "$basename_file"
  
  # Ingest with automatic scan_run_id (derived from filename)
  python3 "$INGEST" "$f" \
    --office-id="$OFFICE_ID" \
    --scanner-id="nmap"
  
  # OR use explicit scan_run_id:
  # python3 "$INGEST" "$f" \
  #   --office-id="$OFFICE_ID" \
  #   --scanner-id="nmap" \
  #   --scan-run-id="$basename_file"
  
  echo ""
done

echo "---"
echo "✓ Ingestion complete"

# Query events by scan run (example)
# python3 -c "
# from src.storage.database import get_db_session
# from src.models.storage import ExposureEvent
# from sqlalchemy import distinct, func
# 
# with get_db_session() as session:
#     stats = session.query(
#         ExposureEvent.scan_run_id,
#         func.count(ExposureEvent.event_id).label('count')
#     ).group_by(ExposureEvent.scan_run_id).all()
#     
#     print('\nScan Run Summary:')
#     for run_id, count in stats:
#         print(f'  {run_id}: {count} events')
# "
