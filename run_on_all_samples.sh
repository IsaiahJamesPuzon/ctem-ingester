#!/usr/bin/env bash
set -euo pipefail

first=1
found=0

while IFS= read -r -d '' f; do
  found=1
  if (( first )); then
    python3 ingestion/ingest.py "$f" --office-id=test-office --scanner-id=scanner-1 --init-db
    first=0
  else
    python3 ingestion/ingest.py "$f" --office-id=test-office --scanner-id=scanner-1
  fi
done < <(find samples -type f -name '*.xml' -print0 | sort -z)

if (( ! found )); then
  echo "No .xml files found under ./samples" >&2
  exit 1
fi
