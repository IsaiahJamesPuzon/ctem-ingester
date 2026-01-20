"""
Simple repository for ingesting exposure events.
"""

from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import insert
import uuid

from src.models.canonical import ExposureEventModel
from src.models.storage import ExposureEvent, ExposureCurrent, QuarantinedFile
from src.utils.security import sanitize_payload


BATCH_SIZE = 500  # Batch size for inserts


class ExposureRepository:
    """Repository for exposure event storage and upsert operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def batch_insert_events(self, events: List[ExposureEventModel]) -> int:
        """
        Batch insert events into exposure_events table (append-only).
        
        Args:
            events: List of canonical exposure event models
        
        Returns:
            Number of events inserted
        """
        if not events:
            return 0
        
        # Convert to storage model dicts
        event_dicts = [self._event_model_to_dict(event) for event in events]
        
        # Batch insert in chunks
        total_inserted = 0
        for i in range(0, len(event_dicts), BATCH_SIZE):
            chunk = event_dicts[i:i + BATCH_SIZE]
            self.session.bulk_insert_mappings(ExposureEvent, chunk)
            total_inserted += len(chunk)
        
        return total_inserted
    
    def batch_upsert_current(self, events: List[ExposureEventModel]) -> Dict[str, int]:
        """
        Batch upsert events into exposures_current table.
        
        On conflict (office_id, exposure_id):
        - Updates: last_seen, status, severity, risk_score, event_action
        - Preserves: first_seen, non-null optional fields (unless explicit null)
        
        Args:
            events: List of canonical exposure event models
        
        Returns:
            Dict with 'inserted' and 'updated' counts
        """
        if not events:
            return {'inserted': 0, 'updated': 0}
        
        stats = {'inserted': 0, 'updated': 0}
        
        # Process in chunks for optimal performance
        for i in range(0, len(events), BATCH_SIZE):
            chunk = events[i:i + BATCH_SIZE]
            chunk_stats = self._upsert_chunk(chunk)
            stats['inserted'] += chunk_stats['inserted']
            stats['updated'] += chunk_stats['updated']
        
        return stats
    
    def _upsert_chunk(self, events: List[ExposureEventModel]) -> Dict[str, int]:
        """Upsert a single chunk of events."""
        # Convert to current state dicts
        current_dicts = [self._event_model_to_current_dict(event) for event in events]
        
        # Use manual upsert for DuckDB (native upsert has compatibility issues)
        inserted, updated = self._manual_upsert(current_dicts)
        
        return {'inserted': inserted, 'updated': updated}
    
    def _manual_upsert(self, current_dicts: List[Dict[str, Any]]) -> tuple[int, int]:
        """
        Optimized manual upsert with bulk fetching.
        
        Performance improvement: Fetches all existing records in one query
        instead of querying per record (N queries → 1 query).
        
        Returns:
            (inserted_count, updated_count)
        """
        if not current_dicts:
            return (0, 0)
        
        inserted = 0
        updated = 0
        
        # Step 1: Bulk fetch all potentially existing records in a single query
        # Build list of (office_id, exposure_id) tuples to check
        keys_to_check = [(d['office_id'], d['exposure_id']) for d in current_dicts]
        
        # Query all existing records that match any of our keys
        from sqlalchemy import or_, and_
        conditions = [
            and_(
                ExposureCurrent.office_id == office_id,
                ExposureCurrent.exposure_id == exposure_id
            )
            for office_id, exposure_id in keys_to_check
        ]
        
        existing_records = self.session.query(ExposureCurrent).filter(or_(*conditions)).all()
        
        # Step 2: Create lookup dictionary for O(1) access
        existing_map = {
            (rec.office_id, rec.exposure_id): rec
            for rec in existing_records
        }
        
        # Step 3: Process each record (update existing or insert new)
        for data in current_dicts:
            key = (data['office_id'], data['exposure_id'])
            existing = existing_map.get(key)
            
            if existing:
                # Update existing (preserve first_seen and non-null fields)
                existing.last_seen = data['last_seen']
                existing.status = data['status']
                existing.severity = data['severity']
                existing.event_action = data['event_action']
                existing.event_kind = data['event_kind']
                existing.updated_at = datetime.utcnow()
                
                # Update optional fields only if new value is not None
                for key_name, value in data.items():
                    if key_name not in ['office_id', 'exposure_id', 'first_seen', 'created_at']:
                        if value is not None:
                            setattr(existing, key_name, value)
                
                updated += 1
            else:
                # Insert new (generate UUID for id)
                data['id'] = str(uuid.uuid4())
                new_exposure = ExposureCurrent(**data)
                self.session.add(new_exposure)
                inserted += 1
        
        return (inserted, updated)
    
    def _event_model_to_dict(self, event: ExposureEventModel) -> Dict[str, Any]:
        """Convert canonical event model to exposure_events table dict."""
        # Sanitize payload before storage
        payload_dict = event.model_dump(mode='json', by_alias=True)
        sanitized = sanitize_payload(payload_dict)
        
        # Inject aggregation metadata if present (from deduplication)
        if hasattr(event, '_ctem_aggregation'):
            sanitized['_ctem_aggregation'] = event._ctem_aggregation
        
        return {
            'event_id': event.event.id,
            'timestamp': event.timestamp,
            'office_id': event.office.id,
            'asset_id': event.target.asset.id,
            'exposure_id': event.exposure.id,
            'exposure_class': event.exposure.class_.value,
            'exposure_status': event.exposure.status.value,
            'event_action': event.event.action.value,
            'event_kind': event.event.kind.value,
            'severity': event.event.severity,
            'risk_score': event.event.risk_score,
            'confidence': event.exposure.confidence,
            'dst_ip': event.exposure.vector.dst.ip if event.exposure.vector.dst else None,
            'dst_port': event.exposure.vector.dst.port if event.exposure.vector.dst else None,
            'protocol': event.exposure.vector.protocol,
            'transport': event.exposure.vector.transport.value,
            'network_direction': (
                event.exposure.vector.network_direction.value
                if event.exposure.vector.network_direction else None
            ),
            'service_json': (
                event.exposure.service.model_dump(mode='json', by_alias=True)
                if event.exposure.service else None
            ),
            'resource_json': (
                event.exposure.resource.model_dump(mode='json', by_alias=True)
                if event.exposure.resource else None
            ),
            'scanner_id': event.scanner.id,
            'scanner_type': event.scanner.type,
            'scan_run_id': (
                event.event.correlation.scan_run_id
                if event.event.correlation else None
            ),
            'dedupe_key': (
                event.event.correlation.dedupe_key
                if event.event.correlation else None
            ),
            'raw_payload_json': sanitized,
            'created_at': datetime.utcnow(),
        }
    
    def _event_model_to_current_dict(self, event: ExposureEventModel) -> Dict[str, Any]:
        """Convert canonical event model to exposures_current table dict."""
        asset = event.target.asset
        service = event.exposure.service
        resource = event.exposure.resource
        
        # Determine first_seen and last_seen
        first_seen = event.exposure.first_seen or event.timestamp
        last_seen = event.exposure.last_seen or event.timestamp
        
        return {
            'office_id': event.office.id,
            'exposure_id': event.exposure.id,
            'exposure_class': event.exposure.class_.value,
            'status': event.exposure.status.value,
            'dst_ip': event.exposure.vector.dst.ip if event.exposure.vector.dst else None,
            'dst_port': event.exposure.vector.dst.port if event.exposure.vector.dst else None,
            'protocol': event.exposure.vector.protocol,
            'transport': event.exposure.vector.transport.value,
            'network_direction': (
                event.exposure.vector.network_direction.value
                if event.exposure.vector.network_direction else None
            ),
            'severity': event.event.severity,
            'risk_score': event.event.risk_score,
            'confidence': event.exposure.confidence,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'asset_id': asset.id,
            'asset_hostname': asset.hostname,
            'asset_ip': asset.ip[0] if asset.ip and len(asset.ip) > 0 else None,
            'asset_mac': asset.mac,
            'asset_os': asset.os,
            'asset_managed': asset.managed,
            'service_name': service.name if service else None,
            'service_product': service.product if service else None,
            'service_version': service.version if service else None,
            'service_tls': service.tls if service else None,
            'service_auth': service.auth.value if service and service.auth else None,
            'service_bind_scope': (
                service.bind_scope.value if service and service.bind_scope else None
            ),
            'service_json': (
                self._add_aggregation_to_service_json(event, service)
                if service else None
            ),
            'resource_json': resource.model_dump(mode='json', by_alias=True) if resource else None,
            'event_action': event.event.action.value,
            'event_kind': event.event.kind.value,
            'scanner_id': event.scanner.id,
            'scanner_type': event.scanner.type,
            'office_name': event.office.name,
            'office_region': event.office.region,
            'office_network_zone': event.office.network_zone,
            'data_class_json': (
                [dc.value for dc in event.exposure.data_class]
                if event.exposure.data_class else None
            ),
            'disposition_ticket': (
                event.disposition.ticket if event.disposition else None
            ),
            'disposition_owner': (
                event.disposition.owner if event.disposition else None
            ),
            'disposition_sla': (
                event.disposition.sla if event.disposition else None
            ),
            'created_at': datetime.utcnow(),
        }

    def _add_aggregation_to_service_json(
        self, 
        event: ExposureEventModel, 
        service
    ) -> Dict[str, Any]:
        """
        Add aggregation metadata to service JSON if present.
        
        Args:
            event: The exposure event model
            service: The service model
            
        Returns:
            Service dict with optional aggregation metadata
        """
        service_dict = service.model_dump(mode='json', by_alias=True)
        
        # Inject aggregation metadata if present (from deduplication)
        if hasattr(event, '_ctem_aggregation'):
            service_dict['_aggregation'] = event._ctem_aggregation
        
        return service_dict
    
    def quarantine_file(
        self,
        filename: str,
        error_type: str,
        error_message: str,
        error_details: Dict[str, Any] | None = None,
        file_size: int | None = None,
        file_hash: str | None = None,
        scanner_type: str | None = None,
        office_id: str | None = None
    ):
        """
        Log a quarantined file.
        
        Args:
            filename: Name of the quarantined file
            error_type: Type of error (e.g., 'XMLParseError', 'ValidationError')
            error_message: Error message
            error_details: Additional error context
            file_size: Size of file in bytes
            file_hash: Hash of file content
            scanner_type: Type of scanner
            office_id: Office ID if known
        """
        quarantined = QuarantinedFile(
            id=str(uuid.uuid4()),
            filename=filename,
            file_size=file_size,
            file_hash=file_hash,
            error_type=error_type,
            error_message=error_message,
            error_details_json=error_details,
            scanner_type=scanner_type,
            office_id=office_id,
        )
        self.session.add(quarantined)
        self.session.commit()


def ingest_events(session: Session, events: List[ExposureEventModel]) -> Dict[str, int]:
    """
    Ingest exposure events to database.
    
    Args:
        session: Database session
        events: List of canonical exposure event models
    
    Returns:
        Dict with stats: events_inserted, exposures_inserted, exposures_updated
    """
    if not events:
        return {'events_inserted': 0, 'exposures_inserted': 0, 'exposures_updated': 0}
    
    repo = ExposureRepository(session)
    
    # Insert into append-only events table
    events_inserted = repo.batch_insert_events(events)
    
    # Upsert into current state table
    upsert_stats = repo.batch_upsert_current(events)
    
    return {
        'events_inserted': events_inserted,
        'exposures_inserted': upsert_stats['inserted'],
        'exposures_updated': upsert_stats['updated'],
    }


def batch_ingest_exposures(events: List[ExposureEventModel], session: Session) -> Dict[str, int]:
    """
    Batch ingest exposure events (alias for ingest_events with swapped arg order for backward compatibility).
    
    Args:
        events: List of canonical exposure event models
        session: Database session
    
    Returns:
        Dict with stats: total_processed, events_inserted, exposures_inserted, exposures_updated
    """
    stats = ingest_events(session, events)
    session.commit()
    stats['total_processed'] = len(events)
    return stats
