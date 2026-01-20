#!/usr/bin/env python3
"""
Asset ID Migration Utility

Migrates exposures from old asset ID format (raw MAC/IP) to new deterministic
format (aid_{hash}). This is necessary when upgrading from older versions
of the ingestion system.

Usage:
    # Dry run (preview changes)
    python migrate_asset_ids.py --dry-run
    
    # Execute migration
    python migrate_asset_ids.py
    
    # Backup first (recommended)
    python migrate_asset_ids.py --backup
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.storage.database import get_db_session
from src.models.storage import ExposureCurrent, ExposureEvent
from src.utils.id_generation import generate_asset_id


def detect_old_format_assets(session) -> List[Dict]:
    """
    Detect assets using old format (raw MAC or IP instead of aid_{hash}).
    
    Old formats:
    - MAC address: "AA:BB:CC:DD:EE:FF"
    - IP address: "10.0.0.1"
    - Synthetic: "XX:XX:XX_10.0.0.1"
    
    New format:
    - "aid_{16-hex-chars}"
    
    Returns:
        List of dicts with asset info and migration mapping
    """
    # Get all unique assets
    results = session.query(
        ExposureCurrent.asset_id,
        ExposureCurrent.asset_mac,
        ExposureCurrent.asset_hostname,
        ExposureCurrent.asset_ip
    ).distinct().all()
    
    old_format_assets = []
    
    for asset_id, mac, hostname, ip in results:
        # Check if asset_id is in old format (not starting with aid_)
        if not asset_id.startswith('aid_'):
            # Generate new asset_id
            try:
                new_asset_id = generate_asset_id(
                    mac=mac,
                    hostname=hostname,
                    ip=ip
                )
                
                old_format_assets.append({
                    'old_id': asset_id,
                    'new_id': new_asset_id,
                    'mac': mac,
                    'hostname': hostname,
                    'ip': ip
                })
            except Exception as e:
                print(f"Warning: Could not generate new ID for {asset_id}: {e}")
    
    return old_format_assets


def migrate_asset_ids(session, migrations: List[Dict], dry_run: bool = True) -> Dict[str, int]:
    """
    Migrate asset IDs from old to new format.
    
    Args:
        session: Database session
        migrations: List of migration mappings
        dry_run: If True, don't commit changes
    
    Returns:
        Statistics dict
    """
    stats = {
        'exposures_updated': 0,
        'events_updated': 0,
        'errors': 0
    }
    
    for migration in migrations:
        old_id = migration['old_id']
        new_id = migration['new_id']
        
        try:
            # Update exposures_current table
            exposure_count = session.query(ExposureCurrent).filter(
                ExposureCurrent.asset_id == old_id
            ).update({
                'asset_id': new_id,
                'updated_at': datetime.utcnow()
            })
            stats['exposures_updated'] += exposure_count
            
            # Update exposure_events table (audit log)
            event_count = session.query(ExposureEvent).filter(
                ExposureEvent.asset_id == old_id
            ).update({'asset_id': new_id})
            stats['events_updated'] += event_count
            
        except Exception as e:
            stats['errors'] += 1
            print(f"Error migrating {old_id} → {new_id}: {e}")
    
    if not dry_run:
        session.commit()
        print("✓ Changes committed to database")
    else:
        session.rollback()
        print("ℹ Dry run complete - no changes committed")
    
    return stats


def create_backup(session, backup_path: Path) -> bool:
    """
    Create backup of exposures_current table.
    
    Args:
        session: Database session
        backup_path: Path to backup file
    
    Returns:
        True if successful
    """
    try:
        # Export to JSON
        import json
        
        exposures = session.query(ExposureCurrent).all()
        backup_data = []
        
        for exp in exposures:
            backup_data.append({
                'id': exp.id,
                'office_id': exp.office_id,
                'exposure_id': exp.exposure_id,
                'asset_id': exp.asset_id,
                'asset_mac': exp.asset_mac,
                'asset_hostname': exp.asset_hostname,
                'asset_ip': exp.asset_ip,
            })
        
        with open(backup_path, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        print(f"✓ Backup created: {backup_path}")
        print(f"  Records: {len(backup_data)}")
        return True
        
    except Exception as e:
        print(f"✗ Backup failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Migrate asset IDs from old format to new deterministic format'
    )
    parser.add_argument('--dry-run', action='store_true', 
                       help='Preview changes without committing')
    parser.add_argument('--backup', action='store_true',
                       help='Create backup before migration')
    parser.add_argument('--backup-path', default='./asset_id_backup.json',
                       help='Path to backup file')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("Asset ID Migration Utility")
    print("=" * 70)
    
    with get_db_session() as session:
        # Create backup if requested
        if args.backup:
            backup_path = Path(args.backup_path)
            if not create_backup(session, backup_path):
                print("✗ Backup failed - aborting migration")
                return 1
        
        # Detect old format assets
        print("\n📊 Detecting assets with old ID format...")
        migrations = detect_old_format_assets(session)
        
        if not migrations:
            print("✓ No assets found with old format - nothing to migrate")
            return 0
        
        print(f"Found {len(migrations)} asset(s) to migrate:\n")
        
        # Show migration preview
        for i, mig in enumerate(migrations[:10], 1):
            print(f"{i}. {mig['old_id']:<25} → {mig['new_id']}")
            print(f"   MAC: {mig['mac'] or 'None':<20} Hostname: {mig['hostname'] or 'None':<20} IP: {mig['ip']}")
        
        if len(migrations) > 10:
            print(f"   ... and {len(migrations) - 10} more")
        
        # Execute migration
        print(f"\n{'🔄 Executing migration (DRY RUN)...' if args.dry_run else '🔄 Executing migration...'}")
        stats = migrate_asset_ids(session, migrations, dry_run=args.dry_run)
        
        # Show results
        print("\n" + "=" * 70)
        print("Migration Results:")
        print("=" * 70)
        print(f"  Assets migrated:        {len(migrations)}")
        print(f"  Exposures updated:      {stats['exposures_updated']}")
        print(f"  Events updated:         {stats['events_updated']}")
        print(f"  Errors:                 {stats['errors']}")
        
        if args.dry_run:
            print("\n⚠️  This was a DRY RUN - no changes were committed")
            print("   Run without --dry-run to apply changes")
        else:
            print("\n✓ Migration complete!")
        
        print("=" * 70)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
