"""
Configuration settings for CTEM ingestion system.

This module provides centralized configuration management with
environment-specific overrides and validation.
"""

import os
from typing import Dict, Optional
from pathlib import Path


class Settings:
    """
    Configuration settings for the ingestion system.
    
    Settings can be overridden via environment variables:
    - CTEM_BATCH_SIZE: Batch size for database operations
    - CTEM_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    - CTEM_MAX_JSON_SIZE_MB: Maximum JSON file size in MB
    """
    
    # Database Settings
    BATCH_SIZE: int = int(os.getenv('CTEM_BATCH_SIZE', '500'))
    
    # Logging Settings
    LOG_LEVEL: str = os.getenv('CTEM_LOG_LEVEL', 'INFO')
    
    # File Processing Settings
    MAX_JSON_SIZE_MB: int = int(os.getenv('CTEM_MAX_JSON_SIZE_MB', '10'))
    MAX_JSON_SIZE_BYTES: int = MAX_JSON_SIZE_MB * 1024 * 1024
    
    # Severity Scores for Exposure Classes
    # Can be customized per deployment environment
    SEVERITY_SCORES: Dict[str, int] = {
        'db_exposed': 90,
        'container_api_exposed': 85,
        'cache_exposed': 75,
        'queue_exposed': 70,
        'remote_admin_exposed': 70,
        'fileshare_exposed': 65,
        'debug_port_exposed': 60,
        'vcs_protocol_exposed': 55,
        'http_content_leak': 50,
        'monitoring_exposed': 45,
        'egress_tunnel_indicator': 45,
        'service_advertised_mdns': 40,
        'media_streaming_exposed': 35,
        'unknown_service_exposed': 30,
    }
    
    # Classification Keywords
    DATABASE_KEYWORDS: list = [
        'mysql', 'postgresql', 'postgres', 'mongodb',
        'redis', 'mssql', 'oracle', 'cassandra',
        'elasticsearch', 'couchdb', 'influxdb', 'mariadb'
    ]
    
    STREAMING_KEYWORDS: list = [
        'rtsp', 'airtunes', 'airplay', 'raop', 'streaming'
    ]
    
    MONITORING_KEYWORDS: list = [
        'prometheus', 'grafana', 'kibana', 'datadog',
        'metrics', 'monitoring'
    ]
    
    CACHE_KEYWORDS: list = [
        'memcached', 'varnish', 'cache'
    ]
    
    QUEUE_KEYWORDS: list = [
        'rabbitmq', 'kafka', 'activemq', 'zeromq',
        'queue', 'amqp'
    ]
    
    # Port Sets
    MONITORING_PORTS: set = {3000, 3333, 5601, 9090, 9091, 9115, 16686}
    CACHE_PORTS: set = {11211, 11212}
    QUEUE_PORTS: set = {5672, 9092, 61616, 25672}
    
    UNAMBIGUOUS_DB_PORTS: set = {
        3306,   # MySQL/MariaDB
        5432,   # PostgreSQL
        27017,  # MongoDB
        6379,   # Redis
        1433,   # MS SQL Server
        1521,   # Oracle
        5984,   # CouchDB
    }
    
    @classmethod
    def get_severity_score(cls, exposure_class: str, default: int = 30) -> int:
        """
        Get severity score for an exposure class.
        
        Args:
            exposure_class: The exposure class name
            default: Default score if not found
            
        Returns:
            Severity score (0-100)
        """
        return cls.SEVERITY_SCORES.get(exposure_class.lower(), default)
    
    @classmethod
    def load_from_file(cls, config_file: Optional[Path] = None) -> None:
        """
        Load configuration from a YAML file.
        
        Args:
            config_file: Path to YAML config file (optional)
        
        Future enhancement: Load settings from YAML file to override defaults
        """
        if config_file and config_file.exists():
            # TODO: Implement YAML loading
            # import yaml
            # with open(config_file) as f:
            #     config = yaml.safe_load(f)
            #     # Update class attributes from config
            pass
    
    @classmethod
    def validate(cls) -> bool:
        """
        Validate configuration settings.
        
        Returns:
            True if configuration is valid
            
        Raises:
            ValueError: If configuration is invalid
        """
        if cls.BATCH_SIZE <= 0:
            raise ValueError(f"BATCH_SIZE must be positive, got {cls.BATCH_SIZE}")
        
        if cls.MAX_JSON_SIZE_MB <= 0:
            raise ValueError(f"MAX_JSON_SIZE_MB must be positive, got {cls.MAX_JSON_SIZE_MB}")
        
        # Validate severity scores are in range
        for exposure_class, score in cls.SEVERITY_SCORES.items():
            if not 0 <= score <= 100:
                raise ValueError(f"Severity score for {exposure_class} must be 0-100, got {score}")
        
        return True


# Validate configuration on module load
Settings.validate()


# Export singleton instance
settings = Settings()
