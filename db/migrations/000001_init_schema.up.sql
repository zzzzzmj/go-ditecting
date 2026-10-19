-- Immutable after release. Add a new numbered migration for future changes.
CREATE TABLE IF NOT EXISTS assets (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(128) NOT NULL,
    ip VARCHAR(64) NOT NULL UNIQUE,
    type VARCHAR(64) NOT NULL DEFAULT 'Unknown',
    zone VARCHAR(128) NOT NULL DEFAULT '',
    vendor VARCHAR(128) NOT NULL DEFAULT '',
    criticality VARCHAR(16) NOT NULL DEFAULT 'high',
    status VARCHAR(16) NOT NULL DEFAULT 'online',
    last_seen_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_assets_zone (zone)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS security_events (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    asset_ip VARCHAR(64) NOT NULL,
    asset_name VARCHAR(128) NOT NULL DEFAULT '',
    source_ip VARCHAR(64) NOT NULL,
    protocol VARCHAR(32) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    received_at DATETIME(6) NOT NULL,
    payload JSON NOT NULL,
    INDEX idx_events_occurred (occurred_at),
    INDEX idx_events_asset (asset_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS alerts (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    fingerprint VARCHAR(64) NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'open',
    technique_id VARCHAR(32) NOT NULL DEFAULT '',
    asset_ip VARCHAR(64) NOT NULL,
    asset_name VARCHAR(128) NOT NULL DEFAULT '',
    source_ip VARCHAR(64) NOT NULL,
    protocol VARCHAR(32) NOT NULL,
    occurrence_count INT NOT NULL DEFAULT 1,
    assignee VARCHAR(128) NOT NULL DEFAULT '',
    first_seen_at DATETIME(6) NOT NULL,
    last_seen_at DATETIME(6) NOT NULL,
    INDEX idx_alert_fingerprint (fingerprint, status, last_seen_at),
    INDEX idx_alert_status (status, severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS incidents (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'investigating',
    assignee VARCHAR(128) NOT NULL DEFAULT '',
    alert_ids JSON NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    INDEX idx_incident_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
