CREATE DATABASE threat_logs;
USE threat_logs;

-- SQL script to create the 'detected_threat' table in MySQL

CREATE TABLE detected_threat (
    id VARCHAR(36) PRIMARY KEY, -- Stores UUID as a string
    detection_id VARCHAR(255) NOT NULL,
    timestamp DATETIME NOT NULL,
    source_type VARCHAR(20) NOT NULL,
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    source_identifier VARCHAR(255) NOT NULL,
    content_snippet TEXT, -- NULLABLE by default if not specified as NOT NULL
    confidence_score FLOAT, -- NULLABLE
    status VARCHAR(20) NOT NULL DEFAULT 'new',
    full_details_json JSON -- Stores the full incoming payload as JSON
);

-- Optional: Add an index on timestamp for faster queries when retrieving recent threats
CREATE INDEX idx_detected_threat_timestamp ON detected_threat (timestamp DESC);

-- Optional: Add an index on source_type for faster filtering by source
CREATE INDEX idx_detected_threat_source_type ON detected_threat (source_type);

-- Optional: Add an index on threat_type for faster filtering by type
CREATE INDEX idx_detected_threat_threat_type ON detected_threat (threat_type);

CREATE TABLE network_event_log (
    id SERIAL PRIMARY KEY,
    log_source VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    event_description TEXT NOT NULL,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    protocol VARCHAR(10),
    port INTEGER,
    action VARCHAR(50),
    username VARCHAR(100),
    details JSON
);

-- Index on the primary key (automatically created by most DBMSs)
-- Explicit index for optimized search if needed
CREATE INDEX idx_network_event_log_id ON network_event_log(id);
