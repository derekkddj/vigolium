-- Frozen LOCAL receipts-v9 catalog SIGNATURE, independently transcribed from
-- ../vigolium/pkg/database/schema_ddl.go (local currentSchemaVersion = 9).
-- This deliberately small fixture retains the lineage-bearing columns/keys;
-- unrelated tables/columns/indexes are omitted. It is NOT current DDL with a
-- downgraded stamp or dropped upstream columns, nor a complete backup schema.
-- Local v6 introduced receipts; v7 planting receipts; v8 canonical OAST
-- bindings; v9 capture states (see the old db.go schema history).
-- None introduced finding_hash_aliases, findings.last_seen_at,
-- scans.module_stats or scans.coverage_modules. Numeric versions collide.
-- These historical type spellings target SQLite. PostgreSQL tests explicitly
-- map AUTOINCREMENT/BLOB/bool spellings and use parameterized binary seeds;
-- no production conversion is implied.
CREATE TABLE schema_meta (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0,
    min_reader_version INTEGER NOT NULL DEFAULT 1,
    written_by TEXT,
    updated_at TIMESTAMP,
    observation_history_since TIMESTAMP
);
CREATE TABLE scans (
    uuid TEXT PRIMARY KEY NOT NULL,
    project_uuid TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    module_errors TEXT,
    extensions_failed TEXT
);
CREATE TABLE http_records (
    uuid TEXT PRIMARY KEY NOT NULL,
    project_uuid TEXT NOT NULL,
    scan_uuid TEXT,
    raw_request BLOB,
    request_hash TEXT NOT NULL,
    raw_response BLOB,
    response_hash TEXT,
    content_hash TEXT,
    capture_request_state TEXT,
    capture_response_state TEXT
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_uuid TEXT NOT NULL,
    http_record_uuids TEXT NOT NULL,
    scan_uuid TEXT,
    module_id TEXT NOT NULL,
    module_name TEXT NOT NULL,
    record_kind TEXT NOT NULL DEFAULT 'finding',
    evidence_grade TEXT DEFAULT '',
    evidence_status TEXT,
    severity TEXT NOT NULL,
    finding_hash TEXT NOT NULL,
    found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE evidence_exchanges (
    project_uuid TEXT NOT NULL,
    id TEXT NOT NULL,
    url TEXT NOT NULL,
    service TEXT NOT NULL,
    raw_request BLOB,
    raw_response BLOB,
    request_state TEXT NOT NULL,
    response_state TEXT NOT NULL,
    provenance TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    PRIMARY KEY (project_uuid, id)
);
CREATE TABLE finding_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    association_hash TEXT NOT NULL,
    exchange_id TEXT NOT NULL,
    role TEXT NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0,
    label TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    finding_url TEXT NOT NULL,
    scan_uuid TEXT NOT NULL,
    UNIQUE (finding_id, association_hash)
);
CREATE TABLE oast_planting_receipts (
    project_uuid TEXT NOT NULL,
    nonce TEXT NOT NULL,
    scan_uuid TEXT NOT NULL,
    exchange_id TEXT NOT NULL,
    PRIMARY KEY (project_uuid, nonce)
);
CREATE TABLE finding_observations (
    project_uuid TEXT NOT NULL,
    finding_id INTEGER NOT NULL,
    finding_hash TEXT NOT NULL,
    scan_uuid TEXT NOT NULL,
    observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (finding_id, scan_uuid)
);
CREATE INDEX idx_oast_planting_receipts_exchange
    ON oast_planting_receipts(project_uuid, exchange_id);
