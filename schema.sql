-- AEGIS schema. All statements are idempotent. No semicolons inside comments.

CREATE TABLE IF NOT EXISTS events (
    ts          DateTime64(3) DEFAULT now64(3),
    event_type  LowCardinality(String),   -- login | dns | http
    src_ip      LowCardinality(String),
    user        String,
    host        LowCardinality(String),
    success     UInt8,
    dns_query   String,
    dns_rcode   LowCardinality(String),
    http_method LowCardinality(String),
    http_path   String,
    http_status UInt16,
    bytes       UInt32,
    is_attack   UInt8                     -- ground-truth label for scoring only. Detectors must never read it.
) ENGINE = MergeTree
ORDER BY ts;

CREATE TABLE IF NOT EXISTS login_10s (
    bucket DateTime, src_ip LowCardinality(String), fails UInt64, total UInt64
) ENGINE = SummingMergeTree ORDER BY (bucket, src_ip);

CREATE MATERIALIZED VIEW IF NOT EXISTS login_10s_mv TO login_10s AS
SELECT toDateTime(toStartOfInterval(ts, INTERVAL 10 SECOND)) AS bucket, src_ip,
       countIf(success = 0) AS fails, count() AS total
FROM events WHERE event_type = 'login' GROUP BY bucket, src_ip;

CREATE TABLE IF NOT EXISTS dns_10s (
    bucket DateTime, src_ip LowCardinality(String), nxdomain UInt64, total UInt64
) ENGINE = SummingMergeTree ORDER BY (bucket, src_ip);

CREATE MATERIALIZED VIEW IF NOT EXISTS dns_10s_mv TO dns_10s AS
SELECT toDateTime(toStartOfInterval(ts, INTERVAL 10 SECOND)) AS bucket, src_ip,
       countIf(dns_rcode = 'NXDOMAIN') AS nxdomain, count() AS total
FROM events WHERE event_type = 'dns' GROUP BY bucket, src_ip;

-- Blacksmith writes here. The generator reads it every second, so the loop really closes.
CREATE TABLE IF NOT EXISTS blocklist (
    ts DateTime64(3) DEFAULT now64(3),
    kind LowCardinality(String),          -- cidr | user
    value String,
    ttl_s UInt32 DEFAULT 3600,
    reason String,
    incident_id String
) ENGINE = MergeTree ORDER BY ts;

CREATE TABLE IF NOT EXISTS incidents (
    ts DateTime64(3) DEFAULT now64(3),
    incident_id String,
    entity String,
    verdict LowCardinality(String),
    confidence Float32,
    stage String,
    summary String
) ENGINE = MergeTree ORDER BY ts;

CREATE TABLE IF NOT EXISTS agent_log (
    ts DateTime64(3) DEFAULT now64(3),
    agent LowCardinality(String),         -- sentinel | bloodhound | blacksmith
    incident_id String,
    message String,
    model String,
    latency_ms UInt32,
    tokens_in UInt32,
    tokens_out UInt32
) ENGINE = MergeTree ORDER BY ts;

CREATE TABLE IF NOT EXISTS attack_log (
    ts DateTime64(3) DEFAULT now64(3),
    run_id String,
    note String
) ENGINE = MergeTree ORDER BY ts;
