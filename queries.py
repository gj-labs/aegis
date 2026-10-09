"""The killer queries. Shared by bench.py, the agents and the dashboard."""

Q1_SPIKE = """
SELECT toStartOfInterval(ts, INTERVAL 10 SECOND) AS t,
       countIf(success = 0) AS failed, count() AS logins
FROM events
WHERE event_type = 'login' AND ts >= now64(3) - INTERVAL 10 MINUTE
GROUP BY t ORDER BY t
"""

# Full-table scan: this is the "scale" number for the demo.
Q1B_FULL_SCAN = """
SELECT toStartOfFiveMinutes(ts) AS t,
       countIf(event_type = 'login' AND success = 0) AS failed_logins,
       countIf(event_type = 'dns' AND dns_rcode = 'NXDOMAIN') AS nxdomain,
       count() AS events
FROM events GROUP BY t ORDER BY t
"""

Q2_TOP_SOURCES = """
SELECT src_ip,
       countIf(event_type = 'login' AND success = 0) AS login_fails,
       uniqIf(user, event_type = 'login' AND success = 0) AS users_targeted,
       countIf(event_type = 'dns' AND dns_rcode = 'NXDOMAIN') AS nxdomain,
       uniqIf(dns_query, event_type = 'dns') AS distinct_domains,
       countIf(event_type = 'http' AND http_status = 404) AS http_404,
       uniqIf(host, event_type = 'login' AND success = 1) AS hosts_authed,
       count() AS total,
       countIf(ts >= now64(3) - INTERVAL 3 SECOND) AS recent_3s,
       login_fails + nxdomain + http_404 AS score
FROM events
WHERE ts >= now64(3) - INTERVAL 2 MINUTE
GROUP BY src_ip
HAVING total > 20
ORDER BY score DESC
LIMIT 20
"""

# parameter: entity (an IP or a username)
Q3_TIMELINE = """
SELECT ts, event_type, src_ip, user, host, success, dns_query, dns_rcode,
       http_path, http_status, bytes
FROM events
WHERE ts >= now64(3) - INTERVAL 15 MINUTE
  AND (src_ip = {entity:String} OR user = {entity:String})
ORDER BY ts
LIMIT 500
"""

Q_COUNT = "SELECT count() FROM events"

ALL = {
    "q1_failed_login_spike": (Q1_SPIKE, None),
    "q1b_full_table_scan": (Q1B_FULL_SCAN, None),
    "q2_top_sources": (Q2_TOP_SOURCES, None),
    "q3_timeline": (Q3_TIMELINE, {"entity": "203.0.113.66"}),
}
