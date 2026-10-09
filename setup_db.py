"""python setup_db.py            -> create tables
   python setup_db.py --baseline -> also load ~10M synthetic baseline events (generated inside ClickHouse)
   python setup_db.py --reset    -> drop everything first
"""
import sys, time
from db import get_client

BASELINE = """
INSERT INTO events (ts, event_type, src_ip, user, host, success, dns_query, dns_rcode,
                    http_method, http_path, http_status, bytes, is_attack)
SELECT
    now64(3) - toIntervalMillisecond(rand(1) % 21600000),
    multiIf(t < 4, 'login', t < 7, 'dns', 'http'),
    concat('10.0.', toString(rand(2) % 16), '.', toString(1 + rand(3) % 250)),
    concat('user', toString(rand(4) % 5000)),
    if(t >= 4 AND t < 7, '', concat('host', toString(rand(5) % 200))),
    multiIf(t < 4, toUInt8(rand(6) % 100 >= 3), 1),
    if(t >= 4 AND t < 7, concat('site', toString(rand(7) % 500), '.com'), ''),
    if(t >= 4 AND t < 7, if(rand(8) % 100 = 0, 'NXDOMAIN', 'NOERROR'), ''),
    if(t >= 7, if(rand(9) % 10 = 0, 'POST', 'GET'), ''),
    if(t >= 7, concat('/p/', toString(rand(10) % 300)), ''),
    if(t >= 7, if(rand(11) % 100 < 3, 500, 200), 0),
    if(t >= 7, toUInt32(rand(12) % 50000), 0),
    0
FROM (SELECT number % 10 AS t FROM numbers(1000000))
"""

def main():
    c = get_client()
    if "--reset" in sys.argv:
        for t in ["login_10s_mv", "dns_10s_mv", "login_10s", "dns_10s", "events",
                  "blocklist", "incidents", "agent_log", "attack_log"]:
            c.command(f"DROP TABLE IF EXISTS {t}")
    sql = open("schema.sql").read()
    for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
        c.command(stmt)
    print("schema ready")
    if "--baseline" in sys.argv:
        for i in range(10):
            t0 = time.time()
            c.command(BASELINE)
            print(f"baseline chunk {i+1}/10 in {time.time()-t0:.1f}s")
        print("events:", c.query("SELECT count() FROM events").result_rows[0][0])

if __name__ == "__main__":
    main()
