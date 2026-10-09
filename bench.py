"""python3 bench.py -> latency and rows scanned for each killer query.
'round trip' = what the client sees, including the network to ClickHouse Cloud.
'server' = time ClickHouse reports for the query itself (when the server returns it)."""
import statistics, time
from db import get_client
from queries import ALL

c = get_client()

def med(fn, n=7):
    xs = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1000)
    return statistics.median(xs)

print("events:", c.query("SELECT count() FROM events").result_rows[0][0])
print(f"network round trip (SELECT 1): {med(lambda: c.query('SELECT 1')):.1f} ms")
for name, (sql, params) in ALL.items():
    ms, server, scanned, n_rows = [], [], 0, 0
    for _ in range(7):
        t0 = time.perf_counter()
        r = c.query(sql, parameters=params or {})
        ms.append((time.perf_counter() - t0) * 1000)
        s = r.summary or {}
        scanned, n_rows = int(s.get("read_rows", 0)), len(r.result_rows)
        if s.get("elapsed_ns"):
            server.append(int(s["elapsed_ns"]) / 1e6)
    srv = f"server {statistics.median(server):6.1f} ms" if server else "server    n/a"
    print(f"{name:24s} round trip {statistics.median(ms):6.1f} ms   {srv}   "
          f"scanned {scanned:>11,} rows   returned {n_rows} rows")
