"""python3 dashboard.py -> http://localhost:8000
Run generator.py background and pipeline.py in other terminals. This page launches the attack and shows everything."""
import json, math, os, subprocess, sys, threading, time
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from db import get_client
from queries import Q1_SPIKE, Q1B_FULL_SCAN, Q2_TOP_SOURCES, Q_COUNT
from llm import MODEL, BASE_URL

HERE = os.path.dirname(os.path.abspath(__file__))
app = FastAPI()
c = get_client()
lock = threading.Lock()          # one ClickHouse query at a time
attack_proc = None


def rows(r):
    return [dict(zip(r.column_names, x)) for x in r.result_rows]


def timed(sql):
    t0 = time.perf_counter()
    r = c.query(sql)
    rt = (time.perf_counter() - t0) * 1000
    s = r.summary or {}
    srv = int(s["elapsed_ns"]) / 1e6 if s.get("elapsed_ns") else None
    return r, {"round_trip_ms": round(rt, 1), "server_ms": round(srv, 1) if srv else None,
               "scanned": int(s.get("read_rows", 0))}


def clean(o):
    """JSON cannot carry NaN/Infinity (e.g. avg() over an empty table). Turn them into null."""
    if isinstance(o, float) and not math.isfinite(o):
        return None
    if isinstance(o, dict):
        return {k: clean(v) for k, v in o.items()}
    if isinstance(o, list):
        return [clean(v) for v in o]
    return o


def ok(data):
    return JSONResponse(clean(json.loads(json.dumps(data, default=str))))


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "dashboard.html"))


@app.get("/api/state")
def state():
    with lock:
        total = c.query(Q_COUNT).result_rows[0][0]
        rate = c.query("SELECT count() FROM events WHERE ts >= now64(3) - INTERVAL 5 SECOND").result_rows[0][0] / 5
        r1, m1 = timed(Q1_SPIKE)
        r2, m2 = timed(Q2_TOP_SOURCES)
        block = rows(c.query("SELECT ts, kind, value, ttl_s, reason FROM blocklist "
                             "WHERE ts + toIntervalSecond(ttl_s) > now64(3) ORDER BY ts DESC LIMIT 12"))
        feed = rows(c.query("SELECT ts, agent, incident_id, message, model, latency_ms, tokens_in, tokens_out "
                            "FROM agent_log ORDER BY ts DESC LIMIT 40"))
        ak = rows(c.query("SELECT count() AS calls, ifNotFinite(round(avg(latency_ms)), 0) AS avg_ms, sum(tokens_in) AS tin, "
                          "sum(tokens_out) AS tout FROM agent_log WHERE message = 'akash inference ok'"))[0]
        atk = rows(c.query("SELECT ts, run_id, note FROM attack_log ORDER BY ts DESC LIMIT 14"))
        status, rule_s, stop_s = "calm", None, None
        if atk:
            run = atk[0]["run_id"]
            mine = [a for a in atk if a["run_id"] == run]
            start = next((a["ts"] for a in mine if a["note"] == "start"), None)
            stop = next((a for a in mine if a["note"].startswith("traffic_stopped")), None)
            status = "attack" if not stop else ("timeout" if "timeout" in stop["note"] else "contained")
            if start and stop:
                stop_s = round((stop["ts"] - start).total_seconds(), 1)
            if start:
                b = c.query("SELECT count(), min(ts) FROM blocklist "
                            "WHERE ts >= (SELECT max(ts) FROM attack_log WHERE note = 'start')").result_rows[0]
                if b[0] > 0:
                    rule_s = round((b[1] - start).total_seconds(), 1)
    return ok({"total": total, "rate": rate, "q1": {"rows": r1.result_rows and rows(r1), **m1},
               "q2": {"rows": rows(r2), **m2}, "blocklist": block, "feed": feed,
               "akash": {**ak, "model": MODEL, "endpoint": BASE_URL.replace("https://", "")},
               "status": status, "rule_s": rule_s, "stop_s": stop_s, "attack": atk})


@app.get("/api/scan")
def scan():
    with lock:
        r, m = timed(Q1B_FULL_SCAN)
        return ok({"buckets": len(r.result_rows), **m})


@app.post("/api/attack")
def attack():
    global attack_proc
    if attack_proc and attack_proc.poll() is None:
        return ok({"started": False})
    attack_proc = subprocess.Popen([sys.executable, "generator.py", "attack"], cwd=HERE)
    return ok({"started": True})


@app.post("/api/reset")
def reset():
    with lock:
        for t in ["blocklist", "incidents", "agent_log", "attack_log"]:
            c.command(f"TRUNCATE TABLE {t}")
        c.command("ALTER TABLE events DELETE WHERE is_attack = 1 SETTINGS mutations_sync = 1")
    return ok({"reset": True})


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
