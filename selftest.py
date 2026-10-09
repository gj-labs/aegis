"""python selftest.py -> exercises the agent logic with a stub database and stub model. No network needed."""
import json, os
os.environ.pop("SENSO_FOLDER_ID", None)
from agents import Ctx, sentinel_scan, handle
from generator import Blocks

class Res:
    def __init__(s, cols, rows): s.column_names, s.result_rows = cols, rows

class StubCH:
    def __init__(s): s.ins = []
    def insert(s, table, rows, column_names=None): s.ins.append((table, rows))
    def query(s, sql, parameters=None):
        if "users_targeted" in sql and "HAVING" in sql:
            cols = ["src_ip","login_fails","users_targeted","nxdomain","distinct_domains","http_404","hosts_authed","total","score"]
            return Res(cols, [("203.0.113.66",300,250,0,0,40,0,400,340), ("203.0.113.67",280,240,0,0,45,0,380,325),
                              ("10.0.3.4",1,1,0,0,0,9,40,1)])
        if "toUnixTimestamp64Milli" in sql: return Res(["x"], [(1,)])
        if "AS first_seen, max(ts)" in sql:
            return Res(["first_seen","last_seen","total","http_404","distinct_paths","login_fails","users_targeted","login_ok"], [(0,1,900,85,8,580,490,1)])
        if "min(ts) AS at" in sql: return Res(["user","host","at"], [("user4242","auth-gw",0)])
        if "sample_dns" in sql:
            return Res(["src_ip","events","hosts_authed","nxdomain","distinct_domains","sample_dns","post_bytes","first_seen"],
                       [("10.0.99.9",400,40,200,200,["a.t.exfil-cdn.net"],9000000,0)])
        if "attack_log" in sql: return Res(["x"], [(41230,)])
        return Res([], [])
    def blocks(s): return []

class StubLLM:
    def __init__(s, bad=False): s.bad = bad
    def call(s, agent, iid, system, user, max_tokens=0):
        d = json.loads(user)
        if agent == "sentinel":
            return {"verdicts": [{"ip": c["src_ip"], "verdict": "malicious", "confidence": .95, "reason": "spray"} for c in d["candidates"]]}
        if agent == "bloodhound":
            return {"stages": [{"stage": "credential_spray", "evidence": "580 failures"}], "compromised_users": ["user4242", "ghost"],
                    "related_ips": ["10.0.99.9", "8.8.8.8"], "narrative": "Attacker sprays then pivots."}
        rules = [{"kind":"cidr","value":"203.0.113.64/28","ttl_s":900,"reason":"x"}, {"kind":"cidr","value":"10.0.0.0/8","ttl_s":900,"reason":"too broad"},
                 {"kind":"cidr","value":"0.0.0.0/0","ttl_s":9,"reason":"insane"}, {"kind":"cidr","value":"203.0.113.0/24","ttl_s":900,"reason":"ok"},
                 {"kind":"user","value":"user4242","ttl_s":900,"reason":"x"}, {"kind":"user","value":"ghost","ttl_s":900,"reason":"invented"},
                 {"kind":"cidr","value":"10.0.99.9","ttl_s":900,"reason":"pivot"}]
        return {"rules": [] if s.bad else rules, "report_markdown": "## Summary\nAttack contained."}

class B:
    def __init__(s): s.nets, s.users = [], set()
for bad in (False, True):
    ch = StubCH(); blocks = Blocks(ch); ctx = Ctx(ch, StubLLM(bad), blocks)
    incs = sentinel_scan(ctx)
    assert len(incs) == 1 and incs[0]["entity"] == "203.0.113.0/24" and len(incs[0]["ips"]) == 2, incs
    accepted, report = handle(ctx, incs[0])
    vals = {(k, v) for k, v, *_ in accepted}
    print("MODE", "fallback" if bad else "model", "->", sorted(vals))
    assert ("user", "user4242") in vals and ("cidr", "10.0.99.9/32") in vals
    assert ("user", "ghost") not in vals and ("cidr", "10.0.0.0/8") not in vals and ("cidr", "0.0.0.0/0") not in vals
    assert "Measured facts" in report and "41.23" in report
print("selftest OK")
