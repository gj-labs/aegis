"""Sentinel (detect), Bloodhound (investigate), Blacksmith (remediate).
SQL does the heavy lifting over millions of rows. The model only sees a few dozen pre-filtered facts."""
import ipaddress, json, os, subprocess, time, uuid
from queries import Q2_TOP_SOURCES

SYS_SENTINEL = ("You are Sentinel, a SOC detection agent. You receive candidate source IPs with 2-minute "
                "behaviour counters from a database of millions of events. Judge each one. Internal 10.x hosts "
                "normally show a handful of events and almost no failures. Output: "
                '{"verdicts":[{"ip":str,"verdict":"malicious|suspicious|benign","confidence":0..1,"reason":str}]}')
SYS_BLOODHOUND = ("You are Bloodhound, an incident investigator. From the computed facts, reconstruct the kill chain. "
                  "Use only these stages: recon, credential_spray, compromise, lateral_movement, exfiltration. "
                  "Only include a stage if the facts support it. compromised_users and related_ips must be chosen "
                  "from the candidate lists provided. Output: "
                  '{"stages":[{"stage":str,"evidence":str}],"compromised_users":[str],"related_ips":[str],'
                  '"narrative":"2-3 sentences, present tense"}')
SYS_BLACKSMITH = ("You are Blacksmith, a remediation agent. Propose minimal, targeted block rules. Rule kinds: cidr "
                  "(an IP or CIDR) or user (disable account). Block the entity CIDR itself when it is an external range, "
                  "disable EVERY compromised user, and block each related internal IP as an exact /32. Output: "
                  '{"rules":[{"kind":"cidr|user","value":str,"ttl_s":int,"reason":str}]}')
SYS_REPORT = ("You are Blacksmith writing an incident report for a SOC. Be concise: summary, kill-chain timeline, "
              "actions taken, recommendations. Use only the facts given. Output: "
              '{"report_markdown":str}')


INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(net):
    """RFC1918 only. (Python's is_private also covers the 203.0.113.0/24 documentation range we use for attackers.)"""
    return any(net.version == 4 and net.overlaps(i) for i in INTERNAL)


def rows(res):
    return [dict(zip(res.column_names, r)) for r in res.result_rows]


class Ctx:
    def __init__(self, ch, llm, blocks):
        self.ch, self.llm, self.blocks = ch, llm, blocks

    def log(self, agent, iid, msg, model="", ms=0, tin=0, tout=0):
        extra = f"  ({ms} ms, {tin}+{tout} tok)" if ms else ""
        print(f"[{agent:10s}] {iid or '-':8s} {msg}{extra}")
        self.ch.insert("agent_log", [(agent, iid or "", msg, model, ms, tin, tout)],
                       column_names=["agent", "incident_id", "message", "model", "latency_ms", "tokens_in", "tokens_out"])


# ---------------------------------------------------------------- Senso (optional, never blocks the loop)
def senso(args, timeout=8):
    try:
        r = subprocess.run(["senso"] + args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


# ---------------------------------------------------------------- Sentinel
def sentinel_scan(ctx):
    """One pass. Returns a list of incident dicts (possibly empty)."""
    cands = []
    for r in rows(ctx.ch.query(Q2_TOP_SOURCES)):
        if (r["login_fails"] >= 40 or r["nxdomain"] >= 40 or r["http_404"] >= 40 or r["hosts_authed"] >= 60) \
                and r["recent_3s"] > 0 and not ctx.blocks.blocked(r["src_ip"]):
            cands.append({k: r[k] for k in ("src_ip", "login_fails", "users_targeted", "nxdomain",
                                            "distinct_domains", "http_404", "hosts_authed", "total")})
    if not cands:
        return []
    ctx.log("sentinel", "", f"{len(cands)} candidate sources pre-filtered by SQL, asking model")
    out = ctx.llm.call("sentinel", "", SYS_SENTINEL, json.dumps({"candidates": cands}))
    verdicts = {v.get("ip"): v for v in (out or {}).get("verdicts", []) if isinstance(v, dict)}
    if out is None:                                           # model unavailable: say so, use the SQL thresholds
        ctx.log("sentinel", "", "model unavailable, using threshold verdicts")
        verdicts = {c["src_ip"]: {"verdict": "malicious", "confidence": 0.6, "reason": "threshold fallback"} for c in cands}
    bad = [c for c in cands if verdicts.get(c["src_ip"], {}).get("verdict") in ("malicious", "suspicious")
           and float(verdicts[c["src_ip"]].get("confidence", 0) or 0) >= 0.7]
    groups = {}
    for c in bad:                                             # one incident per external /24, one per internal host
        ip = ipaddress.ip_address(c["src_ip"])
        key = c["src_ip"] if is_internal(ipaddress.ip_network(c["src_ip"])) else str(ipaddress.ip_network(c["src_ip"] + "/24", strict=False))
        groups.setdefault(key, []).append(c)
    incidents = []
    for key, members in groups.items():
        iid = uuid.uuid4().hex[:8]
        top = verdicts[members[0]["src_ip"]]
        inc = {"id": iid, "entity": key, "ips": [m["src_ip"] for m in members], "stats": members,
               "verdict": top.get("verdict"), "confidence": float(top.get("confidence", 0) or 0),
               "reason": top.get("reason", ""), "detected_ms": ctx.ch.query("SELECT toUnixTimestamp64Milli(now64(3))").result_rows[0][0]}
        ctx.ch.insert("incidents", [(iid, key, inc["verdict"], inc["confidence"], "detected", inc["reason"][:500])],
                      column_names=["incident_id", "entity", "verdict", "confidence", "stage", "summary"])
        ctx.log("sentinel", iid, f"{inc['verdict']} ({inc['confidence']:.2f}) {key}: {inc['reason'][:160]}")
        incidents.append(inc)
    return incidents


# ---------------------------------------------------------------- Bloodhound
def compromise_facts(ctx, ips):
    """Accounts that logged in successfully from these IPs, and what those accounts did from other IPs."""
    p = {"ips": ips}
    comp = rows(ctx.ch.query("""
        SELECT user, any(host) AS host, min(ts) AS at FROM events
        WHERE ts >= now64(3) - INTERVAL 10 MINUTE AND has({ips:Array(String)}, src_ip)
          AND event_type='login' AND success=1 GROUP BY user ORDER BY at LIMIT 5""", parameters=p))
    users = [c["user"] for c in comp]
    related = []
    if users:
        related = rows(ctx.ch.query("""
            SELECT src_ip, count() AS events, uniqIf(host, event_type='login' AND success=1) AS hosts_authed,
                   countIf(event_type='dns' AND dns_rcode='NXDOMAIN') AS nxdomain,
                   uniqIf(dns_query, event_type='dns') AS distinct_domains,
                   groupArrayIf(2)(dns_query, event_type='dns' AND dns_rcode='NXDOMAIN') AS sample_dns,
                   sumIf(bytes, event_type='http' AND http_method='POST') AS post_bytes, min(ts) AS first_seen
            FROM events WHERE ts >= now64(3) - INTERVAL 10 MINUTE AND has({users:Array(String)}, user)
              AND NOT has({ips:Array(String)}, src_ip)
            GROUP BY src_ip HAVING events >= 10 ORDER BY events DESC LIMIT 5""", parameters={"users": users, "ips": ips}))
    return comp, users, related


def bloodhound_investigate(ctx, inc):
    iid, ips = inc["id"], inc["ips"]
    p = {"ips": ips}
    summ = rows(ctx.ch.query("""
        SELECT min(ts) AS first_seen, max(ts) AS last_seen, count() AS total,
               countIf(event_type='http' AND http_status=404) AS http_404,
               uniqIf(http_path, http_status=404) AS distinct_paths,
               countIf(event_type='login' AND success=0) AS login_fails,
               uniqIf(user, event_type='login' AND success=0) AS users_targeted,
               countIf(event_type='login' AND success=1) AS login_ok
        FROM events WHERE ts >= now64(3) - INTERVAL 10 MINUTE AND has({ips:Array(String)}, src_ip)""", parameters=p))[0]
    comp, users, related = compromise_facts(ctx, ips)
    facts = {"entity": inc["entity"], "source_ips": ips, "summary": summ, "successful_logins_from_entity": comp,
             "candidate_compromised_users": users, "candidate_related_ips": [r["src_ip"] for r in related],
             "activity_of_those_users_from_other_ips": related}
    memory = senso(["search", f"incident kill chain {len(ips)} sources password spray lateral movement dns exfil"]) \
        if os.environ.get("SENSO_FOLDER_ID") else None
    if memory:
        facts["past_incident_memory_from_senso"] = memory[:600]
        ctx.log("bloodhound", iid, "Senso memory consulted: similar past incident found")
    ctx.log("bloodhound", iid, f"pulled timeline facts: {summ['total']} events, {len(users)} compromised-user candidates")
    out = ctx.llm.call("bloodhound", iid, SYS_BLOODHOUND, json.dumps(facts, default=str))
    if out is None:
        out = {"stages": [], "compromised_users": users, "related_ips": facts["candidate_related_ips"],
               "narrative": "Model unavailable. Facts computed by SQL only."}
        ctx.log("bloodhound", iid, "model unavailable, using SQL facts only")
    inv = {"stages": out.get("stages", []),
           "compromised_users": [u for u in out.get("compromised_users", []) if u in users],      # guardrail: no invented users
           "related_ips": [i for i in out.get("related_ips", []) if i in facts["candidate_related_ips"]],
           "narrative": out.get("narrative", ""), "facts": facts}
    for s in inv["stages"]:
        ctx.log("bloodhound", iid, f"kill chain: {s.get('stage')} - {str(s.get('evidence'))[:140]}")
    ctx.log("bloodhound", iid, f"narrative: {inv['narrative'][:300]}")
    return inv


# ---------------------------------------------------------------- Blacksmith
def valid_rule(rule, inc, inv):
    """Guardrails: the model proposes, deterministic code disposes. Returns (kind, value) or None."""
    try:
        kind, value = rule["kind"], str(rule["value"]).strip()
        if kind == "user":
            return ("user", value) if value in inv["compromised_users"] else None
        if kind == "cidr":
            net = ipaddress.ip_network(value, strict=False)
            members = [ipaddress.ip_address(i) for i in inc["ips"] + inv["related_ips"]]
            if not any(m in net for m in members):
                return None
            if is_internal(net) and net.prefixlen < 32:       # never block internal ranges, only exact hosts
                return None
            if not is_internal(net) and net.prefixlen < 24:
                return None
            return ("cidr", str(net))
    except Exception:
        return None
    return None


def blacksmith_remediate(ctx, inc, inv):
    iid = inc["id"]
    payload = {"entity": inc["entity"], "source_ips": inc["ips"], "compromised_users": inv["compromised_users"],
               "related_internal_ips": inv["related_ips"], "stages": inv["stages"], "narrative": inv["narrative"]}
    out = ctx.llm.call("blacksmith", iid, SYS_BLACKSMITH, json.dumps(payload), max_tokens=450)
    _, users2, related2 = compromise_facts(ctx, inc["ips"])          # facts may have changed since Bloodhound ran
    new_users = [u for u in users2 if u not in inv["compromised_users"]]
    new_ips = [r["src_ip"] for r in related2 if r["src_ip"] not in inv["related_ips"]]
    if new_users or new_ips:
        inv["compromised_users"] += new_users
        inv["related_ips"] += new_ips
        ctx.log("blacksmith", iid, f"re-check before blocking found {len(new_users)} newly compromised user(s) "
                                   f"and {len(new_ips)} pivot host(s)")
    accepted, rejected = [], 0
    for r in (out or {}).get("rules", []):
        v = valid_rule(r, inc, inv)
        if v and v not in [(a[0], a[1]) for a in accepted]:
            accepted.append((v[0], v[1], max(60, min(int(r.get("ttl_s", 3600) or 3600), 86400)), str(r.get("reason", ""))[:200]))
        else:
            rejected += 1
    if rejected:
        ctx.log("blacksmith", iid, f"guardrails rejected {rejected} proposed rule(s)")
    if not accepted:
        ctx.log("blacksmith", iid, "no valid model rules, applying fallback policy")
        accepted = [("cidr", str(ipaddress.ip_network(i + "/32")), 3600, "fallback: attacker source") for i in inc["ips"]] \
                 + [("user", u, 3600, "fallback: compromised account") for u in inv["compromised_users"]] \
                 + [("cidr", i + "/32", 3600, "fallback: pivot host") for i in inv["related_ips"]]
    # Policy floor: the model proposes, but facts confirmed by SQL must always be remediated.
    added = 0
    for u in inv["compromised_users"]:
        if not any(r[0] == "user" and r[1] == u for r in accepted):
            accepted.append(("user", u, 3600, "policy: account compromised, confirmed by timeline")); added += 1
    for ip in inv["related_ips"]:
        a_ip = ipaddress.ip_address(ip)
        if not any(r[0] == "cidr" and a_ip in ipaddress.ip_network(r[1], strict=False) for r in accepted):
            accepted.append(("cidr", ip + "/32", 3600, "policy: pivot host, confirmed by timeline")); added += 1
    if added:
        ctx.log("blacksmith", iid, f"policy floor added {added} rule(s) the model omitted")
    ctx.ch.insert("blocklist", [(k, v, ttl, reason, iid) for k, v, ttl, reason in accepted],
                  column_names=["kind", "value", "ttl_s", "reason", "incident_id"])   # contain FIRST
    ctx.blocks.refresh(force=True)
    for k, v, ttl, reason in accepted:
        ctx.log("blacksmith", iid, f"BLOCK {k} {v} ttl={ttl}s: {reason}")
    start = ctx.ch.query("SELECT dateDiff('millisecond', ts, now64(3)) FROM attack_log WHERE note = 'start' "
                         "ORDER BY ts DESC LIMIT 1").result_rows
    ttc = start[0][0] / 1000 if start else None
    ctx.ch.insert("incidents", [(iid, inc["entity"], inc["verdict"], inc["confidence"], "contained",
                                 f"rules={len(accepted)} time_to_contain_s={ttc}")],
                  column_names=["incident_id", "entity", "verdict", "confidence", "stage", "summary"])
    ctx.log("blacksmith", iid, f"contained: rules applied {ttc}s after attack start")
    def finish():
        """Write the incident report. Runs after containment, and only when Sentinel has nothing new to handle."""
        data = {"entity": inc["entity"], "source_ips": inc["ips"], "compromised_users": inv["compromised_users"],
                "related_internal_ips": inv["related_ips"], "stages": inv["stages"], "narrative": inv["narrative"],
                "rules_applied": [f"{r[0]} {r[1]}" for r in accepted], "seconds_to_rules": ttc}
        rep = ctx.llm.call("blacksmith", iid, SYS_REPORT, json.dumps(data), max_tokens=700)
        measured = (f"\n\n## Measured facts (computed by code, not written by the model)\n"
                    f"- Rules applied: {len(accepted)} ({', '.join(r[0]+':'+r[1] for r in accepted)})\n"
                    f"- Time from attack start to rules applied: {ttc if ttc is not None else 'n/a'} s\n"
                    f"- Traffic is synthetic. Block is enforced by the simulated generator via the blocklist table.\n")
        report = f"# Incident {iid}: {inc['entity']}\n\n" + str((rep or {}).get("report_markdown") or inv["narrative"]) + measured
        os.makedirs("reports", exist_ok=True)
        open(f"reports/{iid}.md", "w").write(report)
        ctx.log("blacksmith", iid, f"incident report written (reports/{iid}.md)")
        folder = os.environ.get("SENSO_FOLDER_ID")
        if folder:
            senso(["kb", "create-raw", "--data", json.dumps({"title": f"incident-{iid}.md", "text": report,
                                                             "kb_folder_node_id": folder})])
            ctx.log("blacksmith", iid, "incident saved to Senso memory")
        return report

    return accepted, finish


def handle(ctx, inc):
    inv = bloodhound_investigate(ctx, inc)
    return blacksmith_remediate(ctx, inc, inv)
