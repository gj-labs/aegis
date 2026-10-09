# AEGIS: the SOC that fights back

AEGIS is a self-defending SOC demo. Synthetic attack traffic streams into ClickHouse, three agents (Sentinel, Bloodhound, Blacksmith) detect it, reconstruct the kill chain and write block rules, and the attack traffic stops. No human in the loop.

> **All traffic is synthetic.** Blocks are enforced by a simulated traffic generator that reads a `blocklist` table. There is no real firewall or real network behind this demo.

Built during the Cyberdefense Hackathon, October 9, 2026.

## The closed loop

```
generator.py ──► ClickHouse Cloud ◄── dashboard.py (FastAPI + one HTML page)
(baseline +       events, blocklist,        ▲  polls every 1.5 s
 5-stage attack)  incidents, agent_log      │
      ▲                │                    │
      │                ▼                    │
      │     Sentinel ─► Bloodhound ─► Blacksmith
      │     (SQL prefilter  (SQL facts +   (rules + report)
      │      + Akash model) Akash model)   Akash model
      │                                        │
      └──── reads blocklist every 250 ms ◄─────┘   attack traffic visibly stops
```

The attack has five stages: recon, password spray, compromise of one account, lateral movement through an internal pivot host, and DNS-tunnel exfiltration.

- **Sentinel** runs a ClickHouse query over recent events, keeps the few sources that look abnormal, and asks the model for a verdict (strict JSON). It opens an incident.
- **Bloodhound** pulls the entity's timeline from ClickHouse, computes facts in SQL (failures, users targeted, compromised accounts, related internal hosts) and asks the model to map them to kill-chain stages and narrate.
- **Blacksmith** asks the model for block rules, validates them in code, applies them to the `blocklist` table, and only then writes the incident report.

## Numbers

Every number is labeled. **measured** means we ran it and read the output. **fixture** means synthetic input data. Nothing here is **guessed**.

| What | Value | Label |
|---|---|---|
| Baseline events | 10,000,000 rows, generated inside ClickHouse with `INSERT ... SELECT ... FROM numbers()` | fixture |
| Baseline load time | about 1.5 s per 1M rows (about 15 s total) | measured |
| Live ingest during demo | about 1,450 to 1,540 events/s from the Python generator | measured |
| Table size at demo time | about 11.6M events | measured |
| Failed-login spike query (last 10 min) | 10.5 ms server time, 300,672 rows scanned | measured |
| Top suspicious sources (last 2 min) | 21.7 ms server time, 71,296 rows scanned | measured |
| Entity timeline (last 15 min) | 18.3 ms server time, 415,360 rows scanned | measured |
| Full-table aggregation | 107.9 ms server time, 10,000,000 rows scanned | measured |
| Network round trip, laptop to ClickHouse Cloud (us-west-2) | 38 to 74 ms. Round-trip figures on the dashboard include it. | measured |
| Akash model call latency | about 3 s average over recent runs, range roughly 1 to 14 s (Llama 3.3 70B) | measured |

Server time is what ClickHouse reports for the query. Round trip is what the client sees.

### Time to contain (measured, synthetic attack)

"Rule applied" is the time from attack start to the first block rule in the `blocklist` table. "Traffic stopped" is when the generator stopped because the sources were blocked.

| Run | Rule applied | Traffic stopped | Incidents |
|---|---|---|---|
| 1 | 15.2 s | 15.7 s | 2 (a duplicate cleanup incident, fixed afterwards) |
| 2 | 16.0 s | 16.7 s | 1 |
| 3 | TODO(team) | TODO(team) | TODO(team) |
| 4 | TODO(team) | TODO(team) | TODO(team) |

Median: TODO(team). These come from a scripted attack on a ClickHouse Cloud service (tier: TODO(team)), so treat them as a demo measurement, not a benchmark.

## How each sponsor is used

**ClickHouse.** `events` is a MergeTree table ordered by timestamp, so time-window queries scan hundreds of thousands of rows instead of the full table. We found this by benchmarking: our first sort key made every query scan all 10M rows. Blocklist, incidents, agent log and attack log are ClickHouse tables too, so the whole loop runs on one database. The dashboard shows each query's server time, round trip and rows scanned. Two materialized views (`login_10s_mv`, `dns_10s_mv`) are created in `schema.sql` but the live queries currently read `events` directly.

**Akash.** All model inference runs on AkashML (`https://api.akashml.com/v1`, OpenAI-compatible) with `meta-llama/Llama-3.3-70B-Instruct`. Every call is logged with latency and token counts, and the dashboard's Akash panel shows model, endpoint, call count, average latency and tokens. If the model fails, the agents fall back to SQL-only facts and the log says so.

**Guild.ai.** TODO(team): state exactly what was done. As of the last build the three agents are plain Python functions in `agents.py`, run by `pipeline.py`, and are not registered on Guild.

**Senso.** TODO(team): state whether it was used. `agents.py` contains an optional hook that saves each incident report to Senso and lets Bloodhound search past incidents, and it only runs if `SENSO_FOLDER_ID` is set in `.env`.

**Semgrep.** TODO(team): state whether Guardian or a scan was run on this repo, and list real findings and fixes. Do not leave this section as a claim without results.

**Pi.** Prize sponsor only, no integration. Our entry is the closed loop: detection, investigation and remediation without a human, instead of another detector.

## Design decisions

- **SQL does the scale work, the model does the judgment.** An LLM cannot score millions of events. ClickHouse reduces recent events to a handful of candidate sources, and the model only sees those.
- **The model proposes, code disposes.** Block rules from the model pass deterministic checks: external ranges no wider than /24, internal addresses only as exact /32, and a user is disabled only if the timeline confirmed it as compromised. Invented users or overbroad ranges are rejected.
- **A policy floor.** In early runs the model sometimes returned only the attacker CIDR and skipped disabling the compromised account, so the attack continued through the pivot host. Code now adds any confirmed compromised user or related pivot host the model left out, and the log says `policy floor added N rule(s) the model omitted`.
- **Contain first, report second.** The report call happens after the rules are applied, which cut time-to-rules from about 35 s to about 16 s in our runs.
- **Ground-truth labels are never used for detection.** `events.is_attack` exists only for scoring and cleanup.

## Limitations

- One scripted attack scenario. Detection thresholds were tuned on it by hand.
- We did not measure precision or recall.
- Enforcement is simulated through the blocklist table, with a one-hour TTL.
- Model latency varies a lot between calls (about 1 s to 14 s), and time-to-contain varies with it.

## Run it

```
cp .env.example .env          # fill in ClickHouse and AkashML values, never commit .env
pip install -r requirements.txt
python3 setup_db.py --baseline    # creates tables, loads 10M synthetic events
python3 bench.py                  # latency and rows scanned per query
python3 reset_demo.py             # clear blocklist and incidents between runs

python3 generator.py background   # terminal 1: normal traffic
python3 pipeline.py               # terminal 2: Sentinel, Bloodhound, Blacksmith
python3 dashboard.py              # terminal 3: http://localhost:8000, then click Launch attack
```

`python3 selftest.py` runs the agent logic against a stub database and stub model with no network.

## Team

Gary (TODO(team): full name) and Richa Arora.
