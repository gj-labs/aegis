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

"First rule" is the time from attack start to the first block rule in the `blocklist` table. "Traffic stopped" is when the generator stopped because the sources were blocked. Run times are approximate Pacific times.

| Run | Time | Code | First rule | Traffic stopped | Incidents |
|---|---|---|---|---|---|
| 1 | about 2:31 PM | policy floor | 15.2 s | 15.7 s | 2 (second was cleanup after traffic had stopped) |
| 2 | about 2:36 PM | plus 3 s staleness window | 16.0 s | 16.7 s | 1 |
| 3 | 2:39 PM | same as run 2 | 9.5 s | 40.2 s | 2 |
| 4 | 2:40 PM | same as run 2 | 13.6 s | 36.2 s | 2 |
| 5 | about 3:00 PM | same as run 2 | 11.2 s | not recorded | 2 (second rule at 28.8 s) |
| 6 | about 3:02 PM | plus re-check before blocking, deferred reports | 18.8 s | not recorded | 1 |

Over the four runs where we recorded it, traffic stopped in **15.7 to 40.2 s (median 26.5 s)**. In runs 3 to 5 Sentinel detected the attack before the account compromise showed up in the data, so the first incident blocked only the external range. The internal pivot host then needed a second incident, and one Akash call in that investigation took 17.6 s. Run 6 is the first on the code that re-checks for a compromised account right before blocking, and it put all three rules into a single incident. We have only one run on that code, so treat it as preliminary: TODO(team) add any later runs here.

These come from a scripted attack on a ClickHouse Cloud service (tier: TODO(team)), so treat them as a demo measurement, not a benchmark.

## How each sponsor is used

**ClickHouse.** `events` is a MergeTree table ordered by timestamp, so time-window queries scan hundreds of thousands of rows instead of the full table. We found this by benchmarking: our first sort key made every query scan all 10M rows. Blocklist, incidents, agent log and attack log are ClickHouse tables too, so the whole loop runs on one database. The dashboard shows each query's server time, round trip and rows scanned. Two materialized views (`login_10s_mv`, `dns_10s_mv`) are created in `schema.sql` but the live queries currently read `events` directly.

**Akash.** All model inference runs on AkashML (`https://api.akashml.com/v1`, OpenAI-compatible) with `meta-llama/Llama-3.3-70B-Instruct`. Every call is logged with latency and token counts, and the dashboard's Akash panel shows model, endpoint, call count, average latency and tokens. If the model fails, the agents fall back to SQL-only facts and the log says so.

**Guild.ai.** We published one agent on Guild, `garyjain5~aegis-incident-analyst` (version 1.0.1, validated), source in `guild/aegis-incident-analyst`. It takes an incident as JSON (facts from ClickHouse) and writes an incident report using only the facts in the input. We tested it on a made-up incident and the report was correct. **It is not wired into the live pipeline.** Sentinel, Bloodhound and Blacksmith are plain Python in `agents.py`, run by `pipeline.py`, and are not registered on Guild. Run the Guild agent with `guild agent test --workspace garyjain5~aegis-dev --mode json < sample-incident.json`. The command prints a "connection was aborted" message and exits 1, but the agent still finishes; the report is read with `guild session events <session-id>`.

**Senso.** Blacksmith saves every incident report to a Senso knowledge-base folder (`senso kb create-raw`), and the log prints `incident saved to Senso memory` only when the CLI call succeeded. Bloodhound also searches Senso for similar past incidents before it investigates; the search is optional and only runs if `SENSO_FOLDER_ID` is set in `.env`. TODO(team): add whether the search found a past incident in a later run. Until then, treat recall as unverified.

**Semgrep.** We ran Semgrep on the five Python files (655 lines): `dashboard.py`, `agents.py`, `generator.py`, `db.py`, `llm.py`. `--config auto` (290 community Python rules) plus `p/python`, `p/secrets` and `p/sql-injection` gave **0 findings and 0 errors**. These were free community rules only, since Semgrep was not logged in, so the cross-file data-flow rules (Pro) did not run. The scan ran after the code was written, so it did not shape the code.

**Pi.** Prize sponsor only, no integration. Our entry is the closed loop: detection, investigation and remediation without a human, instead of another detector.

## Design decisions

- **SQL does the scale work, the model does the judgment.** An LLM cannot score millions of events. ClickHouse reduces recent events to a handful of candidate sources, and the model only sees those.
- **The model proposes, code disposes.** Block rules from the model pass deterministic checks: external ranges no wider than /24, internal addresses only as exact /32, and a user is disabled only if the timeline confirmed it as compromised. Invented users or overbroad ranges are rejected.
- **A policy floor.** In early runs the model sometimes returned only the attacker CIDR and skipped disabling the compromised account, so the attack continued through the pivot host. Code now adds any confirmed compromised user or related pivot host the model left out, and the log says `policy floor added N rule(s) the model omitted`.
- **Re-check before blocking.** Blacksmith re-runs the compromised-account query right before it writes rules, so an account that was compromised after Bloodhound looked is still blocked in the same incident. The log line is `re-check before blocking found N newly compromised user(s)`.
- **Reports wait for quiet.** Incident reports are written once Sentinel has nothing new to handle, so a slow report call never delays detecting the next incident.
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
