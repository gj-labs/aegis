# CURRENT (AEGIS)
Team: <your name>, Richa Arora (richaarora4@gmail.com). Hard stop: submit by 4:00 PM PT (official 4:30).
State: schema, generator, queries, bench, 3 agents (agents.py), pipeline.py written. selftest.py passes (stub DB and model). Nothing run against real ClickHouse or Akash yet.
Settled: ClickHouse does the scale work; Akash model only classifies pre-filtered candidates; strict JSON from models; blocklist table closes the loop; traffic is synthetic and labeled as such.
Rejected: LLM scoring raw events, real network data, auth, polish.
Next: setup_db.py --baseline, bench.py, fill AKASH_* in .env, then run generator background, pipeline.py, generator attack. Then dashboard (FastAPI).
