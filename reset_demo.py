"""python3 reset_demo.py -> clear blocklist, incidents, logs and attack events. Keeps the 10M baseline.
Run this between attack runs, otherwise the previous run's block rules (1h TTL) block the new attack instantly."""
from db import get_client

c = get_client()
for t in ["blocklist", "incidents", "agent_log", "attack_log"]:
    c.command(f"TRUNCATE TABLE {t}")
c.command("ALTER TABLE events DELETE WHERE is_attack = 1 SETTINGS mutations_sync = 1")   # housekeeping only, never used by detectors
print("demo state cleared (baseline kept)")
