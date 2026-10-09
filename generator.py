"""
Synthetic traffic for AEGIS. All data is synthetic.

  python generator.py background [--rate 1500]   steady normal traffic (leave running)
  python generator.py attack                     launch the 5-stage attack
  python generator.py attack --dry-run --speed 40   test locally, no database

Both modes read the `blocklist` table every second and drop blocked traffic, so a
rule written by Blacksmith visibly stops the attack. A block can be a CIDR/IP or a user.
"""
import argparse, ipaddress, random, sys, time, uuid

COLS = ["event_type", "src_ip", "user", "host", "success", "dns_query", "dns_rcode",
        "http_method", "http_path", "http_status", "bytes", "is_attack"]
TICK = 0.25
MAX_ATTACK_S = 150

ATT_IPS = [f"203.0.113.{i}" for i in range(66, 70)]   # TEST-NET-3 documentation range
PIVOT = "10.0.99.9"                                   # internal host the attacker pivots through
VICTIM = "user4242"
RECON_PATHS = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/.git/config",
               "/api/v1/users", "/backup.zip", "/server-status"]


def ev(et, ip, user="", host="", success=1, q="", rcode="", method="", path="",
       status=0, nbytes=0, atk=0):
    return (et, ip, user, host, success, q, rcode, method, path, status, nbytes, atk)


def normal_batch(n):
    rows = []
    for _ in range(n):
        r = random.random()
        ip = f"10.0.{random.randrange(16)}.{random.randrange(1, 251)}"
        user = f"user{random.randrange(5000)}"
        if r < 0.4:
            rows.append(ev("login", ip, user, f"host{random.randrange(200)}", int(random.random() > 0.03)))
        elif r < 0.7:
            rows.append(ev("dns", ip, user, "", 1, f"site{random.randrange(500)}.com",
                           "NXDOMAIN" if random.random() < 0.01 else "NOERROR"))
        else:
            rows.append(ev("http", ip, user, f"host{random.randrange(200)}", 1, "", "",
                           "GET" if random.random() < 0.9 else "POST", f"/p/{random.randrange(300)}",
                           500 if random.random() < 0.03 else 200, random.randrange(50000)))
    return rows


class Blocks:
    """Cached view of the blocklist table. Invalid values (e.g. from a model) are ignored."""
    def __init__(self, db):
        self.db, self.nets, self.users, self.last = db, [], set(), 0.0

    def refresh(self, force=False):
        if not force and time.time() - self.last < 1.0:
            return
        self.last = time.time()
        nets, users = [], set()
        for kind, value in self.db.blocks():
            try:
                if kind == "cidr":
                    nets.append(ipaddress.ip_network(value.strip(), strict=False))
                elif kind == "user":
                    users.add(value.strip())
            except ValueError:
                pass
        self.nets, self.users = nets, users

    def blocked(self, ip=None, user=None):
        if user and user in self.users:
            return True
        if ip:
            a = ipaddress.ip_address(ip)
            return any(a in n for n in self.nets)
        return False


class DB:
    def __init__(self):
        from db import get_client
        self.c = get_client()
        self.t = 0.0

    def insert(self, rows):
        if rows:
            self.c.insert("events", rows, column_names=COLS)   # ts defaults to server now64(3)

    def log(self, run_id, note):
        self.c.insert("attack_log", [(run_id, note)], column_names=["run_id", "note"])

    def blocks(self):
        return self.c.query("SELECT kind, value FROM blocklist "
                            "WHERE ts + toIntervalSecond(ttl_s) > now64(3)").result_rows


class Fake:
    """Dry-run sink. Simulates Blacksmith: CIDR block at sim t=20s, user block at t=26s."""
    def __init__(self):
        self.t, self.counts = 0.0, {}

    def insert(self, rows):
        for r in rows:
            k = (r[0], r[11])
            self.counts[k] = self.counts.get(k, 0) + 1

    def log(self, run_id, note):
        print(f"  [log] {note}")

    def blocks(self):
        out = []
        if self.t >= 20: out.append(("cidr", "203.0.113.64/28"))
        if self.t >= 26: out.append(("user", VICTIM))
        return out


def rate_rows(rate, dt):
    n = rate * dt
    return int(n) + (1 if random.random() < n - int(n) else 0)


def hexs(k):
    return "".join(random.choice("0123456789abcdef") for _ in range(k))


def run_background(db, rate):
    blocks = Blocks(db)
    print(f"background traffic ~{rate} events/s (Ctrl+C to stop)")
    sent, last, shown = 0, time.time(), 0.0
    while True:
        t0 = time.time()
        blocks.refresh()
        n = min(int(rate * (t0 - last)), rate * 2)
        last = t0
        rows = [r for r in normal_batch(n) if not blocks.blocked(r[1], r[2])]
        db.insert(rows)
        sent += len(rows)
        if t0 - shown > 5:
            shown = t0
            print(f"\r{sent:,} events sent", end="", flush=True)
        time.sleep(max(0.0, TICK - (time.time() - t0)))


def run_attack(db, speed):
    blocks, run_id = Blocks(db), uuid.uuid4().hex[:8]
    started = time.time()
    compromised, announced = False, set()

    def note(t, msg):
        print(f"[t={t:5.1f}s] {msg}")
        db.log(run_id, msg)

    def phase(t, name):
        if name not in announced:
            announced.add(name)
            note(t, f"phase:{name}")

    print(f"attack run {run_id}")
    db.log(run_id, "start")
    while True:
        t = (time.time() - started) * speed
        db.t = t
        blocks.refresh(force=True)
        dt = TICK * speed
        live = [ip for ip in ATT_IPS if not blocks.blocked(ip)]
        pivot_ok = compromised and not blocks.blocked(PIVOT, VICTIM)
        rows = []

        if live and t < 12:                                    # 1. recon: path scanning
            phase(t, "recon")
            for _ in range(rate_rows(150, dt)):
                ip = random.choice(live)
                rows.append(ev("http", ip, "", "web-gw", 0, "", "", "GET", random.choice(RECON_PATHS), 404, 300, 1))

        if live and 2 <= t < 90:                               # 2. password spray
            phase(t, "spray")
            rate = min(1200, 300 + (t - 2) * 25)
            for _ in range(rate_rows(rate, dt)):
                rows.append(ev("login", random.choice(live), f"user{random.randrange(5000)}",
                               "auth-gw", 0, atk=1))

        if live and t >= 7 and not compromised:               # 3. compromise
            compromised = True
            phase(t, "compromise")
            rows.append(ev("login", live[0], VICTIM, "auth-gw", 1, atk=1))
            pivot_ok = True

        if pivot_ok and t >= 9:                                # 4. lateral movement
            phase(t, "lateral")
            for _ in range(rate_rows(20, dt)):
                rows.append(ev("login", PIVOT, VICTIM, f"srv{random.randrange(1, 200)}", 1, atk=1))

        if pivot_ok and t >= 12:                               # 5. exfil over DNS tunnel + large POSTs
            phase(t, "exfil")
            for _ in range(rate_rows(60, dt)):
                rows.append(ev("dns", PIVOT, VICTIM, "", 1, f"{hexs(40)}.t.exfil-cdn.net",
                               "NXDOMAIN" if random.random() < 0.8 else "NOERROR", atk=1))
            for _ in range(rate_rows(2, dt)):
                rows.append(ev("http", PIVOT, VICTIM, "files-01", 1, "", "", "POST", "/upload",
                               200, random.randrange(2_000_000, 8_000_000), 1))

        db.insert(rows)

        spray_over = t >= 90
        active = (bool(live) and not spray_over) or pivot_ok
        if not active:
            reason = "contained" if (blocks.nets or blocks.users) else "ended"
            note(t, f"traffic_stopped:{reason}")
            break
        if t >= MAX_ATTACK_S:
            note(t, "traffic_stopped:timeout_not_contained")
            break
        time.sleep(TICK)
    if isinstance(db, Fake):
        print("event counts (type, is_attack):", dict(sorted(db.counts.items())))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["background", "attack"])
    ap.add_argument("--rate", type=int, default=1500)
    ap.add_argument("--speed", type=float, default=1.0, help="sim-time multiplier (testing only)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    db = Fake() if a.dry_run else DB()
    try:
        run_background(db, a.rate) if a.mode == "background" else run_attack(db, a.speed)
    except KeyboardInterrupt:
        sys.exit(0)
