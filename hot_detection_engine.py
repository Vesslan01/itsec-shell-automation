import csv
import json
import re
from pathlib import Path
from datetime import datetime
from collections import Counter


# ----------------------------
# Config
# ----------------------------
USERS_CSV = Path("users.csv")
EVENTS_JSON = Path("events.json")
AUTH_LOG = Path("auth.log")
REPORT_FILE = Path("final_report.txt")


# ----------------------------
# Helpers
# ----------------------------
def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Missing required file: {path}")


def load_users(csv_path: Path) -> dict:
    """
    Returns dict:
      users[username] = {"status": "active/disabled", "fails": 0}
    """
    require_file(csv_path)
    users = {}
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required_cols = {"username", "status"}
        if not reader.fieldnames or not required_cols.issubset(set(reader.fieldnames)):
            raise ValueError(f"{csv_path} must contain columns: username,status")

        for row in reader:
            username = (row.get("username") or "").strip()
            status = (row.get("status") or "").strip().lower()
            if not username:
                continue
            if status not in {"active", "disabled"}:
                status = "active"  # default safe fallback
            users[username] = {"status": status, "fails": 0}

    return users


def load_events(json_path: Path) -> list[dict]:
    require_file(json_path)
    with json_path.open(encoding="utf-8") as f:
        data = json.load(f)

    events = data.get("events")
    if not isinstance(events, list):
        raise ValueError(f"{json_path} must contain a top-level 'events' list")
    return events


def apply_event_fails(users: dict, events: list[dict]) -> dict:
    """
    Count failed_login events per user.
    If user not in CSV -> track under 'unknown_users' bucket.
    """
    unknown_users = Counter()

    for e in events:
        user = (e.get("user") or "").strip()
        ev = (e.get("event") or "").strip().lower()

        if ev != "failed_login":
            continue
        if not user:
            continue

        if user in users:
            users[user]["fails"] += 1
        else:
            unknown_users[user] += 1

    return {"unknown_users": unknown_users}


def parse_auth_log_ips(log_path: Path) -> Counter:
    """
    Count failed lines per IP address in auth.log.
    Looks for 'failed' case-insensitively + first IPv4 in line.
    """
    require_file(log_path)
    ip_counts = Counter()

    ip_regex = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    failed_regex = re.compile(r"failed", re.IGNORECASE)

    with log_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if not failed_regex.search(line):
                continue
            m = ip_regex.search(line)
            if not m:
                continue
            ip = m.group(1)
            ip_counts[ip] += 1

    return ip_counts


# ----------------------------
# Risk logic
# ----------------------------
def classify_user(status: str, fails: int) -> str:
    """
    Rules (from lesson):
      disabled + fails >= 1 -> CRITICAL
      fails >= 3 -> HIGH RISK
      fails >= 1 -> MEDIUM RISK
      else -> LOW RISK
    """
    if status == "disabled" and fails >= 1:
        return "CRITICAL"
    if fails >= 3:
        return "HIGH RISK"
    if fails >= 1:
        return "MEDIUM RISK"
    return "LOW RISK"


def classify_ip(fails: int) -> str:
    """
    Rules (from lesson):
      fails >= 5 -> BRUTE FORCE SUSPECT
      fails >= 1 -> SUSPICIOUS
      else -> LOW
    """
    if fails >= 5:
        return "BRUTE FORCE SUSPECT"
    if fails >= 1:
        return "SUSPICIOUS"
    return "LOW"


# ----------------------------
# Reporting
# ----------------------------
def write_report(report_path: Path, users: dict, ip_counts: Counter, unknown_users: Counter) -> None:
    # Summary stats
    user_risks = Counter()
    for u, info in users.items():
        user_risks[classify_user(info["status"], info["fails"])] += 1

    with report_path.open("w", encoding="utf-8") as r:
        r.write(f"Report generated: {now_ts()}\n")
        r.write("=== USER RISK REPORT ===\n")
        for username in sorted(users.keys()):
            info = users[username]
            risk = classify_user(info["status"], info["fails"])
            r.write(f"{username}: {risk} (fails={info['fails']}, status={info['status']})\n")

        r.write("\n=== IP RISK REPORT ===\n")
        if ip_counts:
            for ip, count in ip_counts.most_common():
                r.write(f"{ip}: {classify_ip(count)} (fails={count})\n")
        else:
            r.write("No failed-login IPs found in auth.log\n")

        if unknown_users:
            r.write("\n=== UNKNOWN USERS (in events.json but not in users.csv) ===\n")
            for user, count in unknown_users.most_common():
                r.write(f"{user}: failed_login={count}\n")

        r.write("\n=== SUMMARY ===\n")
        r.write(f"Total users in CSV: {len(users)}\n")
        r.write(f"Total IPs with failed attempts: {len(ip_counts)}\n")
        r.write("User risk counts:\n")
        for k in ["CRITICAL", "HIGH RISK", "MEDIUM RISK", "LOW RISK"]:
            r.write(f"  {k}: {user_risks.get(k, 0)}\n")


def main() -> int:
    try:
        users = load_users(USERS_CSV)
        events = load_events(EVENTS_JSON)

        meta = apply_event_fails(users, events)
        unknown_users = meta["unknown_users"]

        ip_counts = parse_auth_log_ips(AUTH_LOG)

        write_report(REPORT_FILE, users, ip_counts, unknown_users)

        print(f"OK: Analysis complete. See {REPORT_FILE}")
        return 0

    except Exception as e:
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())