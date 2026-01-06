import csv
import json
import re
from collections import defaultdict

USERS_CSV = "users.csv"
EVENTS_JSON = "events.json"
AUTH_LOG = "auth.log"
REPORT_FILE = "final_report.txt"

IP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
FAILED_REGEX = re.compile(r"failed", re.IGNORECASE)


def load_users(path: str) -> dict:
    users = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            username = (row.get("username") or "").strip()
            status = (row.get("status") or "").strip().lower()

            if not username:
                continue
            if status not in {"active", "disabled"}:
                # Default: om datan är kass, behandla som active (men man kan lika gärna flagga)
                status = "active"

            users[username] = {"status": status, "fails": 0}
    return users


def apply_event_fails(users: dict, path: str) -> None:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    events = data.get("events", [])
    for e in events:
        if e.get("event") == "failed_login":
            user = e.get("user")
            if user in users:
                users[user]["fails"] += 1


def parse_auth_log_for_ip_fails(path: str) -> dict:
    ip_fail_count = defaultdict(int)

    with open(path, encoding="utf-8") as f:
        for line in f:
            if FAILED_REGEX.search(line):
                m = IP_REGEX.search(line)
                if m:
                    ip_fail_count[m.group(1)] += 1

    return dict(ip_fail_count)


def classify_user(userinfo: dict) -> str:
    fails = userinfo["fails"]
    status = userinfo["status"]

    # Regeln “disabled + fails” trumfar allt
    if status == "disabled" and fails >= 1:
        return "CRITICAL"

    if fails >= 3:
        return "HIGH RISK"
    if fails >= 1:
        return "MEDIUM RISK"
    return "LOW RISK"


def classify_ip(fails: int) -> str:
    if fails >= 5:
        return "BRUTE FORCE SUSPECT"
    if fails >= 1:
        return "SUSPICIOUS"
    return "LOW"


def write_report(users: dict, ip_fails: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as r:
        r.write("=== USER RISK REPORT ===\n")
        for username in sorted(users.keys()):
            info = users[username]
            r.write(
                f"{username}: {classify_user(info)} "
                f"(fails={info['fails']}, status={info['status']})\n"
            )

        r.write("\n=== IP RISK REPORT ===\n")
        for ip in sorted(ip_fails.keys()):
            count = ip_fails[ip]
            r.write(f"{ip}: {classify_ip(count)} (fails={count})\n")


def main() -> None:
    users = load_users(USERS_CSV)
    apply_event_fails(users, EVENTS_JSON)
    ip_fails = parse_auth_log_for_ip_fails(AUTH_LOG)
    write_report(users, ip_fails, REPORT_FILE)
    print(f"Analys klar. Se {REPORT_FILE}.")


if __name__ == "__main__":
    main()