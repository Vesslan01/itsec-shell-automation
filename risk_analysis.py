import json
import csv
from pathlib import Path

EVENTS_FILE = Path("events.json")
USERS_FILE = Path("users.csv")
REPORT_FILE = Path("risk_report.txt")


def load_events(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Saknar fil: {path}")
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if "events" not in data or not isinstance(data["events"], list):
        raise ValueError("events.json måste innehålla en nyckel 'events' som är en lista.")
    return data["events"]


def load_users(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Saknar fil: {path}")
    users: dict[str, dict] = {}
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"username", "status"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError("users.csv måste ha headers: username,status")
        for row in reader:
            username = (row.get("username") or "").strip()
            status = (row.get("status") or "").strip().lower()
            if not username:
                continue
            users[username] = {"status": status, "fails": 0}
    return users


def count_failed_logins(events: list[dict], users: dict) -> None:
    for evt in events:
        user = evt.get("user")
        event_type = evt.get("event")
        if event_type == "failed_login" and user in users:
            users[user]["fails"] += 1


def classify_risk(status: str, fails: int) -> str:
    # BONUS: disabled + fails => CRITICAL
    if status == "disabled" and fails > 0:
        return "CRITICAL"
    if fails >= 3:
        return "HIGH"
    if fails >= 1:
        return "MEDIUM"
    return "LOW"


def write_report(path: Path, users: dict) -> None:
    # Sorterar för stabil output
    with path.open("w", encoding="utf-8", newline="") as report:
        for username in sorted(users.keys()):
            status = users[username]["status"]
            fails = users[username]["fails"]
            risk = classify_risk(status, fails)
            report.write(f"{username}: {risk} (fails: {fails}, status: {status})\n")


def main() -> None:
    users = load_users(USERS_FILE)
    events = load_events(EVENTS_FILE)

    count_failed_logins(events, users)
    write_report(REPORT_FILE, users)

    print(f"Analysen är klar. Se {REPORT_FILE}.")


if __name__ == "__main__":
    main()