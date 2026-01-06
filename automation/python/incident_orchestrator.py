import json
import csv
import re
from pathlib import Path
from datetime import datetime

# ------------------------
# Paths (robust oavsett var du kör ifrån)
# ------------------------
SCRIPT_DIR = Path(__file__).resolve().parent           # automation/python
BASE_DIR = SCRIPT_DIR.parent                           # automation
DATA_DIR = BASE_DIR / "data"                           # automation/data

LINUX_JSON = DATA_DIR / "linux_processes.json"
WIN_CSV    = DATA_DIR / "windows_services.csv"
ANOM_LOG   = DATA_DIR / "anomalies.log"
AUTH_LOG   = DATA_DIR / "auth.log"

ALERTS_JSON  = DATA_DIR / "alerts.json"
INCIDENT_TXT = DATA_DIR / "incident_report.txt"

# ------------------------
# Indicators
# ------------------------
RISK_PROCESSES = {"nc", "netcat", "hydra", "john"}
RISK_SERVICES  = {"RemoteRegistry", "Telnet", "Spooler"}

LOG_PATTERNS = {
    "failed": re.compile(r"failed", re.IGNORECASE),
    "error": re.compile(r"error", re.IGNORECASE),
    "unauthorized": re.compile(r"unauthorized", re.IGNORECASE),
}

IP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

# ------------------------
# Helpers
# ------------------------
def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def read_csv_services(path: Path) -> list[str]:
    if not path.exists():
        return []
    services = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Export-Csv brukar ge "Name","Status"
            name = (row.get("Name") or row.get("name") or "").strip()
            if name:
                services.append(name)
    return services

def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n") for line in f]

def classify_severity(msg: str) -> str:
    # Enkel severity-kodning för sortering
    m = msg.upper()
    if m.startswith("CRITICAL"):
        return "CRITICAL"
    if m.startswith("HIGH"):
        return "HIGH"
    if m.startswith("MEDIUM"):
        return "MEDIUM"
    if m.startswith("WARNING"):
        return "WARNING"
    return "INFO"

def main() -> int:
    incidents: list[str] = []

    # ------------------------
    # 1) Linux JSON
    # ------------------------
    linux_data = read_json(LINUX_JSON)
    linux_procs = []
    if "processes" in linux_data and isinstance(linux_data["processes"], list):
        for p in linux_data["processes"]:
            if isinstance(p, dict) and "name" in p:
                linux_procs.append(str(p["name"]).strip())
            elif isinstance(p, str):
                linux_procs.append(p.strip())

    linux_hits = sorted({p for p in linux_procs if p in RISK_PROCESSES})
    for p in linux_hits:
        incidents.append(f"CRITICAL: Riskprocess upptäckt – {p}")

    # ------------------------
    # 2) Windows CSV
    # ------------------------
    win_services = read_csv_services(WIN_CSV)
    win_hits = sorted({s for s in win_services if s in RISK_SERVICES})
    for s in win_hits:
        incidents.append(f"HIGH: Riskabel Windows-tjänst upptäckt – {s}")

    # ------------------------
    # 3) anomalies.log (från bash + ps)
    # ------------------------
    anomalies = read_lines(ANOM_LOG)
    if anomalies:
        for a in anomalies[-200:]:  # begränsa volymen lite
            if a.strip():
                incidents.append(f"INFO (anomalies.log): {a.strip()}")

    # ------------------------
    # 4) auth.log (bruteforce + indikatorer)
    # ------------------------
    auth_lines = read_lines(AUTH_LOG)

    ip_fail_count: dict[str, int] = {}
    auth_indicator_counts = {"failed": 0, "error": 0, "unauthorized": 0}

    for line in auth_lines:
        low = line.lower()

        # Indikatorer
        for key, rx in LOG_PATTERNS.items():
            if rx.search(line):
                auth_indicator_counts[key] += 1

        # IP fails (räknar bara rader som innehåller "failed")
        if "failed" in low:
            m = IP_REGEX.search(line)
            if m:
                ip = m.group(1)
                ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1

    # Brute-force per IP
    for ip, count in sorted(ip_fail_count.items(), key=lambda x: x[1], reverse=True):
        if count >= 5:
            incidents.append(f"CRITICAL: Brute-force-indikator från IP {ip} ({count} fails)")
        elif count >= 1:
            incidents.append(f"MEDIUM: Misstänkta felaktiga inloggningar från {ip} ({count} fails)")

    # Summera auth-indikatorer
    if any(auth_indicator_counts.values()):
        incidents.append(
            "INFO: auth.log summering – "
            + ", ".join([f"{k}={v}" for k, v in auth_indicator_counts.items()])
        )

    # ------------------------
    # 5) Notifiering (alerts.json)
    # ------------------------
    alerts_payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "paths": {
            "linux_processes": str(LINUX_JSON),
            "windows_services": str(WIN_CSV),
            "anomalies_log": str(ANOM_LOG),
            "auth_log": str(AUTH_LOG),
        },
        "alerts": [{"severity": classify_severity(i), "message": i} for i in incidents],
    }

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with ALERTS_JSON.open("w", encoding="utf-8") as f:
        json.dump(alerts_payload, f, indent=2, ensure_ascii=False)

    # ------------------------
    # 6) Slutrapport (incident_report.txt)
    # ------------------------
    with INCIDENT_TXT.open("w", encoding="utf-8") as f:
        f.write("=== INCIDENT SUMMARY ===\n")
        if not incidents:
            f.write("No incidents detected.\n")
        else:
            for inc in incidents:
                f.write(inc + "\n")

        f.write("\n=== FILES USED ===\n")
        for k, v in alerts_payload["paths"].items():
            f.write(f"{k}: {v}\n")

    # Terminalutskrift
    print("=== INCIDENT SUMMARY ===")
    if not incidents:
        print("- No incidents detected.")
    else:
        for inc in incidents:
            print("-", inc)

    print(f"\nSkapade:\n- {INCIDENT_TXT}\n- {ALERTS_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())