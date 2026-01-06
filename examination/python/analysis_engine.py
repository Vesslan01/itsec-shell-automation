import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------
# Final Analysis Engine (Python)
# Inputs:
#   examination/data/linux_output.json
#   examination/data/windows_output.csv
#   examination/data/anomalies.log
#   examination/data/auth.log (optional)
# Outputs:
#   examination/report/final_report.txt
#   examination/data/alerts.json
# ---------------------------

RISK_PROCESSES = {"nc", "netcat", "hydra", "john"}
RISK_SERVICES = {"Telnet", "RemoteRegistry", "Spooler"}
LOG_INDICATORS = ("failed login", "error", "unauthorized", "failed")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARNING", "ERROR"]


@dataclass
class Alert:
    severity: str
    message: str


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def base_paths() -> Tuple[Path, Path, Path]:
    script_dir = Path(__file__).resolve().parent
    base_dir = script_dir.parent  # examination/
    data_dir = base_dir / "data"
    report_dir = base_dir / "report"
    return base_dir, data_dir, report_dir


def safe_read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None


def load_linux_processes(path: Path, alerts: List[Alert]) -> List[str]:
    raw = safe_read_text(path)
    if raw is None:
        alerts.append(Alert("ERROR", f"(linux) Missing file: {path}"))
        return []

    try:
        data = json.loads(raw)
        procs = data.get("processes", [])
        names = [p.get("name", "") for p in procs if isinstance(p, dict)]
        names = [n for n in names if n]
        return names
    except json.JSONDecodeError as e:
        alerts.append(Alert("ERROR", f"(linux) Invalid JSON in {path}: {e}"))
        return []


def load_windows_services(path: Path, alerts: List[Alert]) -> List[Dict[str, str]]:
    raw = safe_read_text(path)
    if raw is None:
        alerts.append(Alert("ERROR", f"(windows) Missing file: {path}"))
        return []

    try:
        rows: List[Dict[str, str]] = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # normalize keys
                name = (row.get("Name") or "").strip()
                status = (row.get("Status") or "").strip()
                if name:
                    rows.append({"Name": name, "Status": status})
        return rows
    except Exception as e:
        alerts.append(Alert("ERROR", f"(windows) Failed reading CSV {path}: {e}"))
        return []


def load_anomalies(path: Path, alerts: List[Alert]) -> List[str]:
    raw = safe_read_text(path)
    if raw is None:
        alerts.append(Alert("WARNING", f"(anomalies) Missing file: {path}"))
        return []
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    return lines


def parse_auth_log(path: Path, alerts: List[Alert]) -> Dict[str, int]:
    raw = safe_read_text(path)
    if raw is None:
        alerts.append(Alert("INFO", f"(auth) auth.log missing (optional): {path}"))
        return {}

    ip_counts: Dict[str, int] = {}
    ip_regex = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

    for line in raw.splitlines():
        low = line.lower()
        if "failed" in low:
            m = ip_regex.search(line)
            if m:
                ip = m.group(1)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

    return ip_counts


def classify_linux(processes: List[str], alerts: List[Alert]) -> None:
    hits = [p for p in processes if p.lower() in RISK_PROCESSES]
    if hits:
        for p in hits:
            alerts.append(Alert("CRITICAL", f"(linux) Risk process detected: {p}"))
    else:
        alerts.append(Alert("INFO", "(linux) OK: No known Linux risk processes detected."))


def classify_windows(services: List[Dict[str, str]], alerts: List[Alert]) -> None:
    hits = [s for s in services if s["Name"] in RISK_SERVICES]
    if hits:
        for s in hits:
            alerts.append(Alert("HIGH", f"(windows) Risky service detected: {s['Name']} (Status={s.get('Status','')})"))
    else:
        alerts.append(Alert("INFO", "(windows) OK: No risky Windows services detected (Telnet/RemoteRegistry/Spooler)."))


def classify_auth(ip_counts: Dict[str, int], alerts: List[Alert]) -> None:
    if not ip_counts:
        alerts.append(Alert("INFO", "(auth) No failed-login IP indicators found (or auth.log missing)."))
        return

    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        if count >= 5:
            alerts.append(Alert("CRITICAL", f"(auth) Brute-force indicator from IP {ip} ({count} fails)"))
        else:
            alerts.append(Alert("MEDIUM", f"(auth) Suspicious failed logins from IP {ip} ({count} fails)"))


def include_anomalies(anoms: List[str], alerts: List[Alert]) -> None:
    for a in anoms:
        # if anomalies already contains WARNING/ERROR etc, keep it as INFO but show source
        # (du kan senare förbättra till regex-mappning)
        alerts.append(Alert("INFO", f"(anomalies) {a}"))


def summarize(alerts: List[Alert]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    # ensure all keys exist for nice report
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARNING", "ERROR"]:
        counts.setdefault(sev, 0)
    return counts


def write_alerts_json(path: Path, alerts: List[Alert], paths_used: Dict[str, str]) -> None:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "paths": paths_used,
        "alerts": [{"severity": a.severity, "message": a.message} for a in alerts],
    }
    path.write_text(json.dumps(payload, indent=4, ensure_ascii=False), encoding="utf-8")


def write_final_report(path: Path, alerts: List[Alert], summary_counts: Dict[str, int], paths_used: Dict[str, str]) -> None:
    lines: List[str] = []
    lines.append("=== FINAL SECURITY REPORT ===")
    lines.append(f"Generated: {now_ts()}")
    lines.append("")
    lines.append("=== SUMMARY ===")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO", "WARNING", "ERROR"]:
        lines.append(f"{sev}: {summary_counts.get(sev, 0)}")
    lines.append("")
    lines.append("=== ALERTS ===")
    for a in alerts:
        lines.append(f"{a.severity}: {a.message}")
    lines.append("")
    lines.append("=== FILES USED ===")
    for k, v in paths_used.items():
        lines.append(f"{k}: {v}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    base_dir, data_dir, report_dir = base_paths()
    report_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    linux_path = data_dir / "linux_output.json"
    win_path = data_dir / "windows_output.csv"
    anom_path = data_dir / "anomalies.log"
    auth_path = data_dir / "auth.log"

    report_path = report_dir / "final_report.txt"
    alerts_json_path = data_dir / "alerts.json"

    alerts: List[Alert] = []

    linux_procs = load_linux_processes(linux_path, alerts)
    windows_svcs = load_windows_services(win_path, alerts)
    anomalies = load_anomalies(anom_path, alerts)
    ip_counts = parse_auth_log(auth_path, alerts)

    classify_linux(linux_procs, alerts)
    classify_windows(windows_svcs, alerts)
    classify_auth(ip_counts, alerts)
    include_anomalies(anomalies, alerts)

    paths_used = {
        "linux_output.json": str(linux_path),
        "windows_output.csv": str(win_path),
        "anomalies.log": str(anom_path),
        "auth.log": str(auth_path),
    }

    counts = summarize(alerts)
    write_final_report(report_path, alerts, counts, paths_used)
    write_alerts_json(alerts_json_path, alerts, paths_used)

    print("Created:")
    print(f"- {report_path}")
    print(f"- {alerts_json_path}")


if __name__ == "__main__":
    main()