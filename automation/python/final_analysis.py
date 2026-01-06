import json
import csv
from pathlib import Path


# --- Robust paths: fungerar oavsett var du kör scriptet ifrån ---
BASE_DIR = Path(__file__).resolve().parent          # .../automation/python
DATA_DIR = BASE_DIR.parent / "data"                # .../automation/data

LINUX_JSON = DATA_DIR / "linux_processes.json"
WIN_CSV = DATA_DIR / "windows_services.csv"
ANOMALIES_LOG = DATA_DIR / "anomalies.log"
FINAL_REPORT = DATA_DIR / "final_security_report.txt"


def read_linux_processes(path: Path) -> list[str]:
    """Returnerar en lista med processnamn från linux_processes.json."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    procs = data.get("processes", [])
    names = []
    for p in procs:
        name = (p.get("name") or "").strip()
        if name:
            names.append(name)
    return names


def read_windows_services(path: Path) -> list[dict]:
    """Returnerar en lista av dictar från windows_services.csv."""
    services = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalisera nycklar om CSV:en har t.ex. "Name" och "Status"
            services.append(row)
    return services


def read_anomalies(path: Path) -> list[str]:
    """Returnerar rader från anomalies.log (utan newline)."""
    if not path.exists():
        return []
    return [line.rstrip("\n") for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]


def main() -> None:
    # --- Snälla, tydliga fel om filer saknas ---
    missing = [p for p in [LINUX_JSON, WIN_CSV, ANOMALIES_LOG] if not p.exists()]
    if missing:
        print("FEL: Saknade filer i automation/data:")
        for p in missing:
            print(f" - {p}")
        print("\nKör först:")
        print(" - automation/bash/linux_check.sh")
        print(" - automation/powershell/windows_check.ps1")
        return

    linux_processes = read_linux_processes(LINUX_JSON)
    windows_services = read_windows_services(WIN_CSV)
    anomalies = read_anomalies(ANOMALIES_LOG)

    report: list[str] = []

    # --- Risklogik ---
    linux_risk_list = {"nc", "netcat", "hydra", "john"}
    win_risk_services = {"Telnet", "RemoteRegistry", "Spooler"}

    # Linux riskprocesser
    hits = sorted({p for p in linux_processes if p.lower() in linux_risk_list})
    if hits:
        for p in hits:
            report.append(f"CRITICAL: Linux riskprocess upptäckt – {p}")
    else:
        report.append("OK: Inga kända Linux-riskprocesser upptäckta.")

    # Windows riskabla tjänster
    found_services = []
    for svc in windows_services:
        # Vanliga headers: Name/Status (som i din lektion)
        name = (svc.get("Name") or svc.get("name") or "").strip()
        status = (svc.get("Status") or svc.get("status") or "").strip()
        if name in win_risk_services:
            found_services.append((name, status))

    if found_services:
        for name, status in found_services:
            report.append(f"WARNING: Riskabel Windows-tjänst – {name} (Status={status})")
    else:
        report.append("OK: Inga riskabla Windows-tjänster i listan (Telnet/RemoteRegistry/Spooler).")

    # Lägg med anomalies.log
    report.append("")
    report.append("=== ANOMALIES LOG ===")
    if anomalies:
        report.extend(anomalies)
    else:
        report.append("(tom)")

    # --- Skriv slutrapport ---
    FINAL_REPORT.parent.mkdir(parents=True, exist_ok=True)
    with FINAL_REPORT.open("w", encoding="utf-8", newline="\n") as f:
        for line in report:
            f.write(line + "\n")

    print(f"Slutrapport skapad: {FINAL_REPORT}")


if __name__ == "__main__":
    main()