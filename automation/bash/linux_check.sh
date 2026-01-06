#!/bin/bash
set -euo pipefail

# Paths
output="../data/linux_processes.json"
logfile="../data/anomalies.log"

# Loggfunktion
log() {
  echo "$(date) - $1" | tee -a "$logfile"
}

# Processlista (Git Bash-kompatibel)
processes="$(ps | awk '{print $1}' | sort -u)"

# Riskprocesser (exempel)
risk=("nc" "netcat" "hydra" "john")

# Bygg JSON utan trailing comma
{
  echo '{"processes":['
  first=1
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if [[ $first -eq 1 ]]; then
      first=0
    else
      echo ','
    fi
    printf '{"name":"%s"}' "$p"
  done <<< "$processes"
  echo ']}' 
} > "$output"

# Detektion av riskprocesser
for r in "${risk[@]}"; do
  if echo "$processes" | grep -qi "^${r}$"; then
    log "VARNING – Riskprocess upptäckt: $r"
  fi
done

log "Linux-kontroll klar."

