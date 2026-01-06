#!/bin/bash
set -euo pipefail

# ---------------------------
# Linux Security Scanner (Bash)
# Output:
#   examination/data/linux_output.json
#   examination/data/anomalies.log
# ---------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$BASE_DIR/data"

OUT_JSON="$DATA_DIR/linux_output.json"
LOG_FILE="$DATA_DIR/anomalies.log"

RISK_PROCS=("nc" "netcat" "hydra" "john")

ensure_paths() {
  mkdir -p "$DATA_DIR"
  touch "$LOG_FILE"
}

log() {
  local level="$1"; shift
  local msg="$*"
  printf '%s %s: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$msg" | tee -a "$LOG_FILE" >/dev/null
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || {
    log "ERROR" "Missing command: $cmd"
    exit 1
  }
}

get_processes() {
  # Git Bash kan ha en annan ps; detta funkar oftast:
  # - Lista kommando-namn, unique, inga CR
  ps -eo comm --no-headers 2>/dev/null \
    | tr -d '\r' \
    | sed '/^\s*$/d' \
    | sort -u
}

export_json() {
  local procs="$1"

  {
    echo '{"processes":['
    local first=1
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      if [[ $first -eq 1 ]]; then
        first=0
      else
        echo ','
      fi
      # Enkel JSON-safe (processnamn brukar vara “snälla”)
      printf '{"name":"%s"}' "$p"
    done <<< "$procs"
    echo ']}'
  } > "$OUT_JSON"

  log "INFO" "Wrote Linux JSON: $OUT_JSON"
}

check_risks() {
  local procs="$1"
  local found=0

  for r in "${RISK_PROCS[@]}"; do
    if echo "$procs" | grep -qiE "^${r}$"; then
      log "WARNING" "Riskprocess detected: $r"
      found=1
    fi
  done

  if [[ $found -eq 0 ]]; then
    log "INFO" "No known Linux risk processes detected."
  fi
}

main() {
  ensure_paths
  require_cmd ps
  require_cmd grep
  require_cmd sort

  log "INFO" "Linux check started."

  local procs
  procs="$(get_processes || true)"

  if [[ -z "${procs// }" ]]; then
    log "WARNING" "Process list empty (unexpected)."
  fi

  export_json "$procs"
  check_risks "$procs"

  log "INFO" "Linux check completed."
}

main "$@"