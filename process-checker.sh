#!/bin/bash

logfile="process_check.log"

log() {
    echo "$(date) - $1" | tee -a $logfile
}

check_process() {
    local p=$1
    if pgrep "$p" &>/dev/null; then
        log "Processen '$p' körs."
    else
        log "VARNING: Processen '$p' körs inte."
    fi
}

run_checks() {
    local file=$1
    if [ ! -f "$file" ]; then
        log "FEL: Filen $file saknas."
        exit 1
    fi

    while read -r process; do
        check_process "$process"
    done < "$file"
}

run_checks "processlist.txt"
log "Kontroller slutförda."
