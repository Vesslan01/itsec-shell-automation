#!/bin/bash

logfile="user_risk_report.log"

log() {
    echo "$(date) - $1" | tee -a $logfile
}

while IFS=',' read -r username days status; do

    [[ "$username" == "username" ]] && continue

    if (( days > 180 )) && [[ "$status" == "disabled" ]]; then
        log "$username – KRITISK RISK (inaktiv > 180 dagar & disabled)"
    elif (( days > 180 )); then
        log "$username – HIGH RISK (inaktiv > 180 dagar)"
    elif (( days > 90 )); then
        log "$username – MEDIUM RISK (inaktiv > 90 dagar)"
    elif [[ "$status" == "disabled" ]]; then
        log "$username – WARNING (disabled men nyligen inloggad)"
    else
        log "$username – OK"
    fi

done < users.csv

log "Analys slutförd."
