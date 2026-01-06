$LogFile = "user_risk_report.log"

function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date) - $Message"
    $entry | Tee-Object -FilePath $LogFile -Append
}

$users = Import-Csv "users.csv"

foreach ($u in $users) {
    $name = $u.username
    $days = [int]$u.last_login_days
    $status = $u.status

    if ($days -gt 180 -and $status -eq "disabled") {
        Write-Log "$name - KRITISK RISK (inaktiv > 180 dagar och disabled)"
    }
    elseif ($days -gt 180) {
        Write-Log "$name - HIGH RISK (inaktiv > 180 dagar)"
    }
    elseif ($days -gt 90) {
        Write-Log "$name - MEDIUM RISK (inaktiv > 90 dagar)"
    }
    elseif ($status -eq "disabled" -and $days -lt 30) {
        Write-Log "$name - WARNING (disabled men nyligen inloggad)"
    }
    else {
        Write-Log "$name - OK"
    }
}

Write-Log "Analys slutförd."