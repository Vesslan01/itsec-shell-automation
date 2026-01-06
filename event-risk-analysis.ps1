# ====== KONFIGURATION ======
$LogFile = "event_risk_report.log"

# ====== LOGGFUNKTION ======
function Write-Log {
    param ([string]$Message)

    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    $entry | Tee-Object -FilePath $LogFile -Append
}

# ====== LÄS DATA ======
$users  = Import-Csv "users.csv"
$events = (Get-Content "events.json" | ConvertFrom-Json).events

# ====== ANALYS ======
foreach ($u in $users) {

    $name   = $u.username
    $status = $u.status.Trim().ToLower()

    $fails = ($events | Where-Object {
        $_.user -eq $name -and $_.event -eq "failed_login"
    }).Count

    if ($fails -ge 1 -and $status -eq "disabled") {
        Write-Log ("{0} - CRITICAL RISK (disabled + failed logins)" -f $name)
    }
    elseif ($fails -ge 3) {
        Write-Log ("{0} - HIGH RISK (3+ failed attempts)" -f $name)
    }
    elseif ($fails -ge 1) {
        Write-Log ("{0} - MEDIUM RISK (failed attempts)" -f $name)
    }
    else {
        Write-Log ("{0} - LOW RISK" -f $name)
    }
}

Write-Log "Analysis completed."