# ---------------------------
# Windows Security Scanner (PowerShell)
# Output:
#   examination\data\windows_output.csv
#   examination\data\anomalies.log
# ---------------------------

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BaseDir   = Resolve-Path (Join-Path $ScriptDir "..")
$DataDir   = Join-Path $BaseDir "data"

$OutputCsv = Join-Path $DataDir "windows_output.csv"
$LogFile   = Join-Path $DataDir "anomalies.log"

$RiskyServices = @("Telnet", "RemoteRegistry", "Spooler")

function Get-Timestamp {
    (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

function Ensure-DataDir {
    if (-not (Test-Path $DataDir)) {
        New-Item -ItemType Directory -Path $DataDir | Out-Null
    }
    if (-not (Test-Path $LogFile)) {
        New-Item -ItemType File -Path $LogFile | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )
    $line = "{0} {1}: {2}" -f (Get-Timestamp), $Level, $Message
    $line | Out-File -FilePath $LogFile -Append -Encoding utf8
}

function Get-ServicesSafe {
    try {
        Get-Service | Select-Object Name, Status
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to read services: $($_.Exception.Message)"
        throw
    }
}

function Check-RiskyServices {
    param([Parameter(Mandatory=$true)]$Services)

    $hits = 0
    foreach ($svc in $Services) {
        if ($RiskyServices -contains $svc.Name) {
            Write-Log -Level "WARNING" -Message ("Risky Windows service detected: {0} (Status={1})" -f $svc.Name, $svc.Status)
            $hits++
        }
    }

    if ($hits -eq 0) {
        Write-Log -Level "INFO" -Message "No risky Windows services detected (Telnet/RemoteRegistry/Spooler)."
    }
}

# ---- MAIN ----
Ensure-DataDir
Write-Log -Level "INFO" -Message "Windows check started."

$services = Get-ServicesSafe

# Export CSV
$services | Export-Csv -NoTypeInformation -Path $OutputCsv -Encoding UTF8
Write-Log -Level "INFO" -Message "Wrote Windows CSV: $OutputCsv"

# Risk checks
Check-RiskyServices -Services $services

Write-Log -Level "INFO" -Message "Windows check completed."