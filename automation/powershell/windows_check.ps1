$ErrorActionPreference = "Stop"

$Output  = "../data/windows_services.csv"
$LogFile = "../data/anomalies.log"

function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date) - $Message"
    $entry | Out-File -FilePath $LogFile -Append -Encoding utf8
}

# Hämta tjänster
$services = Get-Service | Select-Object Name, Status

# Exportera CSV (Python läser denna senare)
$services | Export-Csv -NoTypeInformation -Path $Output -Encoding utf8

# Exempel på risk-tjänster (kan vara olika på olika Windows)
$risky = @("Telnet", "RemoteRegistry", "Spooler")

foreach ($svc in $services) {
    if ($risky -contains $svc.Name) {
        Write-Log "VARNING – Riskabel Windows-tjänst upptäckt: $($svc.Name)"
    }
}

Write-Log "Windows-kontroll klar."
