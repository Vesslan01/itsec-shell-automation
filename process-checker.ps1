$LogFile = "process_check.log"

function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date) - $Message"
    $entry | Tee-Object -FilePath $LogFile -Append
}

function Check-Process {
    param([string]$Name)

    if (Get-Process -Name $Name -ErrorAction SilentlyContinue) {
        Write-Log "Processen '$Name' körs."
    }
    else {
        Write-Log "VARNING: Processen '$Name' körs inte."
    }
}

function Run-Checks {
    param([string]$Path)

    if (-Not (Test-Path $Path)) {
        Write-Log "FEL: Filen $Path saknas."
        exit
    }

    foreach ($proc in Get-Content $Path) {
    $proc = $proc.Trim()
    if ($proc -eq "") { continue }
    Check-Process -Name $proc
}

}

Run-Checks "processlist.txt"
Write-Log "Kontroller slutförda."
