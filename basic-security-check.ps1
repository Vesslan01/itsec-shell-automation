$LogFile = "security_log.txt"

function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date) - $Message"
    $entry | Tee-Object -FilePath $LogFile -Append
}

function Check-File {
    param([string]$Path)
    if (Test-Path $Path) {
        Write-Log "Filen '$Path' finns."
        (Get-Item $Path).Attributes | Out-String | Tee-Object -FilePath $LogFile -Append
    }
    else {
        Write-Log "VARNING: Filen '$Path' saknas."
    }
}

function Check-User {
    param([string]$User)
    try {
        $exists = (Get-LocalUser -Name $User -ErrorAction Stop)
        Write-Log "Användaren '$User' finns."
    }
    catch {
        Write-Log "VARNING: Användaren '$User' saknas."
    }
}

$File = Read-Host "Ange fil att kontrollera"
Check-File -Path $File

$User = Read-Host "Ange användarnamn att kontrollera"
Check-User -User $User

Write-Log "Kontroller slutförda."
