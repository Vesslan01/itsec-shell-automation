$InputFile = "sample.log"
$LogFile = "analysis.log"

function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date) - $Message"
    $entry | Tee-Object -FilePath $LogFile -Append
}

$failedCount = 0
$errorCount  = 0
$unauthCount = 0

foreach ($line in Get-Content $InputFile) {

    if ($line -match "failed") {
        Write-Log "Misslyckat inloggningsförsök: $line"
        $failedCount++
    }

    if ($line -match "error") {
        Write-Log "Error hittad: $line"
        $errorCount++
    }

    if ($line -match "unauthorized") {
        Write-Log "Obehörigt försök: $line"
        $unauthCount++
    }
}

Write-Log "ANALYS KLAR"
Write-Log "Antal misslyckade inloggningar: $failedCount"
Write-Log "Antal errors: $errorCount"
Write-Log "Antal obehöriga försök: $unauthCount"