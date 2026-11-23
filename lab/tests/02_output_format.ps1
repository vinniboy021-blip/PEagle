# Teste 02 — OutputFormat Json e Csv
param([string]$ScriptPath = "/lab/PEagle.ps1")

$PASS = 0; $FAIL = 0

function Assert {
    param([string]$Name, [bool]$Condition, [string]$Detail="")
    if ($Condition) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green; $script:PASS++
    } else {
        Write-Host "  [FAIL] $Name $(if ($Detail) { "— $Detail" })" -ForegroundColor Red; $script:FAIL++
    }
}

Write-Host "`n=== TESTE 02: OutputFormat (Json/Csv) ===" -ForegroundColor Cyan

# 2.1 OutputFormat Json com arquivo de saida
$tmpJson = "/tmp/peagle_test_$PID.json"
pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module System -OutputFormat Json -OutputFile '$tmpJson' 2>`$null | Out-Null"
Assert "OutputFormat Json -OutputFile: arquivo criado" (Test-Path $tmpJson)
$jsonValid = $false
if (Test-Path $tmpJson) {
    $content = Get-Content $tmpJson -Raw -ErrorAction SilentlyContinue
    if ($content -and $content.Trim()) {
        try { $parsed = $content | ConvertFrom-Json -ErrorAction Stop; $jsonValid = $true } catch {}
    }
}
Assert "OutputFormat Json -OutputFile: JSON valido" $jsonValid
if ($jsonValid) {
    $hasSev  = [bool]($parsed | Get-Member -Name Severity -ErrorAction SilentlyContinue)
    $hasSec  = [bool]($parsed | Get-Member -Name Section  -ErrorAction SilentlyContinue)
    $hasMsg  = [bool]($parsed | Get-Member -Name Message  -ErrorAction SilentlyContinue)
    Assert "Json: campo Severity presente" $hasSev
    Assert "Json: campo Section presente"  $hasSec
    Assert "Json: campo Message presente"  $hasMsg
    $cnt = if ($parsed -is [array]) { $parsed.Count } else { 1 }
    Assert "Json: pelo menos 1 finding" ($cnt -gt 0) "Count=$cnt"
    if ($cnt -gt 0) {
        $first = if ($parsed -is [array]) { $parsed[0] } else { $parsed }
        Assert "Json: Severity valido" ($first.Severity -in @("CRITICAL","HIGH","MEDIUM")) "Val=$($first.Severity)"
    }
}
if (Test-Path $tmpJson) { Remove-Item $tmpJson -Force }

# 2.2 OutputFormat Csv com arquivo de saida
$tmpCsv = "/tmp/peagle_test_$PID.csv"
pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module System -OutputFormat Csv -OutputFile '$tmpCsv' 2>`$null | Out-Null"
Assert "OutputFormat Csv -OutputFile: arquivo criado" (Test-Path $tmpCsv)
if (Test-Path $tmpCsv) {
    $raw = Get-Content $tmpCsv -Raw -ErrorAction SilentlyContinue
    Assert "OutputFormat Csv: tem cabecalho Severity"  ([bool]($raw -match "Severity"))
    Assert "OutputFormat Csv: tem virgulas"            ([bool]($raw -match '","'))
    $rows = Import-Csv $tmpCsv -ErrorAction SilentlyContinue
    Assert "OutputFormat Csv: importavel"              ([bool]$rows)
    if ($rows) {
        Assert "OutputFormat Csv: coluna Severity"     ([bool]($rows | Get-Member -Name Severity -ErrorAction SilentlyContinue))
    }
    Remove-Item $tmpCsv -Force
}

# 2.3 OutputFormat Text (default) nao cria arquivo Json nem Csv
$tmpTxt = "/tmp/peagle_text_$PID.txt"
pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module System -OutputFile '$tmpTxt' 2>`$null | Out-Null"
Assert "OutputFormat Text -OutputFile: cria transcript" (Test-Path $tmpTxt)
if (Test-Path $tmpTxt) { Remove-Item $tmpTxt -Force }

Write-Host ""
Write-Host "  Resultado: $PASS pass / $FAIL fail" -ForegroundColor $(if ($FAIL -eq 0) {"Green"} else {"Red"})
return $FAIL
