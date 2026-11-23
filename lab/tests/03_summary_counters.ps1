# Teste 03 — Contadores e resumo executivo
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

Write-Host "`n=== TESTE 03: Contadores e Resumo Executivo ===" -ForegroundColor Cyan

# Rodar Modern (inclui Defender exclusoes e token privileges)
$output = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module Modern 2>&1"
$outputStr = $output -join "`n"

# 3.1 Resumo executivo presente
Assert "Resumo executivo exibido"     ([bool]($outputStr -match "RESUMO EXECUTIVO"))
Assert "Linha CRITICAL presente"      ([bool]($outputStr -match "CRITICAL:"))
Assert "Linha HIGH presente"          ([bool]($outputStr -match "HIGH:"))
Assert "Linha MEDIUM presente"        ([bool]($outputStr -match "MEDIUM:"))
Assert "Linha TOTAL presente"         ([bool]($outputStr -match "TOTAL:"))

# 3.2 Valores numericos nas linhas
$critLine  = $output | Where-Object { "$_" -match "^\s+CRITICAL:" }  | Select-Object -First 1
$highLine  = $output | Where-Object { "$_" -match "^\s+HIGH:" }      | Select-Object -First 1
$totalLine = $output | Where-Object { "$_" -match "^\s+TOTAL:" }     | Select-Object -First 1

Assert "Linha CRITICAL tem numero"   ([bool]("$critLine"  -match "\d+"))
Assert "Linha HIGH tem numero"       ([bool]("$highLine"  -match "\d+"))
Assert "Linha TOTAL tem numero"      ([bool]("$totalLine" -match "\d+"))

# 3.3 TOTAL = CRITICAL + HIGH + MEDIUM
if ("$critLine" -match "(\d+)") {
    $critVal  = [int]([regex]::Match("$critLine",  "\d+").Value)
    $highVal  = if ("$highLine" -match "(\d+)") { [int]([regex]::Match("$highLine", "\d+").Value) } else { 0 }
    $medLine  = $output | Where-Object { "$_" -match "^\s+MEDIUM:" } | Select-Object -First 1
    $medVal   = if ("$medLine" -match "(\d+)") { [int]([regex]::Match("$medLine", "\d+").Value) } else { 0 }
    $totalVal = if ("$totalLine" -match "(\d+)") { [int]([regex]::Match("$totalLine", "\d+").Value) } else { -1 }
    Assert "TOTAL = CRIT+HIGH+MED ($critVal+$highVal+$medVal)" `
           ($totalVal -eq ($critVal + $highVal + $medVal)) "TOTAL=$totalVal esperado=$($critVal+$highVal+$medVal)"
}

# 3.4 Defender exclusao detectada (mock retorna C:\Temp\bypass)
Assert "Defender exclusao detectada" ([bool]($outputStr -match "bypass|exclus|Exclusion|CRIT.*Temp|HIGH.*Temp"))

# 3.5 SeImpersonatePrivilege (mock whoami /priv retorna Enabled)
Assert "SeImpersonatePrivilege ATIVO detectado" ([bool]($outputStr -match "SeImpersonatePrivilege"))

# 3.6 Banner no modulo System
$sysOut = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module System 2>&1"
$sysStr = $sysOut -join "`n"
Assert "Banner PEagle exibido"  ([bool]($sysStr -match "PEagle"))
Assert "Hostname no banner"      ([bool]($sysStr -match "LAB-WIN2022|COMPUTERNAME"))

# 3.7 Json de Modern exporta findings
$tmpJson = "/tmp/peagle_sum_$PID.json"
pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module Modern -OutputFormat Json -OutputFile '$tmpJson' 2>`$null | Out-Null"
if (Test-Path $tmpJson) {
    $raw = Get-Content $tmpJson -Raw
    try {
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        $cnt = if ($parsed -is [array]) { $parsed.Count } else { 1 }
        Assert "Json Modern: pelo menos 1 finding exportado" ($cnt -gt 0) "Count=$cnt"
    } catch { Assert "Json Modern: JSON valido" $false $_.Exception.Message }
    Remove-Item $tmpJson -Force
} else { Assert "Json Modern: arquivo criado" $false }

Write-Host ""
Write-Host "  Resultado: $PASS pass / $FAIL fail" -ForegroundColor $(if ($FAIL -eq 0) {"Green"} else {"Red"})
return $FAIL
