# Teste 01 — Validacao de sintaxe do script principal
param([string]$ScriptPath = "/lab/PEagle.ps1")

$PASS = 0; $FAIL = 0

function Assert {
    param([string]$Name, [bool]$Condition, [string]$Detail="")
    if ($Condition) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        $script:PASS++
    } else {
        Write-Host "  [FAIL] $Name $(if ($Detail) { "— $Detail" })" -ForegroundColor Red
        $script:FAIL++
    }
}

Write-Host "`n=== TESTE 01: Sintaxe ===" -ForegroundColor Cyan

# 1.1 Arquivo existe
Assert "Arquivo existe" (Test-Path $ScriptPath)

# 1.2 Parser sem erros
$tokens = $null; $errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
Assert "Parser: zero erros de sintaxe" ($errors.Count -eq 0) "Erros: $($errors.Count)"
if ($errors.Count -gt 0) {
    $errors | Select-Object -First 5 | ForEach-Object {
        Write-Host "    L$($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor DarkRed
    }
}

# 1.3 Contem todos os modulos esperados
$content = Get-Content $ScriptPath -Raw
@("Invoke-SystemChecks","Invoke-NetworkChecks","Invoke-ServicesChecks",
  "Invoke-CredsChecks","Invoke-ADCSChecks","Invoke-ADChecks",
  "Invoke-ContainersChecks","Invoke-ModernChecks","Invoke-CVEChecks") | ForEach-Object {
    Assert "Funcao '$_' presente" ($content -match "function $_ ")
}

# 1.4 Checks ESC cobertos
@("ESC1","ESC2","ESC3","ESC4","ESC6","ESC7","ESC8","ESC9","ESC10","ESC11","ESC12","ESC13","ESC15","ESC16","ESC17") | ForEach-Object {
    Assert "Check $_ presente no ADCS" ($content -match $_)
}

# 1.5 OutputFormat no param block
Assert "Param -OutputFormat presente"  ($content -match '\[ValidateSet\("Text","Json","Csv"\)\]')
Assert "Param -OutputFile presente"    ($content -match '\[string\]\$OutputFile')

# 1.6 Contadores de findings declarados
Assert "CountCrit declarado"  ($content -match 'script:CountCrit')
Assert "CountHigh declarado"  ($content -match 'script:CountHigh')
Assert "script:Findings"      ($content -match 'script:Findings')

# 1.7 Sem Get-WmiObject remanescente (exceto na secao AV que usa Get-CimInstance)
$wmiLines = ($content -split "`n") | Where-Object { $_ -match "Get-WmiObject" -and $_ -notmatch "^#" }
Assert "Sem Get-WmiObject no codigo" ($wmiLines.Count -eq 0) "Linhas com Get-WmiObject: $($wmiLines.Count)"
if ($wmiLines.Count -gt 0) { $wmiLines | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed } }

# 1.8 EDR signatures completas
@("SentinelOne","Elastic EDR","Tanium","Cybereason","Carbon Black") | ForEach-Object {
    Assert "EDR '$_' na lista"  ($content -match $_)
}

# 1.9 CVEs cobertos
@("CVE-2020-0796","CVE-2020-1472","CVE-2021-34527","CVE-2021-41379",
  "CVE-2022-26923","CVE-2022-37969","CVE-2023-28252","CVE-2024-38193",
  "CVE-2025-21418","CVE-2025-29824") | ForEach-Object {
    Assert "CVE '$_' coberto" ($content -match [regex]::Escape($_))
}

# 1.10 Tokens de apps verificados
Assert "Tokens Teams/Slack verificados" ($content -match "Teams|Slack|Outlook.*token|token.*Outlook")
Assert "Modulo CVE no switch block"     ($content -match '"CVE"\s+\{.*Invoke-CVEChecks')

Write-Host ""
Write-Host "  Resultado: $PASS pass / $FAIL fail" -ForegroundColor $(if ($FAIL -eq 0) {"Green"} else {"Red"})
return $FAIL
