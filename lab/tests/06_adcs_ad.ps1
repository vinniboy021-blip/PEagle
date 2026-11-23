# Teste 06 — Logica de ADCS, AD, Timestamp e parametro -Fast
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

Write-Host "`n=== TESTE 06: ADCS, AD, Timestamp e -Fast ===" -ForegroundColor Cyan

# 6.1 Modulo ADCS executa sem excecao fatal e exibe secao ADCS
$adcsOut = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module ADCS 2>&1"
$adcsStr = $adcsOut -join "`n"
Assert "Modulo ADCS executa (banner PEagle)" ([bool]($adcsStr -match "PEagle"))
Assert "Modulo ADCS exibe secao ADCS"         ([bool]($adcsStr -match "ADCS|Active Directory Certificate|ESC"))

# 6.2 Codigo-fonte contem todas as verificacoes ESC (cobertura no fonte, nao no output runtime)
$content = Get-Content $ScriptPath -Raw
@("ESC1","ESC2","ESC3","ESC4","ESC6","ESC7","ESC8","ESC9","ESC10","ESC11","ESC12","ESC13","ESC15","ESC16","ESC17") | ForEach-Object {
    Assert "Fonte contem check $_" ($content -match $_)
}

# 6.3 ESC9 nao esta mais dentro de loop de CAs (bug de duplicacao corrigido)
# Verifica que nao existe "caContainer.Children" em bloco com "tplContainer" dentro
$esc9Section = $content -replace '(?s).*W-Sub "ESC9', '' -replace '(?s)W-Sub.*', ''
Assert "ESC9: DirectorySearcher fora do loop de CAs" (-not ($esc9Section -match '@\(\$caContainer\.Children\)'))

# 6.4 Modulo AD executa sem excecao fatal
$adOut = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module AD 2>&1"
$adStr = $adOut -join "`n"
Assert "Modulo AD executa (banner PEagle)" ([bool]($adStr -match "PEagle"))

# 6.5 AD verifica temas criticos (kerberoasting, ACL, delegacao)
@("Kerberoast|kerbero|SPN","Admin.*count|conta.*admin","ACL|delegac|delegat") | ForEach-Object {
    $pattern = $_
    # Verificar no fonte (nao runtime — AD sem LDAP nao gera output)
    Assert "Fonte AD cobre '$pattern'" ($content -match $pattern)
}

# 6.6 CVE modulo respeita build=0 (sem falso positivo de build)
$tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
@"
. /lab/mocks/windows_mocks.ps1
function Get-CimInstance {
    param(`$ClassName, `$Namespace, `$ErrorAction)
    if (`$ClassName -eq 'Win32_OperatingSystem') {
        return [PSCustomObject]@{ BuildNumber='0'; Caption='Windows Test'; Version='0.0.0'; OSArchitecture='64-bit'; LastBootUpTime=[datetime]::Now }
    }
    if (`$ClassName -eq 'Win32_ComputerSystem') {
        return [PSCustomObject]@{ PartOfDomain=`$false; Domain='WORKGROUP'; Manufacturer='Dell'; Model='Test'; TotalPhysicalMemory=8GB }
    }
    return @()
}
& '$ScriptPath' -Module CVE 2>&1
"@ | Set-Content $tmp
$cveOut = pwsh -NoProfile -NonInteractive -File $tmp 2>&1
Remove-Item $tmp -Force
$cveCritCount = ($cveOut | Where-Object { "$_" -match "^\s+\[CRIT\]" }).Count
Assert "CVE build=0 nao gera falso positivo de build ($cveCritCount CRITs)" ($cveCritCount -eq 0) "CRITs=$cveCritCount"

# 6.7 JSON export inclui campo Timestamp
$tmpJson = "/tmp/peagle_ts_$PID.json"
pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module Modern -OutputFormat Json -OutputFile '$tmpJson' 2>`$null | Out-Null"
if (Test-Path $tmpJson) {
    $raw = Get-Content $tmpJson -Raw -ErrorAction SilentlyContinue
    try {
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        $first = if ($parsed -is [array]) { $parsed[0] } else { $parsed }
        Assert "JSON export contem campo Timestamp" ([bool]($first.PSObject.Properties.Name -contains "Timestamp")) "campos=$($first.PSObject.Properties.Name -join ',')"
        # Verificar no raw JSON (ConvertFrom-Json converte para DateTime perdendo o formato string)
        Assert "Timestamp ISO 8601 no JSON raw" ([bool]($raw -match '"Timestamp"\s*:\s*"\d{4}-\d{2}-\d{2}T')) "raw=$($raw.Substring(0,[Math]::Min(200,$raw.Length)))"
    } catch { Assert "JSON valido para teste Timestamp" $false $_.Exception.Message }
    Remove-Item $tmpJson -Force
} else { Assert "JSON criado para teste Timestamp" $false }

# 6.8 Parametro -Fast aceito e pula COM Objects
$fastOut = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module Modern -Fast 2>&1"
$fastStr = $fastOut -join "`n"
Assert "Parametro -Fast aceito sem erro fatal" ([bool]($fastStr -match "PEagle"))
Assert "-Fast pula COM Objects (mensagem 'pulado')" ([bool]($fastStr -match "pulado.*Fast|Fast.*pulado|Fast.*ativo"))

# 6.9 W-Data trunca strings longas (> 120 chars)
$longStr = "A" * 150
$shortStr = "B" * 50
Assert "W-Data trunca em 120 chars (fonte)" ($content -match "\.Substring\(0,117\)")

# 6.10 Get-UserProfiles declarado no fonte
Assert "Get-UserProfiles declarado" ($content -match "function Get-UserProfiles")
Assert "Get-UserProfiles usa ProfileList registry" ($content -match "ProfileList")

Write-Host ""
Write-Host "  Resultado: $PASS pass / $FAIL fail" -ForegroundColor $(if ($FAIL -eq 0) {"Green"} else {"Red"})
return $FAIL
