# Teste 05 — Validacao de parametros e modulos individuais
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

Write-Host "`n=== TESTE 05: Parametros e Modulos ===" -ForegroundColor Cyan

# 5.1 Modulo invalido — PS deve rejeitar com ValidateSet (verifica exit code != 0)
$null = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module InvalidModule" 2>&1
Assert "-Module invalido rejeitado (exit!=0)" ($LASTEXITCODE -ne 0) "exit=$LASTEXITCODE"

# 5.2 OutputFormat invalido (exit code != 0)
$null = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -OutputFormat XML" 2>&1
Assert "-OutputFormat invalido rejeitado (exit!=0)" ($LASTEXITCODE -ne 0) "exit=$LASTEXITCODE"

# 5.3 Cada modulo executa sem excecao fatal — verifica que a saida contem o header do modulo
@("System","Network","Services","Creds","Modern","Containers","CVE") | ForEach-Object {
    $mod = $_
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    @"
. /lab/mocks/windows_mocks.ps1
& '$ScriptPath' -Module $mod
"@ | Set-Content $tmp
    $out = pwsh -NoProfile -NonInteractive -File $tmp 2>&1
    $ec  = $LASTEXITCODE
    Remove-Item $tmp -Force
    # Sucesso = script rodou E gerou output com banner PEagle
    $hasOutput = [bool]($out | Where-Object { "$_" -match "PEagle|SISTEMA|REDE|SERVICO|CREDENCIAIS|WINDOWS MODERNO|CONTAINERS|CVE|VULNERABILIDADES" })
    Assert "Modulo '$mod' produz output esperado" $hasOutput "exit=$ec"
}

# 5.4 Modulo System contem secoes esperadas
$sysOut = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module System" 2>&1
$sysStr = $sysOut -join "`n"
@("SISTEMA","AV","PowerShell") | ForEach-Object {
    Assert "Modulo System exibe secao '$_'" ([bool]($sysStr -match $_))
}

# 5.5 Modulo Network contem secoes esperadas
$netOut = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module Network" 2>&1
$netStr = $netOut -join "`n"
Assert "Modulo Network exibe interfaces"  ([bool]($netStr -match "Ethernet|Interface|REDE|IPv4"))
Assert "Modulo Network exibe hosts file"  ([bool]($netStr -match "hosts|HOSTS|Hosts"))

# 5.6 Modulo Modern contem token privileges
$modOut = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module Modern" 2>&1
$modStr = $modOut -join "`n"
Assert "Modulo Modern exibe Token privileges"     ([bool]($modStr -match "Token|privileges|SeImpersonate"))
Assert "Modulo Modern exibe WMI Subscriptions"    ([bool]($modStr -match "WMI"))
Assert "Modulo Modern exibe Defender exclusoes"   ([bool]($modStr -match "Defender|exclus"))

# 5.7 -OutputFile com Text cria arquivo de transcript
$tmpTxt = "/tmp/peagle_text_$PID.txt"
$null = pwsh -NoProfile -NonInteractive -Command ". /lab/mocks/windows_mocks.ps1; & '$ScriptPath' -Module System -OutputFile '$tmpTxt'" 2>&1
Assert "-OutputFile Text cria transcript" (Test-Path $tmpTxt)
if (Test-Path $tmpTxt) {
    $lines = (Get-Content $tmpTxt -ErrorAction SilentlyContinue).Count
    Assert "Transcript tem conteudo (>10 linhas)" ($lines -gt 10) "Linhas=$lines"
    Remove-Item $tmpTxt -Force
}

Write-Host ""
Write-Host "  Resultado: $PASS pass / $FAIL fail" -ForegroundColor $(if ($FAIL -eq 0) {"Green"} else {"Red"})
return $FAIL
