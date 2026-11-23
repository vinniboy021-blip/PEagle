# Teste 04 — Logica de deteccao de EDR por processo
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

Write-Host "`n=== TESTE 04: Deteccao de EDR ===" -ForegroundColor Cyan

# Helper: escreve script temporario e executa
function Run-WithMock {
    param([string]$ExtraProcs, [string]$Module = "System")
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    @"
. /lab/mocks/windows_mocks.ps1
function Get-Process {
    param(`$Id, `$ErrorAction)
    if (`$Id) { return [PSCustomObject]@{ ProcessName='svchost'; Id=`$Id } }
    return @($ExtraProcs)
}
& '$ScriptPath' -Module $Module 2>&1
"@ | Set-Content $tmp
    $out = pwsh -NoProfile -NonInteractive -File $tmp 2>&1
    Remove-Item $tmp -Force
    return $out
}

# 4.1 MsMpEng → Windows Defender
$out1 = Run-WithMock '[PSCustomObject]@{ ProcessName="MsMpEng"; Id=1234 }, [PSCustomObject]@{ ProcessName="svchost"; Id=5678 }'
Assert "Defender detectado quando MsMpEng ativo" ([bool]($out1 | Where-Object { "$_" -match "Defender|MsMpEng" }))

# 4.2 SentinelAgent → SentinelOne
$out2 = Run-WithMock '[PSCustomObject]@{ ProcessName="SentinelAgent"; Id=1000 }'
Assert "SentinelOne detectado quando SentinelAgent ativo" ([bool]($out2 | Where-Object { "$_" -match "SentinelOne" }))

# 4.3 CSFalconService → CrowdStrike
$out3 = Run-WithMock '[PSCustomObject]@{ ProcessName="CSFalconService"; Id=3000 }'
Assert "CrowdStrike detectado quando CSFalconService ativo" ([bool]($out3 | Where-Object { "$_" -match "CrowdStrike" }))

# 4.4 Sem nenhum EDR → alerta desprotegido
$out4 = Run-WithMock '[PSCustomObject]@{ ProcessName="notepad"; Id=9999 }'
Assert "Alerta 'desprotegido' quando nenhum EDR" ([bool]($out4 | Where-Object { "$_" -match "desprotegido" }))

# 4.5 elastic-agent → Elastic EDR
$out5 = Run-WithMock '[PSCustomObject]@{ ProcessName="elastic-agent"; Id=5000 }'
Assert "Elastic EDR detectado via elastic-agent" ([bool]($out5 | Where-Object { "$_" -match "Elastic" }))

# 4.6 TaniumClient → Tanium
$out6 = Run-WithMock '[PSCustomObject]@{ ProcessName="TaniumClient"; Id=6000 }'
Assert "Tanium detectado via TaniumClient" ([bool]($out6 | Where-Object { "$_" -match "Tanium" }))

# 4.7 AV WMI inativo (productState 0x1000 = nibble3=0) → HIGH
$tmp7 = [System.IO.Path]::GetTempFileName() + ".ps1"
@"
. /lab/mocks/windows_mocks.ps1
function Get-CimInstance {
    param(`$ClassName, `$Namespace, `$ErrorAction)
    if (`$ClassName -eq 'AntiVirusProduct') {
        return @([PSCustomObject]@{ displayName='TestAV'; productState=0x1000 })
    }
    return @()
}
& '$ScriptPath' -Module System 2>&1
"@ | Set-Content $tmp7
$out7 = pwsh -NoProfile -NonInteractive -File $tmp7 2>&1
Remove-Item $tmp7 -Force
Assert "AV inativo (productState 0x1000) gera HIGH" ([bool]($out7 | Where-Object { "$_" -match "INATIVO|HIGH" }))

Write-Host ""
Write-Host "  Resultado: $PASS pass / $FAIL fail" -ForegroundColor $(if ($FAIL -eq 0) {"Green"} else {"Red"})
return $FAIL
