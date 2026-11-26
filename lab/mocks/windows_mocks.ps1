# Mock layer — substitui cmdlets Windows-only por versoes que retornam dados de teste
# Carregado antes de cada teste para permitir execucao no Linux PS

# ── Registry ──────────────────────────────────────────────────────────────────
function Get-ItemProperty {
    param($Path, $Name, $ErrorAction)
    $data = @{
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL"    = @{ RunAsPPL = 1 }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"     = @{ AlwaysInstallElevated = 0 }
        "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"     = @{ AlwaysInstallElevated = 0 }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
            EnableLUA = 1; ConsentPromptBehaviorAdmin = 5
        }
        "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" = @{ StrongCertificateBindingEnforcement = 1 }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" = @{ WUServer = "https://wsus.corp.local" }
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{ CachedLogonsCount = "3" }
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" = @{ UseLogonCredential = 0 }
    }
    $result = $data[$Path]
    if (-not $result) {
        if ($ErrorAction -eq "Stop") { throw "Registry key not found: $Path" }
        return $null
    }
    if ($Name -and -not $result[$Name]) {
        if ($ErrorAction -eq "Stop") { throw "Value $Name not found" }
        return $null
    }
    return [PSCustomObject]$result
}

# ── CimInstance / WmiObject ───────────────────────────────────────────────────
function Get-CimInstance {
    param($ClassName, $Namespace, $Filter, $ErrorAction)
    switch ($ClassName) {
        "Win32_OperatingSystem"   { return [PSCustomObject]@{ Caption="Windows Server 2022 Datacenter"; Version="10.0.20348"; LastBootUpTime=[datetime]"2024-01-01 08:00:00" } }
        "Win32_Processor"         { return [PSCustomObject]@{ Name="Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz"; NumberOfCores=8 } }
        "Win32_ComputerSystem"    { return [PSCustomObject]@{ TotalPhysicalMemory=17179869184; Model="PowerEdge R640"; Manufacturer="Dell Inc."; PartOfDomain=$true; SMBIOSBIOSVersion="2.9.0" } }
        "Win32_BIOS"              { return [PSCustomObject]@{ SMBIOSBIOSVersion="2.9.0 Dell Inc." } }
        "Win32_DiskDrive"         { return @() }
        "AntiVirusProduct"        { return @([PSCustomObject]@{ displayName="Windows Defender"; productState=397568 }) }
        "__EventFilter"           { return @() }
        "__EventConsumer"         { return @() }
        default                   { return @() }
    }
}

function Get-WmiObject { Get-CimInstance @args }

# ── Network ───────────────────────────────────────────────────────────────────
function Get-NetIPAddress {
    return @(
        [PSCustomObject]@{ AddressFamily="IPv4"; InterfaceAlias="Ethernet0"; IPAddress="10.10.10.50"; PrefixLength=24 },
        [PSCustomObject]@{ AddressFamily="IPv4"; InterfaceAlias="Loopback";  IPAddress="127.0.0.1";   PrefixLength=8  }
    )
}
function Get-NetRoute { return @() }
function Get-NetNeighbor {
    return @(
        [PSCustomObject]@{ IPAddress="10.10.10.1"; LinkLayerAddress="aa-bb-cc-dd-ee-ff"; State="Reachable" }
    )
}
function Get-NetFirewallProfile { return [PSCustomObject]@{ Enabled=$true } }
function Get-NetFirewallRule { return @() }

# ── Processos e Servicos ──────────────────────────────────────────────────────
function Get-Service {
    return @(
        [PSCustomObject]@{ Name="Spooler"; DisplayName="Print Spooler"; Status="Running"; StartType="Automatic" },
        [PSCustomObject]@{ Name="wuauserv"; DisplayName="Windows Update"; Status="Running"; StartType="Automatic" }
    )
}

function Get-Process {
    param($Id, $ErrorAction)
    if ($Id) { return [PSCustomObject]@{ ProcessName="svchost"; Id=$Id } }
    return @(
        [PSCustomObject]@{ ProcessName="MsMpEng";  Id=1234 },
        [PSCustomObject]@{ ProcessName="svchost";  Id=5678 },
        [PSCustomObject]@{ ProcessName="lsass";    Id=9012 }
    )
}

function Get-ScheduledTask { return @() }

# ── FileSystem / ACL ──────────────────────────────────────────────────────────
function Get-Acl {
    param($Path)
    return [PSCustomObject]@{ Access = @() }
}
function Get-Volume { return @() }
function Get-ChildItem {
    param($Path, $Recurse, $Include, $Depth, $ErrorAction, $Filter)
    return @()
}
function Get-Item { param($Path); return $null }
function Test-Path { param($Path); return $false }

# ── Usuarios e Grupos ─────────────────────────────────────────────────────────
function Get-LocalGroup { return @() }
function Get-LocalGroupMember {
    param($GroupName, $ErrorAction)
    if ($GroupName -eq "Administrators") {
        return @([PSCustomObject]@{ Name="CORP\Domain Admins"; ObjectClass="Group" })
    }
    return @()
}
function Get-LocalUser { return @() }

# ── Misc Windows ──────────────────────────────────────────────────────────────
function Get-MpPreference {
    param($ErrorAction)
    return [PSCustomObject]@{
        ExclusionPath             = @("C:\Temp\bypass")
        ExclusionProcess          = @()
        ExclusionExtension        = @()
        DisableRealtimeMonitoring = $false
        DisableIOAVProtection     = $false
    }
}
function Get-WindowsOptionalFeature { return $null }
function Get-AppLockerPolicy { throw "AppLocker not available" }
function Get-HotFix { return @() }
function Get-Command {
    param($Name, $ErrorAction)
    if ($ErrorAction -eq "Stop") { throw "Command not found: $Name" }
    return $null
}

# ── Variavel de ambiente Windows ──────────────────────────────────────────────
if (-not $env:COMPUTERNAME)  { $env:COMPUTERNAME  = "LAB-WIN2022" }
if (-not $env:USERDOMAIN)    { $env:USERDOMAIN    = "CORP" }
if (-not $env:USERNAME)      { $env:USERNAME      = "labuser" }
if (-not $env:USERPROFILE)   { $env:USERPROFILE   = "/tmp/userprofile" }
if (-not $env:SystemRoot)    { $env:SystemRoot     = "C:\Windows" }
if (-not $env:SystemDrive)   { $env:SystemDrive   = "C:" }
if (-not $env:TEMP)          { $env:TEMP          = "/tmp" }

# ── Executaveis externos ──────────────────────────────────────────────────────
function whoami {
    param($arg)
    $privLines = @(
        "Privilege Name                  Description                    State",
        "============================    ===========================    =======",
        "SeImpersonatePrivilege          Impersonate a client           Enabled",
        "SeDebugPrivilege                Debug programs                 Disabled",
        "SeChangeNotifyPrivilege         Bypass traverse checking       Enabled"
    )
    $groupLines = @("CORP\Domain Users", "BUILTIN\Users", "NT AUTHORITY\Authenticated Users")
    if ($arg -eq "/priv")   { return $privLines }
    if ($arg -eq "/groups") { return $groupLines }
    if ($arg -eq "/all")    { return ($groupLines + $privLines) }
    return "$env:USERDOMAIN\$env:USERNAME"
}

function netstat { return @() }
function ipconfig { return @("Windows IP Configuration") }
function arp { return @() }
function route { return @() }
function net { return @() }
function wsl { return @() }
function docker { return @() }
function kubectl { throw "kubectl not found" }
function netsh { return @() }
