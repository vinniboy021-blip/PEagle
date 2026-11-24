# PEagle v2.1

```
        ___________                 ___
       |  _ \  ____|     /\        | \ \
       | |_) | |__      /  \       | |\ \
       |  __/|  __|    / /\ \  _   | | > >
       | |   | |____  / ____ \| |__| |/ /
       |_|   |______||_/    \_\______/_/

  v2.1  |  Windows Privilege Escalation Enumeration
```

Script PowerShell autossuficiente para enumeração de privilege escalation em Windows.
Zero dependências externas — basta o `.ps1`.

---

## Uso rápido

```powershell
# Scan completo (todos os módulos)
powershell -ep bypass -File PEagle.ps1

# Scan rápido (pula checks lentos)
powershell -ep bypass -File PEagle.ps1 -Fast

# Apenas CVEs
powershell -ep bypass -File PEagle.ps1 -Module CVE

# Export JSON com timestamp
powershell -ep bypass -File PEagle.ps1 -OutputFormat Json -OutputFile C:\out.json

# Salvar transcript completo
powershell -ep bypass -File PEagle.ps1 -OutputFile C:\scan.txt
```

---

## Parâmetros

| Parâmetro | Valores | Padrão | Descrição |
|-----------|---------|--------|-----------|
| `-Module` | `All` `System` `Network` `Services` `Creds` `AD` `ADCS` `Containers` `Modern` `CVE` | `All` | Módulo a executar |
| `-OutputFile` | caminho | — | Arquivo de saída |
| `-OutputFormat` | `Text` `Json` `Csv` | `Text` | Formato da saída estruturada |
| `-Fast` | switch | off | Pula COM objects (300 amostras) e enum completa de software |

---

## Módulos

### System
- Informações do OS, build, uptime
- Usuários e grupos locais (flag conta Admin)
- Hotfixes instalados
- Processos em execução com paths
- AV/EDR por processo e WMI (`productState` nibble decode)
- LSA RunAsPPL, Credential Guard + status VBS real
- WDigest, DCC2 cached credentials
- HiveNightmare (VSS + SAM legível)
- PowerShell versão, ScriptBlock Logging, CLM
- Software instalado com detecção de versões vulneráveis

### Network
- Interfaces e endereços IP
- Tabela de rotas
- Portas abertas com PID e processo
- Shares acessíveis
- Arquivo `hosts` (entradas suspeitas)
- Cache DNS / tabela ARP

### Services
- Serviços com binários em paths graváveis (via `icacls`)
- Tarefas agendadas com executáveis graváveis
- AlwaysInstallElevated
- Drivers de terceiros
- Serviços com DLL hijacking potential

### Creds
- PS History de todos os perfis (via `ProfileList` registry)
- Windows Credential Manager (`cmdkey /list`)
- DPAPI Vaults e Masterkeys
- SAM/SYSTEM/SECURITY acessíveis diretamente
- Arquivos sensíveis: `.config`, `.xml`, `.ini`, `.kdbx`, `.pfx`
- SSH private keys
- Tokens de Teams, Slack, Outlook (LevelDB/cookies)
- Cookies de Edge/Chrome/Brave (SSO/SAML)
- AWS credentials, Git credential store

### ADCS (ESC1–ESC17)
Detecta todas as misconfigurations conhecidas de Active Directory Certificate Services via LDAP:

| ESC | Vulnerabilidade |
|-----|----------------|
| ESC1 | Enrollee Supplies Subject + Client Auth |
| ESC2 | Any Purpose EKU |
| ESC3 | Certificate Request Agent |
| ESC4 | Template com ACL gravável |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 na CA |
| ESC7 | Manage CA / Manage Certificates |
| ESC8 | Web Enrollment HTTP sem NTLM relay protection |
| ESC9 | CT_FLAG_NO_SECURITY_EXTENSION (SID não embutido) |
| ESC10 | StrongCertificateBindingEnforcement desabilitado |
| ESC11 | CA sem IF_REQUIRESSL |
| ESC12 | OCSP com ACL gravável |
| ESC13 | OID Group Link para grupo privilegiado |
| ESC15 | szOID_NTDS_CA_SECURITY_EXT ausente |
| ESC16 | szOID_NTDS_CA_SECURITY_EXT desabilitado na CA |
| ESC17 | Kerberos Armor desabilitado |

### AD
- Kerberoastable accounts (SPN sem filtro MSA)
- ASREPRoastable accounts
- AdminSDHolder inconsistências
- Delegação irrestrita / restrita
- ACLs perigosas (GenericAll, WriteDACL, ForceChangePassword)
- MachineAccountQuota

### Containers
- Docker socket acessível
- Containers privilegiados em execução
- WSL2 distributions e versão
- Hyper-V configuração
- Namespace escapes (cgroups)

### Modern
- Defender exclusões de scan (dropar payloads aqui)
- Token privileges perigosos (SeImpersonate, SeDebug, SeBackup, etc.)
- WMI Event Subscriptions (backdoors/persistência)
- AppLocker rules em paths graváveis
- COM Objects com binários graváveis (300 amostras; pulado com `-Fast`)
- Named Pipes críticos (impersonation surface)
- UAC status e ConsentPromptBehaviorAdmin
- Grupos privilegiados no token atual

### CVE (2019–2026)

| CVE | Nome | Severidade | Condição extra |
|-----|------|-----------|----------------|
| CVE-2019-0708 | BlueKeep (RDP RCE pre-auth) | CRIT | Win7/Server2008 + RDP ativo |
| CVE-2020-0796 | SMBGhost (RCE pre-auth SMBv3) | CRIT | Builds 18362/18363 |
| CVE-2020-1472 | Zerologon | CRIT | Domain Controller |
| CVE-2021-34527 | PrintNightmare (LPE/RCE) | CRIT | Print Spooler ativo |
| CVE-2021-36934 | HiveNightmare/SeriousSAM | CRIT | Builds 17763-19043 |
| CVE-2021-40449 | Win32k EoP (APT MysterySnail) | HIGH | Builds < 22000 |
| CVE-2021-41379 | InstallerFileTakeOver | HIGH | Builds < 22000 |
| CVE-2021-42278/87 | noPac (Privesc → Domain Admin) | CRIT | Domínio + MachineAccountQuota > 0 |
| CVE-2022-21882 | Win32k EoP (bypass CVE-2021-1732) | HIGH | — |
| CVE-2022-26923 | Certifried (ADCS dNSHostName) | HIGH | Domínio |
| CVE-2022-30190 | Follina/MSDT RCE | CRIT | msdt.exe presente |
| CVE-2022-37969 | CLFS EoP | HIGH | — |
| CVE-2023-21554 | MSMQ QueueJumper RCE | CRIT | MSMQ rodando |
| CVE-2023-23397 | Outlook NTLM relay | HIGH | Outlook instalado |
| CVE-2023-28252 | CLFS EoP (Nokoyawa ransomware) | HIGH | — |
| CVE-2023-36802 | Streaming Service Proxy EoP | HIGH | — |
| CVE-2024-21338 | appid.sys WDAC bypass LPE | HIGH | — |
| CVE-2024-21413 | Outlook Moniker Link RCE | CRIT | Outlook instalado |
| CVE-2024-26169 | WER EoP | HIGH | — |
| CVE-2024-26229 | CSC Driver EoP | HIGH | — |
| CVE-2024-30088 | Kernel EoP via NTFS | HIGH | — |
| CVE-2024-38193 | AFD.sys EoP (APT Lazarus) | CRIT | — |
| CVE-2024-43572 | MMC MSC EvilTwin | HIGH | — |
| CVE-2024-49039 | Task Scheduler EoP (RomCom) | HIGH | — |
| CVE-2025-21333 | Hyper-V NT Kernel VSP EoP | CRIT | Hyper-V ativo |
| CVE-2025-21418 | AFD.sys EoP (jan/2025) | CRIT | — |
| CVE-2025-24054 | NTLM hash leak via .library-ms | HIGH | — |
| CVE-2025-26633 | MMC bypass 0-day (Water Gamayun) | HIGH | — |
| CVE-2025-29824 | CLFS EoP (RansomEXX Storm-2460) | CRIT | — |

> Todos os CVEs validam o OS build antes de alertar — sem falsos positivos em VMs sem OS real detectado.

---

## Formato de saída

### Resumo executivo (sempre exibido)
```
  CRITICAL:    3   ******************************
  HIGH:        7   **************
  MEDIUM:      4
  TOTAL:      14

  CVE                  3xCRIT 2xHIGH
    [CRIT] CVE-2024-38193 (AFD.sys EoP)...
  SISTEMA              2xHIGH 1xMED
    [HIGH] LSA RunAsPPL não configurado...
```

### JSON (com `-OutputFormat Json`)
```json
[
  {
    "Severity": "CRITICAL",
    "Section": "CVE — Vulnerabilidades Conhecidas",
    "Check": "2024 — appid.sys / WER / CSC / Kernel / AFD",
    "Message": "CVE-2024-38193 (AFD.sys EoP)...",
    "Timestamp": "2026-11-22T10:30:00.0000000+00:00"
  }
]
```

### Severidades

| Label | Cor | Significado |
|-------|-----|-------------|
| `[CRIT]` | Vermelho | Exploração imediata — privesc direto |
| `[HIGH]` | Amarelo | Risco elevado — requer configuração adicional |
| `[ MED]` | Magenta | Risco médio — aumenta superfície de ataque |
| `[  OK]` | Verde escuro | Sem problema detectado |
| `[INFO]` | Cinza | Informação relevante |

---

## Detecção de AV/EDR

| EDR | Processo detectado |
|-----|--------------------|
| Windows Defender | MsMpEng |
| CrowdStrike Falcon | CSFalconService, CSFalconContainer |
| SentinelOne | SentinelAgent, SentinelServiceHost |
| Carbon Black | cb.exe, RepMgr, RepUtils |
| Elastic EDR | elastic-agent |
| Cybereason | CybereasonAV, minionhost |
| Tanium | TaniumClient |
| Trend Micro | ds_agent, ntrtscan |
| Cylance | CylanceSvc |
| Palo Alto Cortex | traps, cytray |
| Sophos | SophosAV, SophosLive |
| McAfee/Trellix | mfeann, McShield |
| Symantec | Smc.exe, ccSvcHst |

---

## Detecção de software vulnerável

| Software | Versão máxima vulnerável | CVE |
|----------|--------------------------|-----|
| OpenSSH for Windows | ≤ 9.5 | CVE-2023-48795 (Terrapin) |
| PuTTY | ≤ 0.80 | CVE-2024-31497 (ECDSA key leak) |
| Notepad++ | ≤ 8.6.1 | CVE-2023-40031 |
| 7-Zip | ≤ 23.1 | CVE-2023-31102 |
| WinRAR | ≤ 6.22 | CVE-2023-38831 (RCE via archive) |
| Git for Windows | ≤ 2.42 | CVE-2023-29007 |

---

## Requisitos

- **PowerShell**: 5.1+ (PS7+ recomendado)
- **Privilégios**: usuário comum funciona; checks privilegiados são pulados automaticamente
- **Dependências**: nenhuma

---

## Lab de testes

```bash
# Build
docker build -t peagle-lab -f lab/Dockerfile .

# Executar 132 testes
docker run --rm peagle-lab

# Shell interativo para debug
docker compose -f lab/docker-compose.yml --profile shell run peagle-shell
```

| Arquivo | Testes | O que valida |
|---------|--------|-------------|
| `01_syntax.ps1` | 49 | Parser, funções, CVEs, ESCs, tokens |
| `02_output_format.ps1` | 13 | JSON, CSV, transcript Text |
| `03_summary_counters.ps1` | 14 | Contadores, resumo executivo, severidades |
| `04_edr_detection.ps1` | 7 | Detecção por processo (Defender, CrowdStrike, SentinelOne...) |
| `05_params_validation.ps1` | 19 | ValidateSet, módulos individuais, -OutputFile |
| `06_adcs_ad.ps1` | 30 | ADCS/AD, ESC9 bug fix, Timestamp, -Fast, ProfileList |
| **Total** | **144** | 6 arquivos, 0 falhas |

---

## Arquitetura

```
PEagle.ps1
├── param block          — Module, OutputFile, OutputFormat, Fast
├── Contadores globais   — $script:CountCrit/High/Med, $script:Findings
├── Helpers
│   ├── W-Banner         — ASCII art + info do host
│   ├── W-Sec/Sub/Flush  — estrutura de seções com contagem de findings
│   ├── W-Crit/High/Med  — findings com Timestamp ISO 8601
│   ├── W-Ok/Info/Data   — output informativo (W-Data trunca em 120 chars)
│   ├── W-Hint           — dicas de exploração (DarkRed)
│   ├── Find-WritablePath — ACL check via icacls + fallback Get-Acl
│   └── Get-UserProfiles  — enumera perfis via ProfileList registry
├── Módulos              — Invoke-{System,Network,Services,Creds,ADCS,AD,Containers,Modern,CVE}Checks
├── Main switch          — All = execução sequencial (contadores unificados)
└── Resumo executivo     — barras visuais, agrupamento por seção, próximos passos
```

---

## Changelog

### v2.1 (2026-11-23)
- **CVE expandido**: 18 → 30 CVEs detectados (2019–2026)
- Novo CVE-2019-0708 (BlueKeep) com detecção de RDP ativo
- CVE-2021-36934 (HiveNightmare), CVE-2021-40449 (Win32k APT MysterySnail)
- CVE-2022-21882 (Win32k bypass), CVE-2022-30190 (Follina/MSDT)
- CVE-2023-21554 (MSMQ QueueJumper) com check de serviço MSMQ
- CVE-2024-21413 (Outlook Moniker Link), CVE-2024-43572 (MMC EvilTwin), CVE-2024-49039 (Task Scheduler/RomCom)
- CVE-2025-21333 (Hyper-V VSP EoP) com check de serviço vmms, CVE-2025-26633 (MMC bypass Water Gamayun)
- Seções com rótulos atualizados e header "2019-2026"
- **143/143 testes passando**

### v2.0 (2026-11-22)
- **Rebranding**: WinPEAS-Complete → **PEagle**
- **12 correções** aplicadas após análise completa
- Parallelismo removido do modo `All` — contadores consolidados corretamente
- Bug ESC9 corrigido — `DirectorySearcher` movido para fora do loop de CAs
- Campo `Timestamp` (ISO 8601) em todos os findings e no export JSON/CSV
- Guard `$buildKnown` em todos os CVEs — elimina falsos positivos com build=0
- `InstallerFileTakeOver` restrito a builds < 22000 (Win10 only)
- Parâmetro `-Fast` — pula COM objects e enum completa de software
- `Get-UserProfiles` — enumera via `ProfileList` registry (não hardcode `C:\Users`)
- `Find-WritablePath` refatorado para usar `icacls` como método primário
- `W-Data` trunca strings > 120 chars com `...`
- Credential Guard verifica `VirtualizationBasedSecurityStatus` real (WMI)
- Named Pipes melhorado — mais padrões de impersonation
- Verificação de versões vulneráveis (OpenSSH, PuTTY, 7-Zip, WinRAR, Git, Notepad++)
- Novo arquivo de testes `06_adcs_ad.ps1` — 30 testes
- **132/132 testes passando**

### v1.x (WinPEAS-Complete)
- CVEs 2020–2026 com KB detection e HashSet O(1)
- ADCS ESC1–ESC17 via LDAP DirectorySearcher
- Tokens de Teams/Slack/Outlook/browsers
- Output estruturado: Text/Json/Csv com `-OutputFile`
- Resumo executivo com barras visuais e próximos passos
- Get-WmiObject → Get-CimInstance (compatibilidade PS7)
- 102 testes automatizados em Docker
