<#
.SYNOPSIS
    One-step install of the ContextBridge agent on a Windows machine: prerequisites, code, config, enrollment and
    the scheduled task.

.DESCRIPTION
    Run it in an elevated PowerShell on the new machine after creating a pairing code on the gateway host:

        cb-admin pair <name>          # on the gateway; prints a one-time code (15 minutes by default)

    The script then:
      1. installs Python 3.11+ and Git with winget if they are missing (skip with -SkipPrerequisites);
      2. clones ContextBridge into -InstallDir (or fetches, if it is already there) and checks out -Revision;
      3. creates .venv and installs ContextBridge into it;
      4. writes configs\agent.yaml from the -Policy preset, unless one already exists (replace it with -ForceConfig);
      5. enrolls the device with -Code, unless it is already enrolled;
      6. registers and starts the scheduled task with install-agent.ps1 (-AtLogOn and -Elevated pass through);
      7. waits for the agent to report that it connected to the gateway.

    Running it again on an enrolled machine upgrades it in place: the task is stopped, the code moves to -Revision,
    the package is reinstalled, and the task is registered and started again. The config and identity are kept.
    Use -ConfigPath for an existing agent.yaml outside the default configs folder (absolute or relative to
    -InstallDir). The installer reads its identity and audit paths from that config, preserving enrollment.
    With -ForceConfig it rewrites the config from -Policy, keeping the existing device name and gateway URL unless
    -GatewayUrl is passed; -Name must then match the enrolled name, or be left out.

    The device name defaults to this computer's name in lower case. It must match the name given to `pair`.

    Policy presets (edit configs\agent.yaml afterwards for anything in between):
      ReadOnly  read your user folder, write nothing, run a few diagnostic programs (default)
      Full      read and write C:\, run any PowerShell command, end processes, list windows and media apps

    Without the repository at hand, download and run it in one step:

        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Deep-Sixed/ContextBridge/main/scripts/bootstrap-agent.ps1))) -GatewayUrl wss://agents.example.com -Code ABCD-EFGH-IJKL-MNOP

.EXAMPLE
    .\scripts\bootstrap-agent.ps1 -GatewayUrl wss://agents.example.com -Code ABCD-EFGH-IJKL-MNOP
.EXAMPLE
    .\scripts\bootstrap-agent.ps1 -GatewayUrl wss://agents.example.com -Code ABCD-EFGH-IJKL-MNOP -Name p70 -Policy Full -AtLogOn
.EXAMPLE
    .\scripts\bootstrap-agent.ps1 -Revision 15db8a1      # upgrade an enrolled machine to that revision
.EXAMPLE
    .\scripts\bootstrap-agent.ps1 -Policy Full -ForceConfig   # switch an enrolled machine's policy, same name and gateway
.EXAMPLE
    .\scripts\bootstrap-agent.ps1 -ConfigPath C:\cb-step2\step2\agent-omnilink.yaml -Revision main
.EXAMPLE
    .\scripts\bootstrap-agent.ps1 -GatewayUrl wss://agents.example.com -DryRun
#>
[CmdletBinding()]
param(
    [string]$GatewayUrl = '',
    [string]$Code = '',
    [string]$Name = '',
    [ValidateSet('ReadOnly', 'Full')]
    [string]$Policy = 'ReadOnly',
    [string]$InstallDir = 'C:\ContextBridge',
    [string]$ConfigPath = '',
    [string]$Revision = 'main',
    [string]$RepoUrl = 'https://github.com/Deep-Sixed/ContextBridge',
    [string]$TaskName = 'ContextBridge Agent',
    [switch]$AtLogOn,
    [switch]$Elevated,
    [switch]$ForceConfig,
    [switch]$SkipPrerequisites,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-Native {
    # Runs a program and fails on a non-zero exit. Windows PowerShell turns a native program's stderr into errors
    # under ErrorActionPreference Stop (git and pip write progress there), so judge by the exit code alone.
    param([string]$What, [scriptblock]$Command)
    $ErrorActionPreference = 'Continue'
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit code $LASTEXITCODE)." }
}

function Update-PathFromRegistry {
    # winget changes the stored PATH; pick it up without opening a new shell.
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ';'
}

function Find-Python {
    # Returns the path of a Python 3.11+ interpreter, or $null. The Microsoft Store "python.exe" stub fails the
    # probe, so it is never picked.
    $ErrorActionPreference = 'Continue'
    $probe = 'import sys; print(sys.executable) if sys.version_info >= (3, 11) else sys.exit(1)'
    $candidates = @()
    if (Get-Command py.exe -ErrorAction SilentlyContinue) { $candidates += , @('py.exe', '-3') }
    if (Get-Command python.exe -ErrorAction SilentlyContinue) { $candidates += , @('python.exe') }
    foreach ($candidate in $candidates) {
        $exe = $candidate[0]
        $prefix = @($candidate | Select-Object -Skip 1)
        $out = & $exe @prefix -c $probe 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) {
            $path = ([string]@($out)[-1]).Trim()
            if (Test-Path -LiteralPath $path) { return $path }
        }
    }
    return $null
}

function Install-WithWinget([string]$Id, [string]$Label) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw "$Label is missing and winget is not available. Install $Label yourself, then run this script again."
    }
    Write-Step "Installing $Label with winget"
    Invoke-Native "winget install $Id" {
        winget.exe install --exact --id $Id --silent --accept-package-agreements --accept-source-agreements
    }
    Update-PathFromRegistry
}

function Read-ExistingConfig([string]$Path) {
    # The device name and gateway URL of an existing agent.yaml, read line by line (no YAML parser is at hand
    # before the package is installed). Missing values come back empty.
    $result = @{ Name = ''; GatewayUrl = ''; Identity = ''; AuditLog = '' }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }
    $inGateway = $false
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($line -match '^\s*(#|$)') { continue }
        if ($line -match '^name:\s*(\S+)') { $result.Name = $Matches[1].Trim('"', "'") }
        if ($line -match '^identity:\s*(\S+)') { $result.Identity = $Matches[1].Trim('"', "'") }
        if ($line -match '^audit_log:\s*(\S+)') { $result.AuditLog = $Matches[1].Trim('"', "'") }
        if ($line -match '^\S') { $inGateway = $line -match '^gateway:\s*(#.*)?$' ; continue }
        if ($inGateway -and $line -match '^\s+url:\s*(\S+)') { $result.GatewayUrl = $Matches[1].Trim('"', "'") }
    }
    return $result
}

function Resolve-AgentPath([string]$ConfigFile, [string]$Value) {
    if ([IO.Path]::IsPathRooted($Value)) { return [IO.Path]::GetFullPath($Value) }
    return [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $ConfigFile) $Value))
}

function ConvertTo-DeviceName([string]$Raw) {
    $n = ($Raw.ToLowerInvariant() -replace '[^a-z0-9-]', '-').Trim('-')
    if ($n.Length -gt 63) { $n = $n.Substring(0, 63).TrimEnd('-') }
    return $n
}

function New-AgentConfig([string]$DeviceName, [string]$Url, [string]$Preset, [string]$IdentityValue = '../state/agent-identity.json', [string]$AuditValue = '../audit/agent.audit.jsonl') {
    $header = @"
# ContextBridge agent config written by bootstrap-agent.ps1 ($Preset preset).
# This file is this machine's own policy: the gateway cannot widen it. See configs/agent.windows.yaml for every option.
name: $DeviceName

gateway:
  url: $Url

identity: $IdentityValue
audit_log: $AuditValue
max_concurrent_calls: 8

"@
    if ($Preset -eq 'Full') {
        $body = @"
filesystem:
  roots: ["C:/"]
  writable_roots: ["C:/"]
  delete: trash

commands:
  mode: unrestricted
  shell: powershell
  max_timeout_seconds: 600

processes:
  list: true
  allow_kill: true

desktop:
  observe: true

media:
  discover: true
"@
    } else {
        $body = @"
filesystem:
  roots: ["~"]
  writable_roots: []
  delete: trash

commands:
  mode: allowlist
  allow: [where, whoami, hostname, ipconfig, systeminfo, tasklist]
  max_timeout_seconds: 600

processes:
  list: true
  allow_kill: false

desktop:
  observe: false

media:
  discover: false
"@
    }
    return ($header + $body).Replace("`r`n", "`n") + "`n"
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'bootstrap-agent.ps1 installs the agent on Windows. On Linux and macOS, follow "Remote devices" in the README.'
}

$configPath = if ($ConfigPath) {
    if ([IO.Path]::IsPathRooted($ConfigPath)) { [IO.Path]::GetFullPath($ConfigPath) }
    else { [IO.Path]::GetFullPath((Join-Path $InstallDir $ConfigPath)) }
} else { Join-Path $InstallDir 'configs\agent.yaml' }
$defaultIdentity = Join-Path $InstallDir 'state\agent-identity.json'
$defaultAudit = Join-Path $InstallDir 'audit\agent.audit.jsonl'
$venvPython = Join-Path $InstallDir '.venv\Scripts\python.exe'
$configExists = Test-Path -LiteralPath $configPath
$writeConfig = $ForceConfig -or -not $configExists
$existing = Read-ExistingConfig $configPath
if ($configExists -and (-not $existing.Identity -or -not $existing.AuditLog)) {
    throw "Existing config '$configPath' must contain identity and audit_log paths; refusing to guess enrollment state."
}
$identityPath = if ($existing.Identity) { Resolve-AgentPath $configPath $existing.Identity } else { $defaultIdentity }
$auditPath = if ($existing.AuditLog) { Resolve-AgentPath $configPath $existing.AuditLog } else { $defaultAudit }
$enrolled = Test-Path -LiteralPath $identityPath
# For a new non-default config, keep state/audit in InstallDir rather than next to the config.
$identityValue = if ($ConfigPath -and -not $configExists) { '"' + $defaultIdentity.Replace('\', '/') + '"' } else { '../state/agent-identity.json' }
$auditValue = if ($ConfigPath -and -not $configExists) { '"' + $defaultAudit.Replace('\', '/') + '"' } else { '../audit/agent.audit.jsonl' }
if ($ForceConfig -and $configExists) {
    $identityValue = '"' + $identityPath.Replace('\', '/') + '"'
    $auditValue = '"' + $auditPath.Replace('\', '/') + '"'
}

# Only a new config needs a name and a gateway URL; an existing one already has both, and a rewrite keeps them.
if ($writeConfig) {
    if ($enrolled -and $existing.Name -and $Name -and $Name -ne $existing.Name) {
        throw "This machine is enrolled as '$($existing.Name)', so the config must keep that name; leave out -Name. To rename it, revoke '$($existing.Name)' on the gateway, delete $identityPath, and enroll again."
    }
    if (-not $Name) { $Name = $existing.Name }
    if (-not $Name) { $Name = ConvertTo-DeviceName $env:COMPUTERNAME }
    if ($Name -notmatch '^[a-z0-9][a-z0-9-]{0,62}$' -or @('local', 'all', 'gateway') -contains $Name) {
        throw "Device name '$Name' is not valid: use 1-63 lowercase letters, digits or '-', not local, all or gateway. Pass -Name."
    }
    if (-not $GatewayUrl) { $GatewayUrl = $existing.GatewayUrl }
    if (-not $GatewayUrl) {
        if ($DryRun) { $GatewayUrl = 'wss://agents.example.com' }
        else { $GatewayUrl = (Read-Host 'Gateway agent URL (the wss:// address `cb-admin pair` printed)').Trim() }
    }
    if ($GatewayUrl -notmatch '^wss://[^/\s]+') {
        throw "Pass -GatewayUrl as wss://host (the address `cb-admin pair` printed), not '$GatewayUrl'."
    }
} else {
    $Name = $existing.Name
}
if (-not $enrolled -and -not $Code -and -not $DryRun) {
    $Code = (Read-Host "One-time code from 'cb-admin pair $Name'").Trim()
}
if (-not $enrolled -and -not $Code -and -not $DryRun) {
    throw "A pairing code is needed to enroll. On the gateway host run: cb-admin pair $Name"
}

$installArgs = @{ Config = $configPath; Python = $venvPython; TaskName = $TaskName }
if ($AtLogOn) { $installArgs.AtLogOn = $true }
if ($Elevated) { $installArgs.Elevated = $true }

if ($DryRun) {
    [pscustomobject]@{
        InstallDir    = $InstallDir
        Revision      = $Revision
        RepoUrl       = $RepoUrl
        Config        = if ($writeConfig) { "write $configPath ($Policy preset)" } else { "keep $configPath" }
        Enroll        = if ($enrolled) { "already enrolled ($identityPath)" } else { "enroll as '$Name'" }
        TaskName      = $TaskName
        Trigger       = if ($AtLogOn) { 'AtLogOn' } else { 'AtStartup' }
        RunLevel      = if ($Elevated) { 'Highest' } else { 'Limited' }
        Prerequisites = if ($SkipPrerequisites) { 'skip' } else { 'install Python and Git with winget if missing' }
    } | Format-List | Out-String | Write-Output
    if ($writeConfig) {
        Write-Output '--- agent.yaml ---'
        Write-Output (New-AgentConfig $Name $GatewayUrl $Policy $identityValue $auditValue)
    }
    return
}

# A boot-time (S4U) or elevated task can only be registered from an elevated shell; check before changing anything.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ((-not $AtLogOn -or $Elevated) -and -not $isAdmin) {
    throw 'Run this from an elevated PowerShell (Run as administrator), or pass -AtLogOn to start the agent at sign-in instead.'
}

# 1. Prerequisites
Write-Step 'Checking for Python 3.11+ and Git'
$python = Find-Python
if (-not $python) {
    if ($SkipPrerequisites) { throw 'Python 3.11 or newer was not found.' }
    Install-WithWinget 'Python.Python.3.13' 'Python 3.13'
    $python = Find-Python
    if (-not $python) { throw 'Python was installed but cannot be found yet. Open a new PowerShell and run this script again.' }
}
if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
    if ($SkipPrerequisites) { throw 'Git was not found.' }
    Install-WithWinget 'Git.Git' 'Git'
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        throw 'Git was installed but cannot be found yet. Open a new PowerShell and run this script again.'
    }
}
Write-Host "    Python: $python"

# An upgrade replaces files the running agent holds open, so stop it first. Disabling the task keeps its every-minute
# trigger from relaunching it meanwhile; install-agent.ps1 registers it enabled again.
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Step "Stopping the existing '$TaskName' task for the upgrade"
    Disable-ScheduledTask -TaskName $TaskName | Out-Null
    Stop-ScheduledTask -TaskName $TaskName
}

$taskReregistered = $false
try {
    # 2. Code
    if (Test-Path -LiteralPath (Join-Path $InstallDir '.git')) {
        Write-Step "Fetching ContextBridge into $InstallDir"
        Invoke-Native 'git fetch' { git.exe -C $InstallDir fetch --quiet --tags origin }
    } elseif ((Test-Path -LiteralPath $InstallDir) -and (Get-ChildItem -LiteralPath $InstallDir -Force | Select-Object -First 1)) {
        throw "$InstallDir exists and is not a ContextBridge checkout. Pass another -InstallDir or empty it."
    } else {
        Write-Step "Cloning ContextBridge into $InstallDir"
        Invoke-Native 'git clone' { git.exe clone --quiet $RepoUrl $InstallDir }
    }
    $ErrorActionPreference = 'Continue'
    $target = git.exe -C $InstallDir rev-parse --verify --quiet "origin/$Revision^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { $target = git.exe -C $InstallDir rev-parse --verify --quiet "$Revision^{commit}" 2>$null }
    $ErrorActionPreference = 'Stop'
    if (-not $target) { throw "Revision '$Revision' was not found in $RepoUrl." }
    Invoke-Native 'git checkout' { git.exe -C $InstallDir -c advice.detachedHead=false checkout --quiet --detach $target }
    $short = (git.exe -C $InstallDir rev-parse --short HEAD)
    Write-Host "    Revision: $short"

    # 3. Package
    if (-not (Test-Path -LiteralPath $venvPython)) {
        Write-Step 'Creating the virtual environment'
        Invoke-Native 'venv' { & $python -m venv (Join-Path $InstallDir '.venv') }
    }
    Write-Step 'Installing ContextBridge (this takes a minute or two)'
    Invoke-Native 'pip install' { & $venvPython -m pip install --quiet --disable-pip-version-check -e $InstallDir }

    # 4. Config
    if ($writeConfig) {
        Write-Step "Writing $configPath ($Policy preset)"
        if ($configExists) { Copy-Item -LiteralPath $configPath -Destination "$configPath.bak" -Force }
        # UTF-8 without a byte order mark; Windows PowerShell's -Encoding utf8 would add one.
        $configDir = Split-Path -Parent $configPath
        if (-not (Test-Path -LiteralPath $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
        [IO.File]::WriteAllText($configPath, (New-AgentConfig $Name $GatewayUrl $Policy $identityValue $auditValue), (New-Object Text.UTF8Encoding $false))
    } else {
        Write-Step "Keeping the existing $configPath"
    }
    Invoke-Native 'config check' {
        # No double quotes in the code: Windows PowerShell drops them from native arguments.
        & $venvPython -c 'import sys; from contextbridge.remote.agent import load_agent_config as l; c = l(sys.argv[1]); print(''    Device:'', c.name, '' Gateway:'', c.gateway_url)' $configPath
    }

    # 5. Enrollment
    if ($enrolled) {
        Write-Step 'Already enrolled; keeping the device identity'
    } else {
        Write-Step 'Enrolling with the gateway'
        Invoke-Native 'enroll' { & $venvPython -m contextbridge.remote.agent enroll --config $configPath --code $Code }
    }

    # 6. Scheduled task
    Write-Step "Registering the '$TaskName' scheduled task"
    $started = Get-Date
    & (Join-Path $InstallDir 'scripts\install-agent.ps1') @installArgs
    $taskReregistered = $true
} catch {
    if ($existingTask -and -not $taskReregistered) {
        Enable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
        Write-Warning "Setup failed; re-enabled the existing '$TaskName' task so the previous agent keeps running."
    }
    throw
}

# 7. Connection check: the agent records gateway_connected in its audit log once the gateway accepts it.
Write-Step 'Waiting for the agent to connect'
$connected = $false
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline -and -not $connected) {
    Start-Sleep -Seconds 2
    if (Test-Path -LiteralPath $auditPath) {
        foreach ($line in (Get-Content -LiteralPath $auditPath -Tail 50 -ErrorAction SilentlyContinue)) {
            if ($line -notmatch '"event":"gateway_connected"') { continue }
            try { $ts = [DateTime]::Parse(($line | ConvertFrom-Json).ts).ToUniversalTime() } catch { continue }
            if ($ts -ge $started.ToUniversalTime().AddSeconds(-5)) { $connected = $true; break }
        }
    }
}
if ($connected) {
    Write-Host "ContextBridge agent installed at $short and connected to the gateway." -ForegroundColor Green
    Write-Host 'To use it from Claude or ChatGPT, revoke and reconnect the client and tick this device on the consent page.'
} else {
    # throw, not exit: run as a downloaded script block, exit would close the PowerShell window.
    throw ("The task is installed, but the agent has not reported a connection within 60 seconds. " +
        "Check $(Join-Path $InstallDir 'audit\agent.log') and $auditPath.")
}
