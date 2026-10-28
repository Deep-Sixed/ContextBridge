<#
.SYNOPSIS
    ContextBridge local health check for a Windows agent host (Thanatos).

.DESCRIPTION
    Read-only unless -RecoveryTest is passed. Prints PASS/WARN/FAIL/SKIP lines and writes a Markdown
    report to audit\healthcheck\. Never prints tokens, keys, or file contents.

    Checks: code revision, scheduled task state and logon type, agent process count, duplicate-launch
    evidence, agent audit events (including time from boot to first gateway connection), Tailscale
    state and unattended mode, gateway reachability, firewall exposure, and agent policy.

    To verify reboot recovery: reboot, sign in only if you use -AtLogOn, wait two minutes, run this
    script. The "boot to gateway_connected" line is the measurement.

.PARAMETER Config
    Agent config to check. Defaults to the --config the scheduled task (-TaskName) passes to the
    agent, so the check looks at the agent that actually runs here. Falls back to configs\agent.yaml.

.PARAMETER RecoveryTest
    DISRUPTIVE. Kills the agent started with the checked config (agents using other configs are left
    alone), then times how long the scheduled task takes to relaunch it and reconnect to the gateway.
    Asks for confirmation unless -Yes is given.

.EXAMPLE
    .\scripts\healthcheck\check-agent.ps1
.EXAMPLE
    .\scripts\healthcheck\check-agent.ps1 -Fetch -Hours 48
.EXAMPLE
    .\scripts\healthcheck\check-agent.ps1 -RecoveryTest -TimeoutSeconds 150
#>
[CmdletBinding()]
param(
    [string]$Config = '',
    [string]$Python = '',
    [string]$TaskName = 'ContextBridge Agent',
    [double]$Hours = 24,
    [switch]$Fetch,
    [switch]$RecoveryTest,
    [int]$TimeoutSeconds = 150,
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

# Pull a flag's value (quoted or bare) out of a command line; resolve a path against a base folder.
function Get-ArgValue([string]$CommandLine, [string]$Name) {
    if ($CommandLine -match ([regex]::Escape($Name) + '\s+(?:"([^"]*)"|(\S+))')) {
        if ($Matches[1]) { return $Matches[1] } else { return $Matches[2] }
    }
    return $null
}
function Resolve-ArgPath([string]$Path, [string]$Base) {
    if (-not $Path) { return $null }
    try {
        if (-not [IO.Path]::IsPathRooted($Path)) { $Path = Join-Path $Base $Path }
        return [IO.Path]::GetFullPath($Path)
    } catch { return $null }
}

# Default to the config and log file the scheduled task passes to the agent, so the check looks at
# the agent that actually runs here rather than the template config.
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$taskArgs = ''
$taskDir = $root
if ($task) {
    $taskAction = @($task.Actions) | Select-Object -First 1
    try {
        $taskArgs = "$($taskAction.Arguments)"
        if ($taskAction.WorkingDirectory) { $taskDir = $taskAction.WorkingDirectory }
    } catch { }
}
$taskConfig = Resolve-ArgPath (Get-ArgValue $taskArgs '--config') $taskDir
$configSource = 'from -Config'
if (-not $Config) {
    if ($taskConfig) { $Config = $taskConfig; $configSource = "from scheduled task '$TaskName'" }
    else { $Config = Join-Path $root 'configs\agent.yaml'; $configSource = 'default; no --config found in the scheduled task' }
}
$configPath = (Resolve-Path $Config).Path
$taskLog = Resolve-ArgPath (Get-ArgValue $taskArgs '--log-file') $taskDir
$agentLog = if ($taskLog -and $taskConfig -eq $configPath) { $taskLog } else { Join-Path $root 'audit\agent.log' }
if (-not $Python) {
    $venvPython = Join-Path $root '.venv\Scripts\python.exe'
    $Python = if (Test-Path $venvPython) { $venvPython } else { (Get-Command python.exe -ErrorAction Stop).Source }
}
$env:PYTHONPATH = (Join-Path $root 'src') + [IO.Path]::PathSeparator + $env:PYTHONPATH

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$reportDir = Join-Path $root 'audit\healthcheck'
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$report = Join-Path $reportDir "agent-$stamp.md"
$script:rows = New-Object System.Collections.Generic.List[string]
$script:fails = 0
$script:warns = 0

function Line([string]$Level, [string]$Check, [string]$Detail) {
    if ($Level -eq 'FAIL') { $script:fails++ }
    if ($Level -eq 'WARN') { $script:warns++ }
    $color = switch ($Level) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } }
    Write-Host ('{0,-5} {1,-34} {2}' -f $Level, $Check, $Detail) -ForegroundColor $color
    $script:rows.Add(('| {0} | {1} | {2} |' -f $Level, $Check, ($Detail -replace '\|', '\|')))
}

Write-Host "ContextBridge agent check on $env:COMPUTERNAME at $stamp"
Write-Host "config: $configPath ($configSource)"
Write-Host ''

# ------------------------------------------------------------ 1. code revision
Push-Location $root
try {
    # Explicit refspec so origin/main is updated even in a clone that tracks only some branches.
    if ($Fetch) { git fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main' 2>$null; if ($LASTEXITCODE -ne 0) { Line 'WARN' 'git fetch' 'could not reach origin' } }
    $head = (git rev-parse --short HEAD 2>$null)
    $branch = (git rev-parse --abbrev-ref HEAD 2>$null)
    $main = (git rev-parse --short origin/main 2>$null)
    if ($head -and $head -eq $main) {
        Line 'PASS' 'revision' "$branch @ $head (= origin/main)"
    } else {
        $behind = (git rev-list --count HEAD..origin/main 2>$null)
        $ahead = (git rev-list --count origin/main..HEAD 2>$null)
        Line 'WARN' 'revision' "$branch @ $head; origin/main $main ($behind behind, $ahead ahead)"
    }
    if (git status --porcelain --untracked-files=no 2>$null) { Line 'WARN' 'working tree' 'uncommitted changes to tracked files' }
    else { Line 'PASS' 'working tree' 'clean' }
} finally { Pop-Location }
$pkgVer = & $Python -c 'import contextbridge; print(contextbridge.__version__)' 2>$null
if ($LASTEXITCODE -eq 0 -and $pkgVer) { Line 'PASS' 'package' "contextbridge $pkgVer via $Python" }
else { Line 'FAIL' 'package' "contextbridge not importable with $Python" }

# ------------------------------------------------------------ 2. config + audit summary
function Get-Summary {
    $json = & $Python (Join-Path $root 'scripts\healthcheck\audit_summary.py') --kind agent --config $configPath --hours $Hours 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return (($json | Out-String) | ConvertFrom-Json)
}
$summary = Get-Summary
if (-not $summary) {
    Line 'FAIL' 'audit summary' 'could not read config or audit log'
} else {
    foreach ($f in $summary.findings) { Line $f.level $f.check $f.detail }
    if ($summary.identity_present) { Line 'PASS' 'device identity' "enrolled as $($summary.device_name)" }
    else { Line 'FAIL' 'device identity' 'identity file missing; enroll this device' }
}

# ------------------------------------------------------------ 3. scheduled task
if (-not $task) {
    Line 'FAIL' 'scheduled task' "'$TaskName' not installed"
} else {
    $info = $task | Get-ScheduledTaskInfo
    $logon = $task.Principal.LogonType
    $level = if ($task.State -eq 'Running') { 'PASS' } elseif ($task.State -eq 'Disabled') { 'FAIL' } else { 'WARN' }
    Line $level 'scheduled task' "state $($task.State); last run $($info.LastRunTime); last result 0x$('{0:X}' -f $info.LastTaskResult)"
    if ("$logon" -eq 'S4U') { Line 'PASS' 'task logon type' 'S4U: starts at boot without sign-in' }
    else { Line 'WARN' 'task logon type' "$logon`: starts only after sign-in; reboot recovery needs a sign-in" }
    if ($task.Principal.RunLevel -ne 'Limited') { Line 'WARN' 'task run level' "$($task.Principal.RunLevel) (expected Limited)" }
}

# ------------------------------------------------------------ 4. agent processes + duplicate launches
function Get-AgentProcesses {
    @(Get-CimInstance Win32_Process -Filter "Name like 'python%.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*contextbridge.remote.agent*run*' })
}
function Test-UsesConfig($Process) {
    (Resolve-ArgPath (Get-ArgValue $Process.CommandLine '--config') $root) -eq $configPath
}
function Get-ConfigAgentProcesses { @(Get-AgentProcesses | Where-Object { Test-UsesConfig $_ }) }
# On Windows a venv's python.exe / pythonw.exe is a launcher that starts the base interpreter as a
# child with the same command line, so one agent shows up as two processes. Count launchers only.
function Get-AgentInstances([object[]]$Processes) {
    $ids = @($Processes | ForEach-Object ProcessId)
    @($Processes | Where-Object { $ids -notcontains $_.ParentProcessId })
}
$procs = @(Get-AgentProcesses)
$mine = @(Get-AgentInstances @($procs | Where-Object { Test-UsesConfig $_ }))
$others = @(Get-AgentInstances @($procs | Where-Object { -not (Test-UsesConfig $_) }))
switch ($mine.Count) {
    0 { Line 'FAIL' 'agent process' 'no agent running with this config' }
    1 {
        $p = $mine[0]
        $up = (Get-Date) - $p.CreationDate
        Line 'PASS' 'agent process' ("pid {0}, up {1:d\.hh\:mm\:ss}" -f $p.ProcessId, $up)
    }
    default { Line 'WARN' 'agent process' "$($mine.Count) agents with this config: pids $(($mine | ForEach-Object ProcessId) -join ', ')" }
}
foreach ($p in $others) {
    Line 'WARN' 'other agent process' ("pid {0}, started {1:yyyy-MM-dd HH:mm}, config {2}" -f $p.ProcessId, $p.CreationDate, (Get-ArgValue $p.CommandLine '--config'))
}
if (Test-Path $agentLog) {
    $dupes = @(Select-String -Path $agentLog -SimpleMatch 'another ContextBridge agent is already running' -ErrorAction SilentlyContinue).Count
    $level = if ($dupes -gt 0) { 'WARN' } else { 'PASS' }
    Line $level 'duplicate launches (all time)' "$dupes refused by the instance lock in $agentLog"
} else {
    Line 'SKIP' 'duplicate launches' "$agentLog not found"
}
try {
    $since = (Get-Date).AddHours(-$Hours)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = $since } -ErrorAction Stop |
        Where-Object { $_.Message -like "*\$TaskName*" })
    $started = @($events | Where-Object Id -eq 100).Count
    $ignored = @($events | Where-Object Id -eq 322).Count
    $failed = @($events | Where-Object { $_.Id -in 101, 103, 203 }).Count
    $level = if ($failed -gt 0) { 'WARN' } else { 'INFO' }
    Line $level 'task scheduler log' "last ${Hours}h: $started started, $ignored skipped (already running), $failed launch failures"
} catch {
    Line 'SKIP' 'task scheduler log' 'Operational log disabled or unreadable (enable: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true)'
}

# ------------------------------------------------------------ 5. audit events + reboot recovery
if ($summary -and $summary.audit) {
    $c = $summary.audit.counts
    function N([string]$k) { if ($c.PSObject.Properties.Name -contains $k) { [int]$c.$k } else { 0 } }
    Line 'INFO' 'audit window' "last ${Hours}h; log last written $($summary.audit_last_write)"
    $level = if ((N 'gateway_unreachable') -gt 10) { 'WARN' } else { 'INFO' }
    Line $level 'gateway connection churn' ("connected={0} disconnected={1} unreachable={2} agent_started={3}" -f (N 'gateway_connected'), (N 'gateway_disconnected'), (N 'gateway_unreachable'), (N 'agent_started'))
    if ((N 'result_undelivered') -gt 0) { Line 'WARN' 'undelivered results' "$(N 'result_undelivered') call result(s) lost on disconnect" }
    $last = $summary.audit.last
    $lastConn = if ($last.PSObject.Properties.Name -contains 'gateway_connected') { $last.gateway_connected } else { 'none in window' }
    $lastDisc = if ($last.PSObject.Properties.Name -contains 'gateway_disconnected') { $last.gateway_disconnected } else { 'none in window' }
    Line 'INFO' 'last gateway connect' "$lastConn (last disconnect $lastDisc)"
    $sb = $summary.since_boot
    if ($sb) {
        $bootConn = $sb.first_gateway_connected_after_boot_s
        if ($null -eq $bootConn) { Line 'FAIL' 'boot to gateway_connected' "no gateway connection since boot at $($summary.boot_time)" }
        elseif ($bootConn -le 180) { Line 'PASS' 'boot to gateway_connected' "${bootConn}s after boot at $($summary.boot_time)" }
        else { Line 'WARN' 'boot to gateway_connected' "${bootConn}s after boot (slow) at $($summary.boot_time)" }
        if ($sb.agent_started -gt 1) { Line 'WARN' 'agent restarts since boot' "$($sb.agent_started) agent_started events since boot" }
    }
}

# ------------------------------------------------------------ 6. tailscale + reachability + firewall
$ts = Get-Command tailscale.exe -ErrorAction SilentlyContinue
if ($ts) {
    try {
        $st = (& $ts.Source status --json 2>$null | Out-String) | ConvertFrom-Json
        $level = if ($st.BackendState -eq 'Running') { 'PASS' } else { 'FAIL' }
        Line $level 'tailscale' "backend $($st.BackendState); self $($st.Self.HostName)"
    } catch { Line 'FAIL' 'tailscale' 'status unavailable' }
    try {
        $prefs = (& $ts.Source debug prefs 2>$null | Out-String) | ConvertFrom-Json
        if ($prefs.ForceDaemon) { Line 'PASS' 'tailscale unattended' 'on: tailnet stays up without sign-in' }
        else { Line 'WARN' 'tailscale unattended' 'off: after reboot the tailnet waits for sign-in (tailscale up --unattended)' }
    } catch { Line 'SKIP' 'tailscale unattended' 'could not read prefs' }
} else {
    Line 'SKIP' 'tailscale' 'tailscale.exe not on PATH'
}

if ($summary -and $summary.gateway_url -match '^wss?://([^:/]+):(\d+)') {
    $gwHost = $Matches[1]; $gwPort = [int]$Matches[2]
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ok = $client.ConnectAsync($gwHost, $gwPort).Wait(5000)
        if ($ok -and $client.Connected) { Line 'PASS' 'gateway reachable' "${gwHost}:$gwPort accepts TCP" }
        else { Line 'FAIL' 'gateway reachable' "${gwHost}:$gwPort did not answer in 5s" }
    } catch { Line 'FAIL' 'gateway reachable' "${gwHost}:$gwPort refused" } finally { $client.Close() }
}

try {
    $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object Name)
    if ($off.Count) { Line 'WARN' 'firewall profiles' "disabled: $($off -join ', ')" } else { Line 'PASS' 'firewall profiles' 'all enabled' }
    $pyRules = @(Get-NetFirewallApplicationFilter -ErrorAction Stop | Where-Object { $_.Program -like '*python*' } |
        Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' })
    if ($pyRules.Count) { Line 'WARN' 'inbound python rules' "$($pyRules.Count) inbound allow rule(s) for python; the agent needs none" }
    else { Line 'PASS' 'inbound python rules' 'none (agent dials out only)' }
} catch { Line 'SKIP' 'firewall' 'could not read firewall configuration' }

# ------------------------------------------------------------ 7. recovery test (opt-in, disruptive)
if ($RecoveryTest) {
    Write-Host ''
    if (-not $Yes) {
        $answer = Read-Host 'RECOVERY TEST kills the running agent and waits for the task to relaunch it. Continue? (y/N)'
        if ($answer -notmatch '^[yY]') { Line 'SKIP' 'kill recovery' 'not confirmed'; $RecoveryTest = $false }
    }
}
if ($RecoveryTest) {
    $before = @(Get-ConfigAgentProcesses)
    if (-not $before.Count) {
        Line 'SKIP' 'kill recovery' 'no agent running with this config to kill'
    } else {
        $t0 = (Get-Date).ToUniversalTime()
        $t0Iso = $t0.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $before | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        $oldIds = @($before | ForEach-Object ProcessId)
        $relaunchS = $null; $connectS = $null
        $auditPath = $summary.audit_log
        while (((Get-Date).ToUniversalTime() - $t0).TotalSeconds -lt $TimeoutSeconds) {
            Start-Sleep -Seconds 2
            $elapsed = [math]::Round(((Get-Date).ToUniversalTime() - $t0).TotalSeconds, 1)
            if ($null -eq $relaunchS -and @(Get-ConfigAgentProcesses | Where-Object { $oldIds -notcontains $_.ProcessId }).Count) { $relaunchS = $elapsed }
            if ($relaunchS -ne $null -and $auditPath -and (Test-Path $auditPath)) {
                $hit = Get-Content $auditPath -Tail 50 | Where-Object { $_ -match '"event":"gateway_connected"' } |
                    ForEach-Object { ($_ | ConvertFrom-Json) } | Where-Object { $_.ts -ge $t0Iso } | Select-Object -First 1
                if ($hit) { $connectS = $elapsed; break }
            }
        }
        if ($null -eq $relaunchS) { Line 'FAIL' 'kill recovery: relaunch' "task did not relaunch the agent within ${TimeoutSeconds}s" }
        else { Line 'PASS' 'kill recovery: relaunch' "new agent process after ${relaunchS}s" }
        if ($null -eq $connectS) { Line 'FAIL' 'kill recovery: reconnect' "no gateway_connected within ${TimeoutSeconds}s" }
        else { Line 'PASS' 'kill recovery: reconnect' "gateway_connected after ${connectS}s (kill at $t0Iso)" }
        $after = @(Get-AgentInstances @(Get-ConfigAgentProcesses))
        if ($after.Count -gt 1) { Line 'WARN' 'kill recovery: duplicates' "$($after.Count) agents with this config after relaunch" }
        Write-Host "Next: on the gateway, run  contextbridge-failover --config configs/computer.yaml --device $($summary.device_name)"
    }
}

# ------------------------------------------------------------ report
$md = @(
    "# ContextBridge agent check: $env:COMPUTERNAME, $stamp",
    '',
    "Config ``$configPath``. Result: **$script:fails fail, $script:warns warn**.",
    '',
    '| Level | Check | Detail |',
    '|---|---|---|'
) + $script:rows
if ($summary -and $summary.audit) {
    $md += @('', 'Recent agent events (UTC):', '', '```')
    $md += @($summary.audit.timeline | ForEach-Object { "$($_[0]) $($_[1])" })
    $md += '```'
}
$md | Set-Content -Path $report -Encoding UTF8

Write-Host ''
Write-Host "Result: $script:fails fail, $script:warns warn. Report: $report"
if ($script:fails -gt 0) { exit 1 } else { exit 0 }
