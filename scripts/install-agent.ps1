<#
.SYNOPSIS
    Install or remove the ContextBridge agent as a Windows scheduled task that runs as you.

.DESCRIPTION
    The task runs `python -m contextbridge.remote.agent run` under your own account, never SYSTEM,
    so commands the agent runs have exactly your permissions (further limited by the agent's policy).

    Default: starts at boot and runs whether or not you are signed in (S4U logon; no password is stored).
    Registering an S4U task needs an elevated PowerShell. With -AtLogOn it starts when you sign in instead,
    which needs no elevation.

    The task restarts the agent if it exits, and has no run-time limit. Stopping the task ends the agent and,
    through its Windows job objects, every process the agent started.

    Enroll the device first:  .\scripts\run-agent.ps1 enroll -Code ABCD-EFGH-IJKL-MNOP

.EXAMPLE
    .\scripts\install-agent.ps1
.EXAMPLE
    .\scripts\install-agent.ps1 -Config C:\ContextBridge\configs\agent.yaml -AtLogOn
.EXAMPLE
    .\scripts\install-agent.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Config = (Join-Path $PSScriptRoot '..\configs\agent.yaml'),
    [string]$Python = '',
    [string]$TaskName = 'ContextBridge Agent',
    [switch]$AtLogOn,
    [switch]$Uninstall,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Uninstall) {
    if ($DryRun) {
        Write-Output "Would remove scheduled task '$TaskName'."
        return
    }
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Output "Removed scheduled task '$TaskName'."
    return
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$configPath = (Resolve-Path $Config).Path

if (-not $Python) {
    $venvPython = Join-Path $root '.venv\Scripts\python.exe'
    if (Test-Path $venvPython) {
        $Python = $venvPython
    } else {
        $Python = (Get-Command python.exe -ErrorAction Stop).Source
    }
}
$pythonPath = (Resolve-Path $Python).Path

& $pythonPath -c 'import contextbridge.remote.agent'
if ($LASTEXITCODE -ne 0) {
    throw "ContextBridge is not installed for $pythonPath. Run: & '$pythonPath' -m pip install -e '$root'"
}

# pythonw.exe has no console, so no window appears when the task starts.
$pythonw = Join-Path (Split-Path $pythonPath) 'pythonw.exe'
$executable = if (Test-Path $pythonw) { $pythonw } else { $pythonPath }
$logFile = Join-Path $root 'audit\agent.log'
$arguments = "-m contextbridge.remote.agent run --config `"$configPath`" --log-file `"$logFile`""

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $executable -Argument $arguments -WorkingDirectory $root
if ($AtLogOn) {
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
} else {
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Limited
}
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'ContextBridge agent: connects this machine to the ContextBridge gateway under its local policy.'

if ($DryRun) {
    [pscustomobject]@{
        TaskName         = $TaskName
        User             = $user
        LogonType        = $principal.LogonType
        Trigger          = if ($AtLogOn) { 'AtLogOn' } else { 'AtStartup' }
        Execute          = $executable
        Arguments        = $arguments
        WorkingDirectory = $root
    } | Format-List
    return
}

Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Output "Installed and started '$TaskName' as $user."
Write-Output "Status:  Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
Write-Output "Logs:    $logFile and the agent audit log named in $configPath"
