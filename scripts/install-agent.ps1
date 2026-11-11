<#
.SYNOPSIS
    Install or remove the ContextBridge agent as a Windows scheduled task that runs as you.

.DESCRIPTION
    The task runs `python -m contextbridge.remote.agent run` under your own account, never SYSTEM,
    so commands the agent runs have exactly your permissions (further limited by the agent's policy).

    By default the task runs with a standard (filtered) token, even when your account is an administrator.
    With -Elevated it runs with your full administrator token (run level Highest), so commands the agent runs
    can change system settings, services, drivers and protected files. Use it only on a machine you intend to
    administer remotely, together with the agent's own command policy. -Elevated needs an elevated PowerShell
    and an account in the Administrators group; reinstall without it to go back to a standard token.

    Default: starts at boot and runs whether or not you are signed in (S4U logon; no password is stored).
    Registering an S4U task needs an elevated PowerShell. With -AtLogOn it starts when you sign in instead,
    which needs no elevation.

    A second trigger repeats every minute from installation on, so an agent that exits is relaunched within a
    minute; a running one is left alone. The task has no run-time limit. Stopping the task ends the agent and,
    through its Windows job objects, every process the agent started; the next repeat starts it again, so
    disable the task (Disable-ScheduledTask) to keep it stopped.

    Enroll the device first:  .\scripts\run-agent.ps1 enroll -Code ABCD-EFGH-IJKL-MNOP

.EXAMPLE
    .\scripts\install-agent.ps1
.EXAMPLE
    .\scripts\install-agent.ps1 -Config C:\ContextBridge\configs\agent.yaml -AtLogOn
.EXAMPLE
    .\scripts\install-agent.ps1 -Elevated
.EXAMPLE
    .\scripts\install-agent.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Config = (Join-Path $PSScriptRoot '..\configs\agent.yaml'),
    [string]$Python = '',
    [string]$TaskName = 'ContextBridge Agent',
    [switch]$AtLogOn,
    [switch]$Elevated,
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

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$user = $identity.Name
$runLevel = if ($Elevated) { 'Highest' } else { 'Limited' }
if ($Elevated -and -not $DryRun) {
    # Registering a Highest task needs an elevated shell, and it only helps an account that has an
    # administrator token to give.
    $isElevated = ([System.Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isElevated) {
        throw "-Elevated needs an elevated PowerShell (Run as administrator) and an account in the Administrators group."
    }
}
$action = New-ScheduledTaskAction -Execute $executable -Argument $arguments -WorkingDirectory $root
if ($AtLogOn) {
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel $runLevel
} else {
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel $runLevel
}
# Restart-on-failure only covers a task that fails to start, not an agent that exits, so a second trigger fires
# every minute from now on, indefinitely; MultipleInstances IgnoreNew leaves a running agent alone. (Repeating the
# boot or logon trigger instead would only take effect after the next boot or sign-in.)
$relaunch = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew
$task = New-ScheduledTask -Action $action -Trigger $trigger, $relaunch -Principal $principal -Settings $settings `
    -Description 'ContextBridge agent: connects this machine to the ContextBridge gateway under its local policy.'

if ($DryRun) {
    [pscustomobject]@{
        TaskName         = $TaskName
        User             = $user
        LogonType        = $principal.LogonType
        RunLevel         = $principal.RunLevel
        Trigger          = if ($AtLogOn) { 'AtLogOn' } else { 'AtStartup' }
        Repeat           = $relaunch.Repetition.Interval
        Execute          = $executable
        Arguments        = $arguments
        WorkingDirectory = $root
    } | Format-List
    return
}

Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Output "Installed and started '$TaskName' as $user (run level $runLevel)."
Write-Output "Status:  Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
Write-Output "Logs:    $logFile and the agent audit log named in $configPath"
