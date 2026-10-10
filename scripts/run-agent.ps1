<#
.SYNOPSIS
    Run the ContextBridge agent in the foreground, or enroll this machine with the gateway.

.EXAMPLE
    .\scripts\run-agent.ps1 enroll -Code ABCD-EFGH-IJKL-MNOP
.EXAMPLE
    .\scripts\run-agent.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('run', 'enroll')]
    [string]$Command = 'run',
    [string]$Code = '',
    [string]$Config = (Join-Path $PSScriptRoot '..\configs\agent.yaml'),
    [string]$Python = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $Python) {
    $venvPython = Join-Path $root '.venv\Scripts\python.exe'
    $Python = if (Test-Path $venvPython) { $venvPython } else { (Get-Command python.exe -ErrorAction Stop).Source }
}
$env:PYTHONPATH = (Join-Path $root 'src') + [IO.Path]::PathSeparator + $env:PYTHONPATH

if ($Command -eq 'enroll') {
    if (-not $Code) { throw 'Pass the one-time code from `contextbridge-admin pair`: -Code ABCD-EFGH-IJKL-MNOP' }
    & $Python -m contextbridge.remote.agent enroll --config $Config --code $Code
} else {
    & $Python -m contextbridge.remote.agent run --config $Config
}
exit $LASTEXITCODE
