# ContextBridge agent installer for Windows. Run it in PowerShell as Administrator:
#
#   irm -ErrorAction Stop '__CONTEXTBRIDGE_SERVER__/install/remote-windows.ps1' | iex
#
# To pass options (see scripts\bootstrap-agent.ps1: -Name, -Policy Full, -AtLogOn, -Elevated, ...):
#
#   & ([scriptblock]::Create((irm '__CONTEXTBRIDGE_SERVER__/install/remote-windows.ps1'))) -Policy Full
#
# Administrator approval is needed to install. The agent itself runs with a standard token unless you pass
# -Elevated: installing it and what it may do are separate choices.
#
# This downloads scripts\bootstrap-agent.ps1 from the ContextBridge repository and runs it with this gateway's
# addresses. The device is added by browser approval: it prints a code; open the gateway's /activate page, sign in,
# check the device, and approve. Running it again upgrades an installed agent in place.
$ErrorActionPreference = 'Stop'
$bootstrapUrl = 'https://raw.githubusercontent.com/Deep-Sixed/ContextBridge/main/scripts/bootstrap-agent.ps1'
$bootstrap = [scriptblock]::Create((Invoke-RestMethod -UseBasicParsing -ErrorAction Stop $bootstrapUrl))
$options = @{ Server = '__CONTEXTBRIDGE_SERVER__'; GatewayUrl = '__CONTEXTBRIDGE_AGENTS_URL__' }
# @args keeps option names such as -Policy, so they reach bootstrap-agent.ps1 as named parameters.
& $bootstrap @options @args
