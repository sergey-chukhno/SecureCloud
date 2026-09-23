# ==============================================================================
# SecureCloud Distributed Development Verification PowerShell Wrapper
# ==============================================================================
# Delegates execution directly to the Python distributed orchestrator on Windows.
# ==============================================================================
[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [string]$Preset,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ForwardArgs
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "verify-distributed-dev.py"

$PythonCmd = Get-Command py -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $PythonCmd) {
    $PythonCmd = Get-Command python -ErrorAction SilentlyContinue
}

if (-not $PythonCmd) {
    Write-Error "[SecureCloud] Error: python (or py) is required to execute the verification orchestrator."
    exit 1
}

$AllArgs = @()
if ($Preset) {
    $AllArgs += "--preset"
    $AllArgs += $Preset
}
if ($ForwardArgs) {
    $AllArgs += $ForwardArgs
}

& $PythonCmd.Source $PythonScript @AllArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
