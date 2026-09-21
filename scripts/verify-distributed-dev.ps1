# ==============================================================================
# SecureCloud Distributed Development Verification PowerShell Wrapper
# ==============================================================================
# Delegates execution directly to the Python distributed orchestrator on Windows.
# ==============================================================================
[CmdletBinding()]
param (
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ForwardArgs
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "verify-distributed-dev.py"

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $PythonCmd) {
    Write-Error "[SecureCloud] Error: python (or py) is required to execute the verification orchestrator."
    exit 1
}

& $PythonCmd.Source $PythonScript @ForwardArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
