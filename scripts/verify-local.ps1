# ==============================================================================
# SecureCloud Local Verification PowerShell Wrapper
# ==============================================================================
# Delegates execution directly to the Python orchestrator on Windows.
# ==============================================================================
[CmdletBinding()]
param (
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ForwardArgs
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "verify-local.py"

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
}

if (-not $PythonCmd) {
    Write-Error "[SecureCloud] Error: python is required to execute the verification orchestrator."
    exit 1
}

& $PythonCmd.Source $PythonScript @ForwardArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
