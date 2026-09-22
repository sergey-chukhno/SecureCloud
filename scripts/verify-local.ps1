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

# Automatically initialize MSVC environment if cl.exe is not in PATH
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
    $vswhereCandidates = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    foreach ($vswhere in $vswhereCandidates) {
        if (Test-Path $vswhere) {
            $vsPath = & $vswhere -latest -property installationPath
            if ($vsPath) {
                $devShell = Join-Path $vsPath "Common7\Tools\Launch-VsDevShell.ps1"
                if (Test-Path $devShell) {
                    Write-Host "[SecureCloud] Initializing Visual Studio developer environment..."
                    & $devShell -Arch amd64 -HostArch amd64
                    break
                }
            }
        }
    }
}

# Proactively discover a single compatible MSYS2 binary directory and prepend to PATH
$FoundMsys = $false
foreach ($Base in @("C:\msys64", "D:\msys64")) {
    if (-not $FoundMsys -and (Test-Path $Base)) {
        foreach ($EnvName in @("mingw64", "ucrt64", "clang64")) {
            $Candidate = Join-Path $Base "$EnvName\bin"
            if (Test-Path $Candidate) {
                if ($env:PATH -notlike "*$Candidate*") {
                    $env:PATH = "$Candidate;$env:PATH"
                }
                $FoundMsys = $true
                break
            }
        }
        $UsrBin = Join-Path $Base "usr\bin"
        if ((Test-Path $UsrBin) -and ($env:PATH -notlike "*$UsrBin*")) {
            $env:PATH = "$UsrBin;$env:PATH"
        }
    }
}

& $PythonCmd.Source $PythonScript @ForwardArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
