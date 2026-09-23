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

# Automatically initialize MSVC environment if cl.exe is not in PATH or is 32-bit
if ($Preset -notlike "*mingw*" -and $Preset -notlike "*gcc*") {
    $clCmd = Get-Command cl -ErrorAction SilentlyContinue
    $is32BitCl = $false
    if ($clCmd) {
        if ($clCmd.Source -like "*\Hostx86\x86\*" -or $clCmd.Source -like "*\bin\x86\*") {
            $is32BitCl = $true
        }
    }
    if (-not $clCmd -or $is32BitCl) {
        $vswhereCandidates = @(
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
            "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe",
            "${env:ProgramW6432}\Microsoft Visual Studio\Installer\vswhere.exe"
        )
        foreach ($vswhere in $vswhereCandidates) {
            if (Test-Path $vswhere) {
                $vsPath = & $vswhere -latest -property installationPath
                if ($vsPath) {
                    $devShell = Join-Path $vsPath "Common7\Tools\Launch-VsDevShell.ps1"
                    if (Test-Path $devShell) {
                        Write-Host "[SecureCloud] Initializing Visual Studio x64 developer environment..."
                        & $devShell -Arch amd64 -HostArch amd64
                        break
                    }
                }
            }
        }
    }
}

# Proactively discover a single compatible MSYS2 binary directory and prepend to PATH
if ($Preset -notlike "*msvc*") {
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
