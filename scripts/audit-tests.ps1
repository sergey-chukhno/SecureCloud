<#
.SYNOPSIS
Automated build and execution runner for the SecureCloud Audit test suite.
.DESCRIPTION
1. Compiles every audit test target individually using CMake.
2. Stops immediately if any target fails to build, outputting compiler errors.
3. Executes all test binaries one by one if the build phase succeeds.
4. Outputs a clear summary and detailed logs for any failed tests.
#>

param (
    [string]$Preset = "ci-windows-mingw",
    [string]$BuildDir = "build/ci-windows-mingw"
)

$ErrorActionPreference = "Stop"

$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH

# Exhaustive list of SecureCloud Audit test targets
$targets = @(
    # Unit tests
    "securecloud_audit_acknowledgement_manager_test",
    "securecloud_audit_config_test",
    "securecloud_audit_deduplication_pipeline_test",
    "securecloud_audit_event_mapper_test",
    "securecloud_audit_event_model_test",
    "securecloud_audit_event_validator_test",
    "securecloud_audit_ingestion_service_test",
    "securecloud_audit_page_cursor_test",
    "securecloud_audit_proto_mapper_test",
    "securecloud_audit_server_lifecycle_test",
    "securecloud_audit_service_impl_test",
    "securecloud_audit_batch_aggregator_test",
    "securecloud_audit_bounded_deduplication_cache_test",
    "securecloud_audit_bounded_ingestion_queue_test",
    "securecloud_audit_clickhouse_client_test",
    "securecloud_audit_clickhouse_event_serializer_test",
    "securecloud_audit_deduplication_metrics_test",
    "securecloud_audit_event_payload_fingerprint_test",
    "securecloud_audit_grpc_producer_identity_validator_test",
    "securecloud_audit_ingestion_pipeline_test",
    "securecloud_audit_insert_worker_pool_test",
    "securecloud_audit_producer_identity_validator_test",
    "securecloud_audit_sensitive_data_guard_test",
    "securecloud_audit_validation_worker_pool_test",

    # Integration tests
    "securecloud_audit_clickhouse_integration_test",
    "securecloud_audit_ingestion_concurrency_test",
    "securecloud_audit_ingestion_failure_injection_test",
    "securecloud_audit_ingestion_integration_test",
    "securecloud_audit_service_lifecycle_integration_test"
)

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "         SecureCloud Audit Test Runner & Reporter                 " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Preset   : $Preset" -ForegroundColor Gray
Write-Host "Targets  : $($targets.Count) test suites" -ForegroundColor Gray
Write-Host "------------------------------------------------------------------" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# STEP 1: BUILD PHASE
# -------------------------------------------------------------------------
Write-Host "`n[STEP 1/2] Building all test targets..." -ForegroundColor Yellow

$failedBuilds = @()

foreach ($target in $targets) {
    Write-Host "  [BUILDING] $target... " -NoNewline

    $buildOutput = & cmake --build --preset $Preset --target $target 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED" -ForegroundColor Red
        $failedBuilds += [PSCustomObject]@{
            Target = $target
            Output = ($buildOutput -join "`n")
        }
    } else {
        Write-Host "OK" -ForegroundColor Green
    }
}

if ($failedBuilds.Count -gt 0) {
    Write-Host "`n==================================================================" -ForegroundColor Red
    Write-Host " BUILD PHASE FAILED: $($failedBuilds.Count) target(s) failed to compile!" -ForegroundColor Red
    Write-Host "==================================================================" -ForegroundColor Red

    foreach ($failed in $failedBuilds) {
        Write-Host "`n------------------------------------------------------------------" -ForegroundColor Red
        Write-Host " Target Failure: $($failed.Target)" -ForegroundColor Red
        Write-Host "------------------------------------------------------------------" -ForegroundColor Red
        Write-Host $failed.Output
    }

    Write-Host "`nAborting test execution due to build failures." -ForegroundColor Red
    exit 1
}

Write-Host "`n[SUCCESS] All $($targets.Count) test targets compiled successfully!" -ForegroundColor Green

# -------------------------------------------------------------------------
# STEP 2: EXECUTION PHASE
# -------------------------------------------------------------------------
Write-Host "`n[STEP 2/2] Running test executables..." -ForegroundColor Yellow

$passed = @()
$failedRuns = @()

foreach ($target in $targets) {
    # Dynamically locate the test executable within the build directory
    $exePath = Get-ChildItem -Path "$BuildDir/tests" -Filter "$target.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

    if (-not $exePath -or -not (Test-Path $exePath)) {
        Write-Host "  [RUNNING] $target... " -NoNewline
        Write-Host "NOT FOUND" -ForegroundColor Red
        $failedRuns += [PSCustomObject]@{
            Target = $target
            Output = "Executable binary not found at $BuildDir/tests/**/$target.exe"
        }
        continue
    }

    Write-Host "  [RUNNING] $target... " -NoNewline

    $runOutput = cmd /c "`"$exePath`" 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED" -ForegroundColor Red
        $failedRuns += [PSCustomObject]@{
            Target = $target
            Output = ($runOutput -join "`n")
        }
    } else {
        Write-Host "PASSED" -ForegroundColor Green
        $passed += $target
    }
}

# -------------------------------------------------------------------------
# STEP 3: SUMMARY & REPORTING
# -------------------------------------------------------------------------
Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "                    FINAL TEST SUITE SUMMARY                      " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Total Executed : $($targets.Count)" -ForegroundColor White
Write-Host " Passed         : $($passed.Count)" -ForegroundColor Green
Write-Host " Failed         : $($failedRuns.Count)" -ForegroundColor $(if ($failedRuns.Count -eq 0) { "Green" } else { "Red" })

if ($failedRuns.Count -gt 0) {
    Write-Host "`n==================================================================" -ForegroundColor Red
    Write-Host " DETAILED TEST FAILURE REPORT                                     " -ForegroundColor Red
    Write-Host "==================================================================" -ForegroundColor Red

    foreach ($failed in $failedRuns) {
        Write-Host "`n------------------------------------------------------------------" -ForegroundColor Red
        Write-Host " FAILED TEST: $($failed.Target)" -ForegroundColor Red
        Write-Host "------------------------------------------------------------------" -ForegroundColor Red
        Write-Host $failed.Output
    }

    Write-Host "`nResult: OVERALL SUITE FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nResult: ALL TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
    exit 0
}
