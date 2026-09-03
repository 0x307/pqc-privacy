# build.ps1 — Native build script for privacy crate
#
# Usage (from workspace root or privacy/):
#   powershell -ExecutionPolicy Bypass -File privacy/build.ps1
#
# Or from inside privacy/:
#   powershell -ExecutionPolicy Bypass -File build.ps1
#
# Flags:
#   -Release   Build in release mode (default: debug)
#   -Test      Run cargo test after build
#   -Check     Run cargo check only (no compile)

param(
    [switch]$Release,
    [switch]$Test,
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve script directory so this works from any cwd
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Privacy Crate Build ===" -ForegroundColor Cyan
Write-Host "Version:    0.1.0" -ForegroundColor Gray
Write-Host "Algorithms: ML-KEM-768, ML-DSA-65, AES-GCM-256, HKDF-SHA256" -ForegroundColor Gray
Write-Host "Modules:    30 (PQCPrivacy)" -ForegroundColor Gray
Write-Host ""

Push-Location $ScriptDir
try {

    # ── Step 1: Check wasm32-unknown-unknown target ───────────────────────────
    Write-Host "[build] Checking wasm32-unknown-unknown target..." -ForegroundColor Cyan
    $installedTargets = rustup target list --installed 2>&1
    if ($installedTargets -notmatch "wasm32-unknown-unknown") {
        Write-Host "[build] Installing wasm32-unknown-unknown target..." -ForegroundColor Yellow
        rustup target add wasm32-unknown-unknown
        if ($LASTEXITCODE -ne 0) {
            Write-Error "[build] Failed to install wasm32-unknown-unknown target"
            exit $LASTEXITCODE
        }
        Write-Host "[build] wasm32-unknown-unknown installed." -ForegroundColor Green
    } else {
        Write-Host "[build] wasm32-unknown-unknown already installed." -ForegroundColor Green
    }

    # ── Step 2: cargo check or build ─────────────────────────────────────────
    if ($Check) {
        Write-Host "[build] Running cargo check..." -ForegroundColor Cyan
        cargo check
        if ($LASTEXITCODE -ne 0) {
            Write-Error "[build] cargo check failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
        Write-Host "[build] cargo check passed." -ForegroundColor Green

        Write-Host "[build] Running cargo check --features wasm..." -ForegroundColor Cyan
        cargo check --features wasm
        if ($LASTEXITCODE -ne 0) {
            Write-Error "[build] cargo check --features wasm failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
        Write-Host "[build] cargo check --features wasm passed." -ForegroundColor Green
    } else {
        $buildArgs = @("build")
        if ($Release) {
            $buildArgs += "--release"
            Write-Host "[build] Running cargo build --release..." -ForegroundColor Cyan
        } else {
            Write-Host "[build] Running cargo build (debug)..." -ForegroundColor Cyan
        }

        & cargo @buildArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Error "[build] cargo build failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
        Write-Host "[build] cargo build succeeded." -ForegroundColor Green
    }

    # ── Step 3: Run tests ─────────────────────────────────────────────────────
    if ($Test) {
        Write-Host "[build] Running cargo test..." -ForegroundColor Cyan
        cargo test
        if ($LASTEXITCODE -ne 0) {
            Write-Error "[build] cargo test failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
        Write-Host "[build] All tests passed." -ForegroundColor Green
    }

    # ── Step 4: Report ────────────────────────────────────────────────────────
    Write-Host "" 
    Write-Host "=== Build Complete ===" -ForegroundColor Green
    Write-Host "Crate:    privacy v0.1.0" -ForegroundColor Gray
    Write-Host "Target:   native ($(rustc --print target-triple 2>$null))" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To build WASM artifacts, run:" -ForegroundColor Yellow
    Write-Host "  powershell -ExecutionPolicy Bypass -File build-wasm.ps1" -ForegroundColor Yellow

} finally {
    Pop-Location
}
