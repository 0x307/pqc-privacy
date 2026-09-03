# build-wasm.ps1 — Canonical WASM build script for privacy
#
# Usage (from workspace root or privacy/):
#   powershell -ExecutionPolicy Bypass -File privacy/build-wasm.ps1
#
# Or from inside privacy/:
#   powershell -ExecutionPolicy Bypass -File build-wasm.ps1
#
# Produces privacy/dist/ containing:
#   privacy_bg.wasm        — compiled WebAssembly binary
#   privacy.js             — JS glue module (ESM)
#   privacy.d.ts           — TypeScript type definitions
#   privacy_bg.wasm.d.ts   — WASM TypeScript definitions
#   privacy.wit            — WIT interface file
#   package.json           — npm package manifest

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve script directory so this works from any cwd
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[build] Building privacy WASM artifacts..." -ForegroundColor Cyan
Write-Host "[build] Algorithms: ML-KEM-768, ML-DSA-65, AES-GCM-256, HKDF-SHA256" -ForegroundColor Gray

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

    # ── Step 2: Check wasm-pack ───────────────────────────────────────────────
    Write-Host "[build] Checking wasm-pack..." -ForegroundColor Cyan
    $wasmPackVersion = wasm-pack --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[build] wasm-pack not found. Installing via cargo..." -ForegroundColor Yellow
        cargo install wasm-pack
        if ($LASTEXITCODE -ne 0) {
            Write-Error "[build] Failed to install wasm-pack"
            exit $LASTEXITCODE
        }
        Write-Host "[build] wasm-pack installed." -ForegroundColor Green
    } else {
        Write-Host "[build] wasm-pack found: $wasmPackVersion" -ForegroundColor Green
    }

    # ── Step 3: wasm-pack build ───────────────────────────────────────────────
    Write-Host "[build] Running wasm-pack..." -ForegroundColor Cyan
    wasm-pack build --target web --out-dir dist --release -- --no-default-features --features wasm
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[build] wasm-pack failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-Host "[build] wasm-pack build succeeded." -ForegroundColor Green

    # ── Step 4: Copy WIT interface file ──────────────────────────────────────
    Write-Host "[build] Copying WIT interface file..." -ForegroundColor Cyan
    $WitSrc  = Join-Path $ScriptDir "wit\privacy.wit"
    $WitDest = Join-Path $ScriptDir "dist\privacy.wit"
    Copy-Item -Path $WitSrc -Destination $WitDest -Force

    # ── Step 5: Write dist/package.json ──────────────────────────────────────
    Write-Host "[build] Writing dist/package.json..." -ForegroundColor Cyan
    $PackageJson = @'
{
  "name": "privacy",
  "version": "0.1.0",
  "description": "PQCPrivacy: Quantum-Entangled Privacy Framework with Chaos-Modulated Zero-Knowledge Manifolds — standalone WASM",
  "type": "module",
  "main": "./privacy.js",
  "types": "./privacy.d.ts",
  "files": [
    "privacy_bg.wasm",
    "privacy.js",
    "privacy.d.ts",
    "privacy_bg.wasm.d.ts",
    "privacy.wit"
  ],
  "keywords": [
    "post-quantum",
    "privacy",
    "zero-knowledge",
    "chaos",
    "ml-kem",
    "ml-dsa",
    "wasm",
    "cryptography",
    "fips-203",
    "fips-204"
  ],
  "license": "MIT OR Apache-2.0",
  "repository": {
    "type": "git",
    "url": "https://github.com/0x307/__pqc-and-privacy__"
  },
  "exports": {
    ".": {
      "import": "./privacy.js",
      "types": "./privacy.d.ts"
    }
  }
}
'@
    $PackageJsonPath = Join-Path $ScriptDir "dist\package.json"
    Set-Content -Path $PackageJsonPath -Value $PackageJson -Encoding UTF8

    # ── Step 6: Create zip archive ────────────────────────────────────────────
    Write-Host "[build] Creating privacy-v0.1.0-wasm.zip..." -ForegroundColor Cyan
    $ZipPath = Join-Path $ScriptDir "privacy-v0.1.0-wasm.zip"
    $DistPath = Join-Path $ScriptDir "dist"
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    Compress-Archive -Path "$DistPath\*" -DestinationPath $ZipPath -Force
    Write-Host "[build] Archive created: privacy-v0.1.0-wasm.zip" -ForegroundColor Green

    # ── Step 7: Count exported functions ─────────────────────────────────────
    $JsFile = Join-Path $ScriptDir "dist\privacy.js"
    if (Test-Path $JsFile) {
        $ExportCount = (Select-String -Path $JsFile -Pattern "^export function" | Measure-Object).Count
        Write-Host "[build] Exported WASM functions: $ExportCount" -ForegroundColor Cyan
    }

    # ── Step 8: Report ────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[build] Done. dist/ contents:" -ForegroundColor Green
    Get-ChildItem (Join-Path $ScriptDir "dist") | Format-Table Name, Length -AutoSize

    Write-Host ""
    Write-Host "=== WASM Build Complete ===" -ForegroundColor Green
    Write-Host "Archive: privacy-v0.1.0-wasm.zip" -ForegroundColor Gray
    Write-Host "Target:  wasm32-unknown-unknown" -ForegroundColor Gray
    Write-Host "Features: wasm (wasm-bindgen, js-sys, getrandom/js)" -ForegroundColor Gray

} finally {
    Pop-Location
}
