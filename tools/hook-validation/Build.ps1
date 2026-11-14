#!/usr/bin/env pwsh
# Build the standalone NSP hook-validation tool for the "pe-build-identity"
# method.  Only gcc (MinGW-w64) is required: version.dll, wintrust.dll and
# crypt32.dll are Windows in-box libraries.
#
#   pwsh -File tools/hook-validation/Build.ps1
#
# Output: <repo>/build/hook-validation/nsp-hook-validate.exe
# (build/ is git-ignored; the artifact is reproducible, not committed.)

[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
$repoRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path
$outDir = Join-Path $repoRoot 'build\hook-validation'
$outExe = Join-Path $outDir 'nsp-hook-validate.exe'
$source = Join-Path $scriptDir 'pe_identity.c'

if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    throw 'gcc not found on PATH (MinGW-w64 x86_64 is required)'
}
if (-not (Test-Path $source)) {
    throw "source not found: $source"
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# -municode provides wmain(); -lversion/-lwintrust/-lcrypt32 are the three
# Windows import libraries this tool needs (file version, Authenticode,
# certificate extraction).
gcc -O2 -Wall -Wextra -municode -DUNICODE -D_UNICODE -o $outExe $source -lversion -lwintrust -lcrypt32
if ($LASTEXITCODE -ne 0) {
    throw "gcc failed with exit code $LASTEXITCODE"
}

$item = Get-Item $outExe
Write-Host ('built {0} ({1} bytes)' -f $item.FullName, $item.Length)
