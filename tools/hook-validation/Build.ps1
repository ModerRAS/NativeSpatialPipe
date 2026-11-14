# Build the cross-build hook validator with MinGW gcc (no third-party dependencies).
# Output: build/hook-validation/nsp-hook-validate.exe
#
# Run from the repo root (default PowerShell execution policy blocks unsigned scripts):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools/hook-validation/Build.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent (Split-Path -Parent $here)
$outDir = Join-Path $repo 'build/hook-validation'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$out = Join-Path $outDir 'nsp-hook-validate.exe'
$sources = @('pe.c', 'json.c', 'fp.c', 'main.c') | ForEach-Object { Join-Path $here $_ }
$gcc = Get-Command gcc -ErrorAction Stop
& $gcc.Source -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter -o $out @sources -municode -lbcrypt -lversion
if ($LASTEXITCODE -ne 0) { throw "gcc failed with exit code $LASTEXITCODE" }
Write-Host "built $out"