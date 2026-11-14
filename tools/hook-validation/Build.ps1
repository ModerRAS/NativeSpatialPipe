# Build the behavioral-shadow validator with the local MinGW gcc.
# Requires: gcc on PATH (tested with gcc 16.1.0 x86_64-posix-seh).
param(
    [string]$Gcc = "gcc",
    [string]$OutDir = ""
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot/../..").Path
if (-not $OutDir) { $OutDir = Join-Path $root "build/hook-validation" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "gcc: $(& $Gcc --version | Select-Object -First 1)"
$common = @("-O2", "-Wall", "-Wextra", "-std=c11")
$src = Join-Path $PSScriptRoot "shadow_gate.c"

& $Gcc @common $src -o (Join-Path $OutDir "nsp-shadow-gate.exe")
if ($LASTEXITCODE) { throw "exe build failed" }
& $Gcc @common "-DNSP_SHADOW_DLL" "-shared" $src -o (Join-Path $OutDir "nsp-shadow-gate.dll")
if ($LASTEXITCODE) { throw "dll build failed" }

Get-ChildItem $OutDir -Filter "nsp-shadow-gate.*" |
    Select-Object Length, Name |
    Format-Table -AutoSize |
    Out-String -Width 120 |
    Write-Host
Write-Host "built into $OutDir"
