# Build the branch-1 hook validation tool with gcc (MinGW-w64).
# Output: <repo>/build/hook-validation/nsp-hook-validate.exe (ignored by .gitignore).
[CmdletBinding()]
param(
    [string]$Gcc = "gcc",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)
if (-not $OutDir) { $OutDir = Join-Path $repoRoot "build/hook-validation" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$sources = @(Get-ChildItem -Path (Join-Path $scriptDir "src") -Filter "*.c" | Sort-Object Name | ForEach-Object { $_.FullName })
if ($sources.Count -eq 0) { throw "no C sources found under $scriptDir/src" }

$exe = Join-Path $OutDir "nsp-hook-validate.exe"
Write-Host "gcc $($sources.Count) source(s) -> $exe"
& $Gcc -O2 -std=c11 -Wall -Wextra -Wno-unused-parameter -o $exe @sources -lbcrypt -lversion -lshell32
if ($LASTEXITCODE -ne 0) { throw "gcc failed with exit code $LASTEXITCODE" }
Write-Host "built $exe"
