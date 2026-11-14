<#
.SYNOPSIS
  Build the standalone hook-validation tool with gcc (MinGW-w64).
.DESCRIPTION
  Produces build/hook-validation/nsp-hook-validate.exe. The tool has no
  third-party dependencies: it parses PE32+ images with the bundled pe.c parser.
#>
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$outDir = Join-Path $repoRoot 'build\hook-validation'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$exe = Join-Path $outDir 'nsp-hook-validate.exe'
$sources = Get-ChildItem -Path $PSScriptRoot -Filter *.c | Sort-Object Name | ForEach-Object { $_.FullName }
Write-Host ("gcc sources: " + (($sources | ForEach-Object { Split-Path -Leaf $_ }) -join ' '))
& gcc -O2 -std=c11 -Wall -Wextra -static -o $exe @sources
if ($LASTEXITCODE -ne 0) { throw "gcc failed with exit code $LASTEXITCODE" }
Write-Host "built $exe"
