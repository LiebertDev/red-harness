# Build the exception-handling ground-truth fixtures.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests/fixtures/eh/build.ps1
#
# Locates the MSVC toolchain through vswhere (no hardcoded Visual Studio
# edition), builds the x64 and x86 console binaries from eh_cases.cpp, and
# writes linker map files next to them.  Release configuration: /O1, no PDB
# (/DEBUG:NONE), no incremental link.  /MD is intentional: the x64 SEH handler
# must be the imported __C_specific_handler, which is what the dataflow
# slicer's scope-table parser resolves.
#
# Outputs (all relative to this script):
#   build/eh_cases_x64.exe   build/eh_cases_x64.map
#   build/eh_cases_x86.exe   build/eh_cases_x86.map
#
# The binaries are committed; rebuilds use /Brepro so the images are stable.
# A rebuild after a toolchain update can change addresses/hashes: update
# ground-truth.json (compare addresses come from the map + dumpbin /disasm).

param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Build = Join-Path $Root 'build'
$Work = Join-Path $Build 'work'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "vswhere.exe not found at $vswhere; install the Visual Studio C++ build tools first."
}

$vsPath = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vsPath) {
    throw 'vswhere found no installation with the MSVC x86/x64 toolchain.'
}
$vsPath = ($vsPath | Select-Object -First 1).Trim()

$vcvars = @{
    x64 = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
    x86 = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars32.bat'
}
foreach ($k in $vcvars.Keys) {
    if (-not (Test-Path -LiteralPath $vcvars[$k])) {
        throw "Missing $($vcvars[$k])"
    }
}

if ($Clean -and (Test-Path -LiteralPath $Build)) {
    Remove-Item -LiteralPath $Build -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $Build, (Join-Path $Work 'x64'), (Join-Path $Work 'x86') | Out-Null

function Invoke-MsvcBuild {
    param([string]$Arch)

    $objDir = Join-Path $Work $Arch
    $exe = "build\eh_cases_$Arch.exe"
    $map = "build\eh_cases_$Arch.map"
    # One shell per architecture: vcvars sets the compiler/linker environment.
    $line = 'call "{0}" >nul 2>&1 && cd /d "{1}" && ' -f $vcvars[$Arch], $Root
    $line += 'cl /nologo /O1 /MD /EHsc /W4 /GS /Fo:"{0}\\" /Fe:"{1}" eh_cases.cpp ' -f $objDir, $exe
    $line += '/link /DEBUG:NONE /INCREMENTAL:NO /OPT:REF /DYNAMICBASE /NXCOMPAT /Brepro /MAP:"{0}"' -f $map

    Write-Host "== ${Arch}: cl /O1 /MD /EHsc /W4 /GS (no PDB) =="
    cmd /c $line
    if ($LASTEXITCODE -ne 0) {
        throw "MSVC $Arch build failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Root $exe))) {
        throw "Expected output missing: $exe"
    }
}

Invoke-MsvcBuild -Arch 'x64'
Invoke-MsvcBuild -Arch 'x86'

# Record the exact compiler banner for ground-truth.json.
foreach ($arch in @('x64', 'x86')) {
    $v = & cmd /c ('call "{0}" >nul 2>&1 && cl 2>&1' -f $vcvars[$arch]) |
        Select-String -Pattern 'Compiler Version|S.r.m'
    if ($v) { Write-Host "$arch compiler: $($v.Line.Trim())" }
}

Get-ChildItem -LiteralPath $Build -Filter 'eh_cases_*.exe' |
    ForEach-Object {
        '{0}  {1} bytes  sha256 {2}' -f $_.Name, $_.Length,
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
Write-Host 'Build complete. Addresses: build/*.map and dumpbin /disasm build/*.exe'
