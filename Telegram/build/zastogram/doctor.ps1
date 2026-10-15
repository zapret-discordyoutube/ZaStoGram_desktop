# Invariants of the ZaStoGram Windows build VM, checked before every build.
#
#   doctor.ps1 libs     before build-libs.bat (prepare.py)
#   doctor.ps1 client   before build-telegram.bat
#
# Prints "ENVIRONMENT NOT READY: ..." and exits 1 when the machine, not the
# sources, is broken. upstream-sync treats that line as an environment failure
# and does not ask an AI to change code for it. Run it after env.bat.
param([Parameter(Mandatory = $true)][ValidateSet('libs', 'client')][string]$Mode)

$problems = @()
function Need($ok, $text) { if (-not $ok) { $script:problems += $text } }

# MSVC 14.44 from VS 2022 Build Tools: v145 of VS 2026 drops Windows 7.
Need ($env:VCToolsVersion -like '14.44.*') "MSVC toolset is '$($env:VCToolsVersion)', need 14.44.* (env.bat, -vcvars_ver=14.44)"
Need ($env:Platform -eq 'x64') "Platform is '$($env:Platform)', need x64 (env.bat)"

# Windows SDK pinned in docs/building-win.md, which CI reads too.
Need (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0') 'Windows SDK 10.0.26100.0 is missing'

# CMake 4 removed compatibility with cmake_minimum_required(VERSION < 3.5).
$cmake = (& cmake --version 2>$null | Select-Object -First 1)
Need ($cmake -match 'cmake version 3\.') "need CMake 3.x, found '$cmake'"

foreach ($tool in 'git', 'python', 'ninja', 'sccache') {
    Need ([bool](Get-Command $tool -ErrorAction SilentlyContinue)) "$tool is not in PATH"
}

# gyp (breakpad) looks for vcvarsall.bat; on this VM it is a shim to VsDevCmd.
$vcvarsall = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat'
if ($Mode -eq 'libs') {
    Need (Test-Path $vcvarsall) "vcvarsall.bat shim is missing: $vcvarsall"
    if (Test-Path $vcvarsall) {
        Need ((Get-Content $vcvarsall -Raw) -match 'vcvars_ver=14\.44') 'vcvarsall.bat shim does not pin -vcvars_ver=14.44'
    }
}

# Qt from scratch needs about 15 GB; the client build with LTO several more.
$needGB = if ($Mode -eq 'libs') { 15 } else { 8 }
$freeGB = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
Need ($freeGB -ge $needGB) "only $freeGB GB free on C:, need $needGB GB"

if ($Mode -eq 'client') {
    Need (Test-Path (Join-Path $env:TBUILD 'Libraries\win64\cache_keys')) 'libraries are not built: run build-libs.bat'
}

if ($problems) {
    $problems | ForEach-Object { "ENVIRONMENT NOT READY: $_" }
    exit 1
}
"environment ok ($Mode): MSVC $($env:VCToolsVersion), $cmake, $freeGB GB free"
exit 0
