# Housekeeping of C:\TBuild\Libraries\win64, called by build-libs.bat.
#
#   clean-libs.ps1 stale   before prepare: remove the Qt versions qt_version.py
#                          no longer selects (qt_<ver>, Qt-<ver> and their keys),
#                          and drop the cache key of every keep_whole stage whose
#                          directory is missing or looks stripped, so prepare
#                          rebuilds it instead of skipping it over missing files.
#   clean-libs.ps1 strip   after a successful prepare: remove intermediates with
#                          the filter of the "Free up some disk space" step of
#                          win.yml, except what libs-keep.json lists in keep_whole,
#                          then check that every kept directory is still there.
#
# Caches are never touched: C:\TBuild\sccache and the incremental out\ stay.
param([Parameter(Mandatory = $true)][ValidateSet('stale', 'strip')][string]$Mode)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$libs = Join-Path (Split-Path $repo -Parent) 'Libraries\win64'
$keys = Join-Path $libs 'cache_keys'
$qtVersionPy = Join-Path $repo 'Telegram\build\qt_version.py'
$keepFile = Join-Path $PSScriptRoot 'libs-keep.json'

function Free-GB { '{0:N1}' -f ((Get-PSDrive C).Free / 1GB) }

$keepExt = '.lib', '.a', '.exe', '.h', '.hpp', '.inc', '.cmake', '.pc'
$keep = Get-Content $keepFile -Raw -Encoding UTF8 | ConvertFrom-Json
$keepNames = @($keep.keep_whole.PSObject.Properties.Name)

"=== clean-libs ${Mode}: free $(Free-GB) GB ==="

if ($Mode -eq 'stale') {
    # The same branch build-libs.bat (argument qt6) uses to choose Qt.
    $text = Get-Content $qtVersionPy -Raw
    $m = [regex]::Match($text, "'qt6' in sys\.argv:[\s\S]*?os\.environ\['QT'\] = '([0-9.]+)'")
    if (-not $m.Success) { "Qt 6 version not found in $qtVersionPy, nothing removed"; exit 0 }
    $current = $m.Groups[1].Value
    "current Qt: $current"
    Get-ChildItem $libs -Directory | Where-Object {
        $_.Name -match '^(qt_|Qt-)(\d+\.\d+\.\d+)$' -and $Matches[2] -ne $current
    } | ForEach-Object {
        "removing stale $($_.Name)"
        Remove-Item $_.FullName -Recurse -Force
        $key = Join-Path $keys $_.Name
        if (Test-Path $key) { Remove-Item $key -Force }
    }
    # A kept directory that an older strip removed or cut down to headers and
    # libraries under a still valid key: invalidate the key of its stage.
    foreach ($name in $keepNames) {
        $stage = ($name -split '/')[0]
        $key = Join-Path $keys $stage
        if (-not (Test-Path $key)) { continue }
        $dir = Join-Path $libs ($name -replace '/', '\')
        $files = @(if (Test-Path $dir) { Get-ChildItem $dir -Recurse -Force -File -ErrorAction SilentlyContinue })
        $sources = @($files | Where-Object { -not ($keepExt -contains $_.Extension.ToLowerInvariant()) })
        if (-not $files -or -not $sources) {
            "rebuild $stage`: $name is missing or stripped under a valid cache key"
            Remove-Item $key -Force
        }
    }
} else {
    $keepWhole = @($keepNames | ForEach-Object {
        (Join-Path $libs ($_ -replace '/', '\')).TrimEnd('\') + '\'
    })
    # -like treats a backslash literally (its escape is the backtick).
    $keepPath = '\include\', '\objects-', '\cache_keys\'
    $removed = 0L
    Get-ChildItem $libs -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object {
        $p = $_.FullName
        -not ($keepExt -contains $_.Extension.ToLowerInvariant()) -and
        -not ($keepPath | Where-Object { $p -like "*$_*" }) -and
        -not ($keepWhole | Where-Object { $p.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })
    } | ForEach-Object {
        $removed += $_.Length
        Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
    }
    # Empty directories, deepest first.
    Get-ChildItem $libs -Recurse -Force -Directory -ErrorAction SilentlyContinue |
        Sort-Object { $_.FullName.Length } -Descending |
        Where-Object { -not (Get-ChildItem -LiteralPath $_.FullName -Force) } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
    'removed intermediates: {0:N1} GB' -f ($removed / 1GB)

    # A kept directory of a stage that was built must survive the strip.
    $missing = @()
    foreach ($name in $keepNames) {
        $stage = ($name -split '/')[0]
        if ((Test-Path (Join-Path $libs $stage)) -and -not (Test-Path (Join-Path $libs ($name -replace '/', '\')))) {
            $missing += $name
        }
    }
    if ($missing) {
        "ENVIRONMENT NOT READY: strip lost kept directories: $($missing -join ', ')"
        exit 1
    }
}

"=== clean-libs ${Mode}: free $(Free-GB) GB ==="
exit 0
