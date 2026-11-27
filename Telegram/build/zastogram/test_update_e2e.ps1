# End-to-end check of the client auto-update on the build VM (interactive
# session, started through a scheduled task, see Telegram/build/zastogram/
# test_update_e2e.sh). Runs ONE client build in a fresh -workdir, lets its real
# updater poll the real release feed, and writes a verdict plus the update lines
# of the client log:
#
#   ACCEPTED   the update was downloaded, verified and kept (tupdates\ready-package)
#   REJECTED   the client logged "Update Error" and dropped the package
#   NOUPDATE   the feed offered nothing newer ("the latest version is installed")
#   TIMEOUT    no verdict in -Seconds
#
# Nothing here touches the normal ZaStoGram profile or the build output: the
# exe is copied away from out\Release and runs with its own -workdir.
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Label,
    [int]$Seconds = 150
)
$ErrorActionPreference = 'Stop'
$root = 'C:\TBuild\updtest'
$work = Join-Path $root "work\$Label"
$logs = Join-Path $root 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force $work | Out-Null

$proc = Start-Process -FilePath $Exe -ArgumentList @('-many', '-workdir', "$work\") -PassThru
$deadline = (Get-Date).AddSeconds($Seconds)
$verdict = 'TIMEOUT'
$logFile = Join-Path $work 'log.txt'
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if (Test-Path (Join-Path $work 'tupdates\ready-package')) { $verdict = 'ACCEPTED'; break }
    if (Test-Path $logFile) {
        $text = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
        if ($text -match 'Update Error: ') { $verdict = 'REJECTED'; break }
        if ($text -match 'the latest version is installed') { $verdict = 'NOUPDATE'; break }
    }
    if ($proc.HasExited) { $verdict = 'EXITED'; break }
}
Start-Sleep -Seconds 2
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }

$out = @("RESULT: $verdict", "EXE: $Exe", "LABEL: $Label")
if (Test-Path $logFile) {
    $out += Select-String -Path $logFile -Pattern 'Update (Info|Error)|v2|manifest|Packer|build id|ZsgBuild|dev-' |
        ForEach-Object { $_.Line }
} else {
    $out += 'no log.txt in the workdir'
}
if (Test-Path (Join-Path $work 'tupdates')) {
    $out += 'tupdates: ' + ((Get-ChildItem (Join-Path $work 'tupdates') -Recurse -File |
        ForEach-Object { "$($_.Name)($($_.Length))" }) -join ', ')
}
$out | Set-Content -Encoding UTF8 (Join-Path $logs "$Label.txt")
