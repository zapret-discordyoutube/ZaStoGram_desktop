#!/usr/bin/env bash
# Runs test_update_e2e.ps1 on the build VM in the interactive desktop session
# (a scheduled task bound to the logged-on user, the same way the other VM
# smoke tests start GUI clients) and prints the verdict file.
#
#   test_update_e2e.sh <label> <exe on the VM> [seconds]
#
# The exe must be a COPY outside C:\TBuild\ZaStoGram_desktop\out (a running
# client would lock the build output). Prints RESULT: ACCEPTED|REJECTED|...
set -euo pipefail
LABEL="${1:?label}"
EXE="${2:?exe path on the VM}"
SECONDS_LIMIT="${3:-150}"
WIN="${WIN:-win10}"
ROOT='C:\TBuild\updtest'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ssh "$WIN" "if not exist ${ROOT}\\logs mkdir ${ROOT}\\logs" >/dev/null
scp -q "$HERE/test_update_e2e.ps1" "$WIN:C:/TBuild/updtest/test_update_e2e.ps1"
ssh "$WIN" "del /q ${ROOT}\\logs\\${LABEL}.txt 2>nul & schtasks /create /f /tn zsgupd-${LABEL} /it /sc once /st 00:00 /ru privacy /tr \"powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ${ROOT}\\test_update_e2e.ps1 -Exe ${EXE} -Label ${LABEL} -Seconds ${SECONDS_LIMIT}\"" >/dev/null
ssh "$WIN" "schtasks /run /tn zsgupd-${LABEL}" >/dev/null
for _ in $(seq 1 $((SECONDS_LIMIT / 5 + 12))); do
  if ssh "$WIN" "if exist ${ROOT}\\logs\\${LABEL}.txt (exit 0) else (exit 1)"; then
    ssh "$WIN" "type ${ROOT}\\logs\\${LABEL}.txt"
    ssh "$WIN" "schtasks /delete /f /tn zsgupd-${LABEL}" >/dev/null 2>&1 || true
    exit 0
  fi
  sleep 5
done
echo "RESULT: NO-VERDICT-FILE (the task did not finish in time)" >&2
ssh "$WIN" "schtasks /delete /f /tn zsgupd-${LABEL}" >/dev/null 2>&1 || true
exit 1
