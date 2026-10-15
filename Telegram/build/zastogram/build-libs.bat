@echo off
rem Third-party libraries, as the "Libraries" step of .github/workflows/win.yml:
rem   prepare\win.bat skip-debug silent qt6 [stage ...]
rem   set JOBS=4 & build-libs.bat libvpx     one stage with limited parallelism
rem JOBS (default 16) goes into NUMBER_OF_PROCESSORS, which the recipes pass to
rem make -j and jom -j. The VM is a workstation: keep JOBS around 8.
call "%~dp0env.bat"
if errorlevel 1 exit /b 1
powershell -NoProfile -ExecutionPolicy Bypass -File "%ZSG_VM_DIR%doctor.ps1" libs
if errorlevel 1 exit /b 1
if "%JOBS%"=="" set JOBS=16
set NUMBER_OF_PROCESSORS=%JOBS%
cd /d "%TBUILD%"
echo === start %DATE% %TIME%  JOBS=%JOBS%  stages=%* ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%ZSG_VM_DIR%clean-libs.ps1" stale
call "%ZSG_REPO%\Telegram\build\prepare\win.bat" skip-debug silent qt6 %*
set PREPARE_EXIT=%ERRORLEVEL%
if not "%PREPARE_EXIT%"=="0" goto done
rem After a successful prepare only: drop intermediates, keeping what
rem libs-keep.json says later stages and the client build still read.
powershell -NoProfile -ExecutionPolicy Bypass -File "%ZSG_VM_DIR%clean-libs.ps1" strip
if errorlevel 1 set PREPARE_EXIT=1
:done
echo === exit code: %PREPARE_EXIT% at %DATE% %TIME% ===
exit /b %PREPARE_EXIT%
