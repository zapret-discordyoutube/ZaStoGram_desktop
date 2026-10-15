@echo off
rem ZaStoGram Release x64, as the "Telegram Desktop build" step of win.yml.
rem   build-telegram.bat [lto]    lto -> DESKTOP_APP_ENABLE_LTO=ON, as CI does for tags
rem The last line is "=== exit code: N ..."; zsg-release.sh reads the result from it.
call "%~dp0env.bat"
if errorlevel 1 (echo === exit code: 1 at %DATE% %TIME% === & exit /b 1)
powershell -NoProfile -ExecutionPolicy Bypass -File "%ZSG_VM_DIR%doctor.ps1" client
if errorlevel 1 (echo === exit code: 1 at %DATE% %TIME% === & exit /b 1)
set LTO=OFF
if /I "%~1"=="lto" set LTO=ON
echo === start %DATE% %TIME%  LTO=%LTO% ===

cd /d "%ZSG_REPO%\Telegram"
call configure.bat -G "Ninja Multi-Config" qt6 -D TDESKTOP_API_TEST=ON ^
 -D CMAKE_CONFIGURATION_TYPES=Release ^
 -D DESKTOP_APP_ENABLE_LTO=%LTO% ^
 -D CMAKE_C_COMPILER_LAUNCHER=sccache ^
 -D CMAKE_CXX_COMPILER_LAUNCHER=sccache ^
 -D CMAKE_COMPILE_WARNING_AS_ERROR=ON ^
 -D CMAKE_MSVC_DEBUG_INFORMATION_FORMAT= ^
 -D DESKTOP_APP_DISABLE_AUTOUPDATE=OFF ^
 -D ZASTOGRAM_PACKER=ON ^
 -D DESKTOP_APP_DISABLE_QT_PLUGINS=ON ^
 -D DESKTOP_APP_DISABLE_CRASH_REPORTS=OFF
if errorlevel 1 (echo === CONFIGURE FAILED === & echo === exit code: 1 at %DATE% %TIME% === & exit /b 1)

rem 28 parallel links do not fit into the VM's 20 GB of RAM.
rem -k 0: keep compiling after a failed object, so one run reports every error
rem (upstream-sync hands the whole list to its build fixer at once).
cmake --build ..\out --config Release --target Telegram Packer --parallel 4 -- -k 0
set BUILD_EXIT=%ERRORLEVEL%
echo === exit code: %BUILD_EXIT% at %DATE% %TIME% ===
exit /b %BUILD_EXIT%
