@echo off
rem ZaStoGram build environment for the Windows VM (MSVC 14.44, x64).
rem Versioned with the sources: C:\TBuild\env.bat only forwards here, so a merge
rem that changes the build recipes changes this environment in the same commit.
rem Sets ZSG_VM_DIR (this folder), ZSG_REPO (repository root), TBUILD (its parent).
set "ZSG_VM_DIR=%~dp0"
for %%i in ("%~dp0..\..\..") do set "ZSG_REPO=%%~fi"
for %%i in ("%ZSG_REPO%\..") do set "TBUILD=%%~fi"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
rem VsDevCmd.bat, unlike vcvarsall.bat, does not set Platform; prepare.py needs it.
set Platform=x64
set "PATH=%USERPROFILE%\.cargo\bin;C:\Tools\bin;%PATH%"
exit /b 0
