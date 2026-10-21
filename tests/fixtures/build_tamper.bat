@echo off
rem Builds the rh-tamper test target (VS 2022 Build Tools, x64). Output: build\rh-tamper.exe
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /O2 /MT /W3 /Fo:build\ /Fe:build\rh-tamper.exe tamper.c /link /DEBUG:NONE advapi32.lib
