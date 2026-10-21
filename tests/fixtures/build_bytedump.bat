@echo off
rem Builds the rh-bytedump byte-fidelity target (VS 2022 Build Tools, x64). Output: build\rh-bytedump.exe
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /O2 /MT /W3 /Fo:build\ /Fe:build\rh-bytedump.exe bytedump.c /link /DEBUG:NONE
