@echo off
gcc test.c ..\src\patchlib.c -o test.exe -s -m64 -lpsapi
gcc target.c -o target.exe -s -m64
pause
