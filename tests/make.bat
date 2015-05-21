@echo off
gcc test.c ..\src\patchlib.c -o test.exe -s -m32
gcc target.c -o target.exe -s -m32
pause
