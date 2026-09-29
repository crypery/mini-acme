@echo off
echo Building mini-acme ...
gcc -O2 -o mini-acme.exe -I. -I./zlib -I./crypery -I./utilery ./zlib/*.c ./crypery/*.c ./utilery/*.c mini-acme.c -lws2_32
if %errorlevel% neq 0 (
    echo Build FAILED
    exit /b 1
)
echo Build OK
