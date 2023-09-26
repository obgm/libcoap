@echo off
pushd "%~dp0"

if exist Debug rd /s /q Debug
if exist Release rd /s /q Release
if exist x64 rd /s /q x64
if exist NoTLS rd /s /q NoTLS

cd ..

REM Need to set OPENSSL_INSTALL_PATH so we can build with OpenSSL
IF EXIST "C:\Program Files\OpenSSL\include\openssl\ssl.h" (
  SET "OPENSSL_INSTALL_PATH=C:\Program Files\OpenSSL\"
) ELSE (
  SET "OPENSSL_INSTALL_PATH=C:\Program Files\OpenSSL-Win64\")
)

echo OPENSSL_INSTALL_PATH = %OPENSSL_INSTALL_PATH%

rem MSBuild.exe ./win32/libcoap.sln /p:Configuration=NoTLS /p:Platform=x64 /warnaserror
MSBuild.exe ./win32/libcoap.sln /p:Platform=x64 /warnaserror

:exit
popd
@echo on
