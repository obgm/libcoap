@echo off
pushd "%~dp0"

if exist Debug rd /s /q Debug
if exist Release rd /s /q Release
if exist x64 rd /s /q x64
if exist NoTLS rd /s /q NoTLS

cd ..

"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" ./win32/libcoap.sln /p:Configuration=NoTLS /p:Platform=x64 /warnaserror

:exit
popd
@echo on
