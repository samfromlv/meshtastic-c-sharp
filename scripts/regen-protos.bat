@echo off
setlocal enabledelayedexpansion
pushd "%~dp0.."

set "PROTOC_VER=3.30.1"

rem Firmware-only protos (on-flash storage, depend on nanopb.proto) - not generated for C#
set "EXCLUDE= deviceonly deviceonly_legacy "

rem Ask NuGet where the global packages folder is (respects NUGET_PACKAGES / nuget.config)
for /f "tokens=1,* delims= " %%a in ('dotnet nuget locals global-packages --list ^| findstr /b "global-packages:"') do set "NUGET_ROOT=%%b"
if not "%NUGET_ROOT:~-1%"=="\" set "NUGET_ROOT=%NUGET_ROOT%\"
set "PROTOC_TOOLS=%NUGET_ROOT%google.protobuf.tools\%PROTOC_VER%\tools"
set "PROTOC=%PROTOC_TOOLS%\windows_x64\protoc.exe"

if not exist "%PROTOC%" (
  echo protoc not found at "%PROTOC%"
  echo Run "dotnet restore" first, or check the Google.Protobuf.Tools version.
  popd
  exit /b 1
)

set "FILES="
for %%f in (protobufs\meshtastic\*.proto) do (
  if "!EXCLUDE: %%~nf =!"=="!EXCLUDE!" set "FILES=!FILES! %%f"
)

"%PROTOC%" -I=protobufs -I="%PROTOC_TOOLS%" --csharp_out=Meshtastic\Generated --csharp_opt=base_namespace=Meshtastic.Protobufs !FILES!
set "RC=!ERRORLEVEL!"

popd
exit /b %RC%
