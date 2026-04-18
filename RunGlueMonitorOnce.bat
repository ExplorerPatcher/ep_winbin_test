@echo off
setlocal

set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"

set "RUN_DIR=%REPO_ROOT%\Run"
set "GLUE_EXE=%REPO_ROOT%\bin\Release\x64\ep_winbin_test_glue.exe"
set "WORKER_EXE=%REPO_ROOT%\bin\Release\x64\ep_winbin_test_worker.exe"

if not exist "%RUN_DIR%" (
    echo Run directory not found: "%RUN_DIR%"
    exit /b 1
)

if not exist "%GLUE_EXE%" (
    echo Glue executable not found: "%GLUE_EXE%"
    exit /b 1
)

if not exist "%WORKER_EXE%" (
    echo Worker executable not found: "%WORKER_EXE%"
    exit /b 1
)

pushd "%RUN_DIR%" || exit /b 1
"%GLUE_EXE%" monitor-once
set "EXITCODE=%ERRORLEVEL%"
popd

exit /b %EXITCODE%
