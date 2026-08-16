@echo off
REM ============================================================
REM  CHIMERA Windows 客户端 - 生产构建脚本
REM  用法:
REM    build.bat                 构建 stub 界面（核心未合并时自动跳过 go mod tidy）
REM    build.bat with_transport  构建真实传输层（需要 ../../core 已合并）
REM ============================================================
setlocal
cd /d "%~dp0\.."

where wails >nul 2>nul
if errorlevel 1 (
    echo [ERROR] 未找到 wails CLI。
    echo         请先安装：go install github.com/wailsapp/wails/v2/cmd/wails@v2.10.2
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] 未找到 npm。请先安装 Node.js 20 或更高版本。
    exit /b 1
)

set "CORE_MERGED=0"
if exist "..\..\core\core.go" set "CORE_MERGED=1"

echo [1/2] 安装前端依赖...
call npm install
if errorlevel 1 exit /b 1

if /i "%~1"=="with_transport" (
    if "%CORE_MERGED%"=="0" (
        echo [ERROR] 未找到 ../../core\core.go，无法构建真实传输层。
        echo         请先合并核心传输层，或使用默认 stub 构建：build.bat
        exit /b 1
    )
    echo [2/2] 整理 Go 依赖并构建真实传输层...
    go mod tidy
    if errorlevel 1 exit /b 1
    call wails build -tags with_transport -m
) else (
    if "%CORE_MERGED%"=="1" (
        echo [2/2] 构建 stub 版本（核心已合并，执行标准构建）...
        call wails build
    ) else (
        echo [2/2] 构建 stub 版本（核心未合并，跳过 go mod tidy）...
        call wails build -m
    )
)
if errorlevel 1 exit /b 1

echo 构建完成：build\bin\ChimeraClient.exe
endlocal
