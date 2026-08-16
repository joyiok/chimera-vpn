@echo off
REM ============================================================
REM  CHIMERA Windows 客户端 - 开发模式脚本
REM  用法:
REM    dev.bat                    开发模式（热重载前端）
REM    dev.bat with_transport     开发模式 + 真实传输层
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

echo 安装前端依赖...
call npm install
if errorlevel 1 exit /b 1

if /i "%~1"=="with_transport" (
    if "%CORE_MERGED%"=="0" (
        echo [ERROR] 未找到 ../../core\core.go，无法启用真实传输层。
        echo         请先合并核心传输层，或使用默认 stub 开发模式：dev.bat
        exit /b 1
    )
    echo 整理 Go 依赖并以真实传输层启动开发模式...
    go mod tidy
    if errorlevel 1 exit /b 1
    call wails dev -tags with_transport -m
) else (
    if "%CORE_MERGED%"=="1" (
        echo 启动开发模式（标准）...
        call wails dev
    ) else (
        echo 启动开发模式（核心未合并，跳过 go mod tidy）...
        call wails dev -m
    )
)
endlocal
