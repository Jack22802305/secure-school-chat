@echo off
echo 🚀 Starting Discord Clone Platform
echo ==================================

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Go is not installed. Please install Go 1.21 or later.
    pause
    exit /b 1
)

REM Create necessary directories
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "bin" mkdir bin

REM Download Go dependencies
echo 📦 Downloading Go dependencies...
go mod tidy
if %errorlevel% neq 0 (
    echo ❌ Failed to download Go dependencies
    pause
    exit /b 1
)

REM Build the server
echo 🔨 Building server...
go build -o bin/discord-server.exe cmd/server/main.go
if %errorlevel% neq 0 (
    echo ❌ Failed to build server
    pause
    exit /b 1
)

REM Prepare web files
echo 📁 Preparing web files...
if not exist "web/dist" mkdir web\dist
copy web\index.html web\dist\ >nul
copy web\webrtc.js web\dist\ >nul

REM Start the server
echo 🌐 Starting server on ports 8080 (HTTP) and 8081 (UDP)...
echo 📝 Server output will be displayed below
echo.

echo ✅ Server starting...
echo.
echo 🌍 Open your browser and navigate to: http://localhost:8080
echo 📱 You can test P2P connections by opening multiple browser tabs
echo.
echo 🔧 Features available:
echo    • Real-time messaging
echo    • Server/Channel system  
echo    • Voice calls (WebRTC)
echo    • Video calls (WebRTC)
echo    • Screen sharing
echo    • P2P connections via UDP hole punching
echo.
echo ⏹️  Press Ctrl+C to stop the server
echo.

REM Start the server
bin\discord-server.exe -http=8080 -udp=8081 -db=data/discord.db

