#!/bin/bash

echo "🚀 Starting Discord Clone Platform"
echo "=================================="

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21 or later."
    exit 1
fi

# Check if Node.js is installed (for development)
if ! command -v node &> /dev/null; then
    echo "⚠️  Node.js is not installed. WebRTC features may not work optimally."
fi

# Create necessary directories
mkdir -p logs
mkdir -p data

# Download Go dependencies
echo "📦 Downloading Go dependencies..."
go mod tidy
if [ $? -ne 0 ]; then
    echo "❌ Failed to download Go dependencies"
    exit 1
fi

# Build the server
echo "🔨 Building server..."
go build -o bin/discord-server cmd/server/main.go
if [ $? -ne 0 ]; then
    echo "❌ Failed to build server"
    exit 1
fi

# Start the server
echo "🌐 Starting server on ports 8080 (HTTP) and 8081 (UDP)..."
echo "📝 Logs will be saved to logs/server.log"

# Create a simple HTML server for static files if needed
if [ ! -f "web/dist/index.html" ]; then
    echo "📁 Copying web files..."
    mkdir -p web/dist
    cp web/index.html web/dist/
    cp web/webrtc.js web/dist/
fi

# Start the server with logging
./bin/discord-server -http=8080 -udp=8081 -db=data/discord.db 2>&1 | tee logs/server.log &
SERVER_PID=$!

echo "✅ Server started with PID: $SERVER_PID"
echo ""
echo "🌍 Open your browser and navigate to: http://localhost:8080"
echo "📱 You can test P2P connections by opening multiple browser tabs"
echo ""
echo "🔧 Features available:"
echo "   • Real-time messaging"
echo "   • Server/Channel system"
echo "   • Voice calls (WebRTC)"
echo "   • Video calls (WebRTC)"
echo "   • Screen sharing"
echo "   • P2P connections via UDP hole punching"
echo ""
echo "⏹️  Press Ctrl+C to stop the server"

# Wait for interrupt
trap "echo '🛑 Stopping server...'; kill $SERVER_PID; exit 0" INT
wait $SERVER_PID

