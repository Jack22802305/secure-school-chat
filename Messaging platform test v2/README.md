# Discord Clone - P2P Messaging Platform

A Discord-like messaging and video call platform built with P2P networking using UDP hole punching for efficient real-time communication.

## Features

- 🔥 Real-time messaging with P2P connections
- 🎥 Voice and video calls using WebRTC
- 🏠 Server/Guild system with channels
- 💬 Direct messaging
- 🔐 End-to-end encryption
- 🌐 Modern web interface
- 📱 Responsive design

## Architecture

This platform uses a hybrid architecture:
- **Rendezvous Server**: Facilitates P2P connections and manages user presence
- **P2P Connections**: Direct client-to-client communication for messages and media
- **WebRTC**: For voice and video streaming
- **UDP Hole Punching**: To establish connections through NATs

## Quick Start

### 1. Start the Rendezvous Server
```bash
go run cmd/server/main.go
```

### 2. Build and Start the Web Client
```bash
npm install
npm run build
npm run dev
```

### 3. Open your browser
Navigate to `http://localhost:3000`

## Project Structure

```
├── cmd/
│   └── server/          # Rendezvous server
├── internal/
│   ├── server/          # Server-side logic
│   ├── client/          # Client-side P2P logic
│   └── shared/          # Shared utilities
├── web/                 # Vue.js web client
├── static/              # Static assets
└── docs/                # Documentation
```

## Based On

This project is inspired by and builds upon the UDP hole punching example from [wilfreddenton/udp-hole-punching](https://github.com/wilfreddenton/udp-hole-punching).

