# Discord Clone - Development Guide

## Quick Start

### Prerequisites
- Go 1.21 or later
- Modern web browser with WebRTC support
- (Optional) Node.js for advanced development

### Running the Application

#### Windows
```bash
start.bat
```

#### Linux/macOS
```bash
chmod +x start.sh
./start.sh
```

#### Manual Start
```bash
# Build and run the server
go build -o bin/discord-server cmd/server/main.go
./bin/discord-server -http=8080 -udp=8081 -db=data/discord.db

# Open browser to http://localhost:8080
```

## Architecture Overview

### Components

1. **Rendezvous Server** (`internal/server/`)
   - HTTP API for user management and messaging
   - WebSocket for real-time communication
   - UDP server for P2P connection facilitation
   - SQLite database for persistence

2. **P2P Client** (`internal/client/`)
   - UDP hole punching implementation
   - Encrypted peer-to-peer messaging
   - Connection management

3. **WebRTC Manager** (`internal/webrtc/`)
   - Voice and video call management
   - Screen sharing support
   - ICE candidate handling

4. **Web Client** (`web/`)
   - Vue.js-based Discord-like interface
   - WebRTC integration
   - Real-time messaging UI

### P2P Connection Flow

1. **Registration**: Clients register with rendezvous server
2. **Discovery**: Server maintains peer registry
3. **Hole Punching**: Server facilitates NAT traversal
4. **Direct Communication**: Peers communicate directly
5. **Encryption**: All P2P messages are encrypted

### WebRTC Integration

1. **Signaling**: Uses WebSocket for SDP exchange
2. **STUN**: Google STUN servers for NAT traversal
3. **Media**: Audio/video streaming between peers
4. **Data Channels**: Text chat during calls

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### Servers & Channels
- `GET /api/servers` - List user's servers
- `POST /api/servers` - Create new server
- `GET /api/servers/{id}/channels` - List channels
- `POST /api/servers/{id}/channels` - Create channel

### Messaging
- `GET /api/channels/{id}/messages` - Get messages
- `POST /api/channels/{id}/messages` - Send message

### WebSocket Events
- `join_channel` - Join text channel
- `leave_channel` - Leave text channel
- `join_voice_channel` - Join voice channel
- `leave_voice_channel` - Leave voice channel
- `webrtc_offer` - WebRTC offer
- `webrtc_answer` - WebRTC answer
- `webrtc_ice_candidate` - ICE candidate

## Testing P2P Connections

### Local Testing
1. Open multiple browser tabs to `http://localhost:8080`
2. Register different users in each tab
3. Create a server and channels
4. Test messaging and voice calls

### Network Testing
1. Deploy server to VPS or cloud instance
2. Update `serverTCPIP` and `serverUDPIP` in client code
3. Test from different networks
4. Verify NAT traversal works

## Configuration

### Server Configuration
```bash
./discord-server -http=8080 -udp=8081 -db=discord.db
```

### Environment Variables
- `HTTP_PORT` - HTTP server port (default: 8080)
- `UDP_PORT` - UDP server port (default: 8081)
- `DB_PATH` - Database file path (default: discord.db)

## Development Tips

### Adding New Features
1. Update shared types in `internal/shared/types.go`
2. Add server handlers in `internal/server/handlers.go`
3. Update client logic in `internal/client/`
4. Modify web UI in `web/index.html`

### Debugging
- Server logs show P2P connection attempts
- Browser console shows WebRTC connection states
- Network tab shows WebSocket messages

### Security Considerations
- All P2P messages use AES-GCM encryption
- WebRTC uses DTLS for media encryption
- Authentication is simplified for demo purposes

## Known Limitations

1. **Authentication**: Simplified JWT-like tokens
2. **Persistence**: Basic SQLite database
3. **Scalability**: Single server instance
4. **Mobile**: Not optimized for mobile browsers
5. **TURN**: No TURN server for restrictive NATs

## Future Enhancements

- [ ] Mobile app support
- [ ] File sharing
- [ ] Message history synchronization
- [ ] Advanced user permissions
- [ ] TURN server integration
- [ ] Message encryption at rest
- [ ] Push notifications
- [ ] Bot API

## Troubleshooting

### Common Issues

**WebRTC not working**
- Check browser permissions for microphone/camera
- Ensure HTTPS for production (required for WebRTC)
- Check firewall settings

**P2P connections failing**
- Verify UDP port 8081 is accessible
- Check NAT type (symmetric NATs may not work)
- Ensure server is reachable from both clients

**Build errors**
- Run `go mod tidy` to update dependencies
- Check Go version (requires 1.21+)
- Verify all imports are available

### Performance Optimization

- Use production build for web assets
- Enable gzip compression
- Implement connection pooling
- Add caching for static content
- Use CDN for global deployment

