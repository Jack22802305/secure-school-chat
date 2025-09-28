package client

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"discord-clone/internal/shared"
)

type P2PClient struct {
	userID     string
	username   string
	serverAddr string
	udpConn    *net.UDPConn
	
	// Encryption keys
	privateKey []byte
	publicKey  []byte
	
	// Peer connections
	peers    map[string]*PeerConnection
	peersMux sync.RWMutex
	
	// Message handlers
	messageHandlers map[string]func(*shared.P2PMessage)
	handlersMux     sync.RWMutex
	
	// Status
	connected bool
	connMux   sync.RWMutex
}

type PeerConnection struct {
	PeerID     string
	RemoteAddr *net.UDPAddr
	SharedKey  []byte
	LastSeen   time.Time
	Status     string
}

func NewP2PClient(userID, username, serverAddr string) (*P2PClient, error) {
	privateKey, publicKey, err := shared.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	client := &P2PClient{
		userID:          userID,
		username:        username,
		serverAddr:      serverAddr,
		privateKey:      privateKey,
		publicKey:       publicKey,
		peers:           make(map[string]*PeerConnection),
		messageHandlers: make(map[string]func(*shared.P2PMessage)),
	}

	// Set up default message handlers
	client.setupDefaultHandlers()

	return client, nil
}

func (c *P2PClient) Connect() error {
	// Connect to UDP server
	serverAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve server address: %v", err)
	}

	c.udpConn, err = net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}

	c.connMux.Lock()
	c.connected = true
	c.connMux.Unlock()

	// Register with server
	if err := c.registerWithServer(); err != nil {
		return fmt.Errorf("failed to register with server: %v", err)
	}

	// Start listening for messages
	go c.listenForMessages()
	
	// Start heartbeat
	go c.startHeartbeat()

	log.Printf("P2P client connected for user %s", c.userID)
	return nil
}

func (c *P2PClient) Disconnect() {
	c.connMux.Lock()
	c.connected = false
	c.connMux.Unlock()

	if c.udpConn != nil {
		c.udpConn.Close()
	}
}

func (c *P2PClient) registerWithServer() error {
	msg := shared.P2PMessage{
		Type:      shared.MsgTypeRegister,
		From:      c.userID,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"username":   c.username,
			"public_key": c.publicKey,
		},
	}

	return c.sendToServer(&msg)
}

func (c *P2PClient) EstablishConnection(peerID string) error {
	msg := shared.P2PMessage{
		Type:      shared.MsgTypeEstablish,
		From:      c.userID,
		Timestamp: time.Now(),
		Data: shared.EstablishRequest{
			PeerID: peerID,
		},
	}

	return c.sendToServer(&msg)
}

func (c *P2PClient) SendMessage(peerID, content string) error {
	c.peersMux.RLock()
	peer, exists := c.peers[peerID]
	c.peersMux.RUnlock()

	if !exists {
		return fmt.Errorf("no connection to peer %s", peerID)
	}

	// Encrypt message if we have a shared key
	var encryptedContent string
	var encrypted bool
	if peer.SharedKey != nil {
		var err error
		encryptedContent, err = shared.EncryptMessage(peer.SharedKey, content)
		if err != nil {
			log.Printf("Failed to encrypt message: %v", err)
			encryptedContent = content
		} else {
			encrypted = true
		}
	} else {
		encryptedContent = content
	}

	chatMsg := shared.ChatMessage{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Content:   encryptedContent,
		UserID:    c.userID,
		Username:  c.username,
		Timestamp: time.Now(),
		Type:      "text",
	}

	msg := shared.P2PMessage{
		Type:      shared.MsgTypeChat,
		From:      c.userID,
		To:        peerID,
		Data:      chatMsg,
		Timestamp: time.Now(),
		Encrypted: encrypted,
	}

	return c.sendToPeer(&msg, peer.RemoteAddr)
}

func (c *P2PClient) SendVoiceData(channelID string, audioData []byte) error {
	voiceData := shared.VoiceData{
		UserID:    c.userID,
		ChannelID: channelID,
		Data:      audioData,
		Codec:     "opus",
	}

	msg := shared.P2PMessage{
		Type:      shared.MsgTypeVoice,
		From:      c.userID,
		Data:      voiceData,
		Timestamp: time.Now(),
	}

	// Broadcast to all peers in the channel
	return c.broadcastToChannel(channelID, &msg)
}

func (c *P2PClient) SendVideoData(channelID string, videoData []byte, width, height int) error {
	videoDataMsg := shared.VideoData{
		UserID:    c.userID,
		ChannelID: channelID,
		Data:      videoData,
		Width:     width,
		Height:    height,
		Format:    "h264",
	}

	msg := shared.P2PMessage{
		Type:      shared.MsgTypeVideo,
		From:      c.userID,
		Data:      videoDataMsg,
		Timestamp: time.Now(),
	}

	// Broadcast to all peers in the channel
	return c.broadcastToChannel(channelID, &msg)
}

func (c *P2PClient) broadcastToChannel(channelID string, msg *shared.P2PMessage) error {
	c.peersMux.RLock()
	defer c.peersMux.RUnlock()

	for _, peer := range c.peers {
		if err := c.sendToPeer(msg, peer.RemoteAddr); err != nil {
			log.Printf("Failed to send to peer %s: %v", peer.PeerID, err)
		}
	}

	return nil
}

func (c *P2PClient) listenForMessages() {
	buffer := make([]byte, 4096)
	
	for {
		c.connMux.RLock()
		connected := c.connected
		c.connMux.RUnlock()
		
		if !connected {
			break
		}

		n, err := c.udpConn.Read(buffer)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		var msg shared.P2PMessage
		if err := json.Unmarshal(buffer[:n], &msg); err != nil {
			log.Printf("Failed to unmarshal message: %v", err)
			continue
		}

		c.handleMessage(&msg)
	}
}

func (c *P2PClient) handleMessage(msg *shared.P2PMessage) {
	c.handlersMux.RLock()
	handler, exists := c.messageHandlers[msg.Type]
	c.handlersMux.RUnlock()

	if exists {
		handler(msg)
	} else {
		log.Printf("No handler for message type: %s", msg.Type)
	}
}

func (c *P2PClient) setupDefaultHandlers() {
	c.messageHandlers["establish_response"] = c.handleEstablishResponse
	c.messageHandlers[shared.MsgTypeChat] = c.handleChatMessage
	c.messageHandlers[shared.MsgTypeVoice] = c.handleVoiceMessage
	c.messageHandlers[shared.MsgTypeVideo] = c.handleVideoMessage
}

func (c *P2PClient) handleEstablishResponse(msg *shared.P2PMessage) {
	var response shared.EstablishResponse
	data, _ := json.Marshal(msg.Data)
	json.Unmarshal(data, &response)

	if !response.Success {
		log.Printf("Failed to establish connection: %s", response.Message)
		return
	}

	// Create peer connection
	remoteAddr, err := net.ResolveUDPAddr("udp", response.PeerInfo.PublicAddr.String())
	if err != nil {
		log.Printf("Failed to resolve peer address: %v", err)
		return
	}

	// Compute shared secret (simplified - in reality you'd exchange public keys)
	sharedSecret, err := shared.ComputeSharedSecret(c.privateKey, c.publicKey) // This should use peer's public key
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return
	}

	sharedKey := shared.DeriveAESKey(sharedSecret)

	peer := &PeerConnection{
		PeerID:     response.PeerInfo.ID,
		RemoteAddr: remoteAddr,
		SharedKey:  sharedKey,
		LastSeen:   time.Now(),
		Status:     "connected",
	}

	c.peersMux.Lock()
	c.peers[response.PeerInfo.ID] = peer
	c.peersMux.Unlock()

	log.Printf("Established connection with peer %s", response.PeerInfo.ID)
}

func (c *P2PClient) handleChatMessage(msg *shared.P2PMessage) {
	var chatMsg shared.ChatMessage
	data, _ := json.Marshal(msg.Data)
	json.Unmarshal(data, &chatMsg)

	// Decrypt if encrypted
	if msg.Encrypted {
		c.peersMux.RLock()
		peer, exists := c.peers[msg.From]
		c.peersMux.RUnlock()

		if exists && peer.SharedKey != nil {
			decrypted, err := shared.DecryptMessage(peer.SharedKey, chatMsg.Content)
			if err != nil {
				log.Printf("Failed to decrypt message: %v", err)
			} else {
				chatMsg.Content = decrypted
			}
		}
	}

	log.Printf("Received message from %s: %s", chatMsg.Username, chatMsg.Content)
}

func (c *P2PClient) handleVoiceMessage(msg *shared.P2PMessage) {
	var voiceData shared.VoiceData
	data, _ := json.Marshal(msg.Data)
	json.Unmarshal(data, &voiceData)

	log.Printf("Received voice data from %s in channel %s", voiceData.UserID, voiceData.ChannelID)
	// Here you would process the audio data
}

func (c *P2PClient) handleVideoMessage(msg *shared.P2PMessage) {
	var videoData shared.VideoData
	data, _ := json.Marshal(msg.Data)
	json.Unmarshal(data, &videoData)

	log.Printf("Received video data from %s in channel %s", videoData.UserID, videoData.ChannelID)
	// Here you would process the video data
}

func (c *P2PClient) startHeartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.connMux.RLock()
			connected := c.connected
			c.connMux.RUnlock()
			
			if !connected {
				return
			}

			msg := shared.P2PMessage{
				Type:      shared.MsgTypeHeartbeat,
				From:      c.userID,
				Timestamp: time.Now(),
			}

			c.sendToServer(&msg)
		}
	}
}

func (c *P2PClient) sendToServer(msg *shared.P2PMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	_, err = c.udpConn.Write(data)
	return err
}

func (c *P2PClient) sendToPeer(msg *shared.P2PMessage, addr *net.UDPAddr) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	return err
}

func (c *P2PClient) SetMessageHandler(msgType string, handler func(*shared.P2PMessage)) {
	c.handlersMux.Lock()
	c.messageHandlers[msgType] = handler
	c.handlersMux.Unlock()
}

func (c *P2PClient) GetConnectedPeers() []string {
	c.peersMux.RLock()
	defer c.peersMux.RUnlock()

	peers := make([]string, 0, len(c.peers))
	for peerID := range c.peers {
		peers = append(peers, peerID)
	}
	return peers
}

