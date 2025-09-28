package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"discord-clone/internal/shared"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Server struct {
	httpPort   string
	udpPort    string
	db         *gorm.DB
	httpServer *http.Server
	udpConn    *net.UDPConn
	
	// Connected peers
	peers    map[string]*shared.PeerInfo
	peersMux sync.RWMutex
	
	// WebSocket connections
	wsConnections map[string]*websocket.Conn
	wsConnsMux    sync.RWMutex
	
	// WebSocket upgrader
	upgrader websocket.Upgrader
}

func NewServer(httpPort, udpPort, dbPath string) (*Server, error) {
	// Initialize database
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(
		&shared.User{},
		&shared.Server{},
		&shared.Channel{},
		&shared.Message{},
		&shared.ServerInvite{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to migrate database: %v", err)
	}

	s := &Server{
		httpPort:      httpPort,
		udpPort:       udpPort,
		db:            db,
		peers:         make(map[string]*shared.PeerInfo),
		wsConnections: make(map[string]*websocket.Conn),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for development
			},
		},
	}

	return s, nil
}

func (s *Server) Start() error {
	// Start UDP server
	go s.startUDPServer()
	
	// Start HTTP server
	return s.startHTTPServer()
}

func (s *Server) startHTTPServer() error {
	router := mux.NewRouter()
	
	// API routes
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/auth/register", s.handleRegister).Methods("POST")
	api.HandleFunc("/auth/login", s.handleLogin).Methods("POST")
	api.HandleFunc("/ws", s.handleWebSocket)
	api.HandleFunc("/servers", s.handleGetServers).Methods("GET")
	api.HandleFunc("/servers", s.handleCreateServer).Methods("POST")
	api.HandleFunc("/servers/{serverID}/channels", s.handleGetChannels).Methods("GET")
	api.HandleFunc("/servers/{serverID}/channels", s.handleCreateChannel).Methods("POST")
	api.HandleFunc("/channels/{channelID}/messages", s.handleGetMessages).Methods("GET")
	api.HandleFunc("/channels/{channelID}/messages", s.handleSendMessage).Methods("POST")
	
	// Serve static files
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/dist/")))
	
	s.httpServer = &http.Server{
		Addr:    ":" + s.httpPort,
		Handler: router,
	}
	
	log.Printf("HTTP server starting on port %s", s.httpPort)
	return s.httpServer.ListenAndServe()
}

func (s *Server) startUDPServer() {
	addr, err := net.ResolveUDPAddr("udp", ":"+s.udpPort)
	if err != nil {
		log.Fatal("Failed to resolve UDP address:", err)
	}

	s.udpConn, err = net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal("Failed to start UDP server:", err)
	}
	defer s.udpConn.Close()

	log.Printf("UDP server starting on port %s", s.udpPort)

	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := s.udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		go s.handleUDPMessage(buffer[:n], clientAddr)
	}
}

func (s *Server) handleUDPMessage(data []byte, clientAddr *net.UDPAddr) {
	var msg shared.P2PMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Failed to unmarshal UDP message: %v", err)
		return
	}

	switch msg.Type {
	case shared.MsgTypeRegister:
		s.handlePeerRegister(&msg, clientAddr)
	case shared.MsgTypeEstablish:
		s.handleEstablishConnection(&msg, clientAddr)
	case shared.MsgTypeHeartbeat:
		s.handleHeartbeat(&msg, clientAddr)
	default:
		log.Printf("Unknown UDP message type: %s", msg.Type)
	}
}

func (s *Server) handlePeerRegister(msg *shared.P2PMessage, clientAddr *net.UDPAddr) {
	peerInfo := &shared.PeerInfo{
		ID:         msg.From,
		PublicAddr: clientAddr,
		LastSeen:   time.Now(),
		Status:     "online",
	}

	s.peersMux.Lock()
	s.peers[msg.From] = peerInfo
	s.peersMux.Unlock()

	log.Printf("Peer registered: %s from %s", msg.From, clientAddr)

	// Send acknowledgment
	response := shared.P2PMessage{
		Type:      "register_ack",
		To:        msg.From,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"success": true},
	}

	s.sendUDPMessage(&response, clientAddr)
}

func (s *Server) handleEstablishConnection(msg *shared.P2PMessage, clientAddr *net.UDPAddr) {
	var req shared.EstablishRequest
	data, _ := json.Marshal(msg.Data)
	json.Unmarshal(data, &req)

	s.peersMux.RLock()
	targetPeer, exists := s.peers[req.PeerID]
	sourcePeer, sourceExists := s.peers[msg.From]
	s.peersMux.RUnlock()

	if !exists || !sourceExists {
		response := shared.EstablishResponse{
			Success: false,
			Message: "Peer not found",
		}
		
		responseMsg := shared.P2PMessage{
			Type:      "establish_response",
			To:        msg.From,
			Data:      response,
			Timestamp: time.Now(),
		}
		
		s.sendUDPMessage(&responseMsg, clientAddr)
		return
	}

	// Send connection info to both peers
	s.facilitateConnection(sourcePeer, targetPeer)
}

func (s *Server) facilitateConnection(peer1, peer2 *shared.PeerInfo) {
	// Send peer2's info to peer1
	response1 := shared.P2PMessage{
		Type: "establish_response",
		To:   peer1.ID,
		Data: shared.EstablishResponse{
			Success:  true,
			PeerInfo: peer2,
		},
		Timestamp: time.Now(),
	}

	// Send peer1's info to peer2
	response2 := shared.P2PMessage{
		Type: "establish_response",
		To:   peer2.ID,
		Data: shared.EstablishResponse{
			Success:  true,
			PeerInfo: peer1,
		},
		Timestamp: time.Now(),
	}

	s.sendUDPMessage(&response1, peer1.PublicAddr.(*net.UDPAddr))
	s.sendUDPMessage(&response2, peer2.PublicAddr.(*net.UDPAddr))

	log.Printf("Facilitated connection between %s and %s", peer1.ID, peer2.ID)
}

func (s *Server) handleHeartbeat(msg *shared.P2PMessage, clientAddr *net.UDPAddr) {
	s.peersMux.Lock()
	if peer, exists := s.peers[msg.From]; exists {
		peer.LastSeen = time.Now()
	}
	s.peersMux.Unlock()
}

func (s *Server) sendUDPMessage(msg *shared.P2PMessage, addr *net.UDPAddr) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to marshal UDP message: %v", err)
		return
	}

	_, err = s.udpConn.WriteToUDP(data, addr)
	if err != nil {
		log.Printf("Failed to send UDP message: %v", err)
	}
}

func (s *Server) Shutdown() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}
	
	if s.udpConn != nil {
		s.udpConn.Close()
	}
}

