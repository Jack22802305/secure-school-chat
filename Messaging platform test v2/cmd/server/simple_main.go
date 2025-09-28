package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// Simple in-memory storage (no database required)
type SimpleServer struct {
	users       map[string]*User
	servers     map[string]*Server
	channels    map[string]*Channel
	messages    map[string][]*Message
	wsConns     map[string]*websocket.Conn
	onlineUsers map[string]bool
	mutex       sync.RWMutex
	upgrader    websocket.Upgrader
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type Server struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	OwnerID  string     `json:"owner_id"`
	Channels []*Channel `json:"channels"`
}

type Channel struct {
	ID       string `json:"id"`
	ServerID string `json:"server_id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
}

type Message struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ChannelID string    `json:"channel_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	User      *User     `json:"user"`
}

func NewSimpleServer() *SimpleServer {
	return &SimpleServer{
		users:       make(map[string]*User),
		servers:     make(map[string]*Server),
		channels:    make(map[string]*Channel),
		messages:    make(map[string][]*Message),
		wsConns:     make(map[string]*websocket.Conn),
		onlineUsers: make(map[string]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (s *SimpleServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	user := &User{
		ID:       uuid.New().String(),
		Username: req.Username,
		Email:    req.Email,
	}

	s.mutex.Lock()
	s.users[user.ID] = user
	s.mutex.Unlock()

	response := map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   user.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *SimpleServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	s.mutex.RLock()
	var user *User
	for _, u := range s.users {
		if u.Username == req.Username {
			user = u
			break
		}
	}
	s.mutex.RUnlock()

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   user.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *SimpleServer) handleGetServers(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Authorization")

	s.mutex.RLock()
	var userServers []*Server
	for _, server := range s.servers {
		if server.OwnerID == userID {
			// Load channels
			var channels []*Channel
			for _, channel := range s.channels {
				if channel.ServerID == server.ID {
					channels = append(channels, channel)
				}
			}
			server.Channels = channels
			userServers = append(userServers, server)
		}
	}
	s.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userServers)
}

func (s *SimpleServer) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Authorization")

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	server := &Server{
		ID:      uuid.New().String(),
		Name:    req.Name,
		OwnerID: userID,
	}

	// Create default channels
	generalChannel := &Channel{
		ID:       uuid.New().String(),
		ServerID: server.ID,
		Name:     "general",
		Type:     "text",
	}

	voiceChannel := &Channel{
		ID:       uuid.New().String(),
		ServerID: server.ID,
		Name:     "General",
		Type:     "voice",
	}

	s.mutex.Lock()
	s.servers[server.ID] = server
	s.channels[generalChannel.ID] = generalChannel
	s.channels[voiceChannel.ID] = voiceChannel
	s.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server)
}

func (s *SimpleServer) handleGetChannels(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverID := vars["serverID"]

	s.mutex.RLock()
	var channels []*Channel
	for _, channel := range s.channels {
		if channel.ServerID == serverID {
			channels = append(channels, channel)
		}
	}
	s.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(channels)
}

func (s *SimpleServer) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverID := vars["serverID"]

	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	channel := &Channel{
		ID:       uuid.New().String(),
		ServerID: serverID,
		Name:     req.Name,
		Type:     req.Type,
	}

	s.mutex.Lock()
	s.channels[channel.ID] = channel
	s.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(channel)
}

func (s *SimpleServer) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelID := vars["channelID"]

	s.mutex.RLock()
	messages := s.messages[channelID]
	s.mutex.RUnlock()

	if messages == nil {
		messages = []*Message{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func (s *SimpleServer) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelID := vars["channelID"]
	userID := r.Header.Get("Authorization")

	var req struct {
		Content string `json:"content"`
		Type    string `json:"type"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	s.mutex.RLock()
	user := s.users[userID]
	s.mutex.RUnlock()

	message := &Message{
		ID:        uuid.New().String(),
		UserID:    userID,
		ChannelID: channelID,
		Content:   req.Content,
		CreatedAt: time.Now(),
		User:      user,
	}

	s.mutex.Lock()
	if s.messages[channelID] == nil {
		s.messages[channelID] = []*Message{}
	}
	s.messages[channelID] = append(s.messages[channelID], message)
	s.mutex.Unlock()

	// Broadcast to WebSocket connections
	s.broadcastMessage(map[string]interface{}{
		"type": "new_message",
		"data": map[string]interface{}{
			"id":         message.ID,
			"user_id":    message.UserID,
			"channel_id": message.ChannelID,
			"content":    message.Content,
			"created_at": message.CreatedAt,
			"user":       message.User,
		},
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(message)
}

func (s *SimpleServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		return
	}

	s.mutex.Lock()
	s.wsConns[userID] = conn
	s.onlineUsers[userID] = true
	s.mutex.Unlock()

	// Broadcast user joined
	s.broadcastMessage(map[string]interface{}{
		"type": "user_joined",
		"data": map[string]interface{}{"user_id": userID},
	})

	defer func() {
		s.mutex.Lock()
		delete(s.wsConns, userID)
		delete(s.onlineUsers, userID)
		s.mutex.Unlock()

		// Broadcast user left
		s.broadcastMessage(map[string]interface{}{
			"type": "user_left",
			"data": map[string]interface{}{"user_id": userID},
		})
	}()

	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}

		// Handle WebSocket messages
		msgType, ok := msg["type"].(string)
		if !ok {
			continue
		}

		switch msgType {
		case "join_channel":
			// User joined a channel - could track this for online users
			log.Printf("User %s joined channel", userID)
		case "leave_channel":
			// User left a channel
			log.Printf("User %s left channel", userID)
		}
	}
}

func (s *SimpleServer) handleGetOnlineUsers(w http.ResponseWriter, r *http.Request) {
	s.mutex.RLock()
	var onlineUsersList []map[string]interface{}
	for userID := range s.onlineUsers {
		if user, exists := s.users[userID]; exists {
			onlineUsersList = append(onlineUsersList, map[string]interface{}{
				"id":       user.ID,
				"username": user.Username,
			})
		}
	}
	s.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(onlineUsersList)
}

func (s *SimpleServer) broadcastMessage(msg map[string]interface{}) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, conn := range s.wsConns {
		conn.WriteJSON(msg)
	}
}

func main() {
	server := NewSimpleServer()

	router := mux.NewRouter()

	// API routes
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/auth/register", server.handleRegister).Methods("POST")
	api.HandleFunc("/auth/login", server.handleLogin).Methods("POST")
	api.HandleFunc("/ws", server.handleWebSocket)
	api.HandleFunc("/servers", server.handleGetServers).Methods("GET")
	api.HandleFunc("/servers", server.handleCreateServer).Methods("POST")
	api.HandleFunc("/servers/{serverID}/channels", server.handleGetChannels).Methods("GET")
	api.HandleFunc("/servers/{serverID}/channels", server.handleCreateChannel).Methods("POST")
	api.HandleFunc("/channels/{channelID}/messages", server.handleGetMessages).Methods("GET")
	api.HandleFunc("/channels/{channelID}/messages", server.handleSendMessage).Methods("POST")
	api.HandleFunc("/online-users", server.handleGetOnlineUsers).Methods("GET")

	// Serve static files
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/dist/")))

	fmt.Println("🚀 Discord Clone Server Starting!")
	fmt.Println("================================")
	fmt.Println("✅ Server running on: http://localhost:8080")
	fmt.Println("📱 Open your browser and navigate to the URL above")
	fmt.Println("🎉 Features: Real-time messaging, servers, channels")
	fmt.Println("⏹️  Press Ctrl+C to stop")
	fmt.Println("")

	log.Fatal(http.ListenAndServe(":8080", router))
}
