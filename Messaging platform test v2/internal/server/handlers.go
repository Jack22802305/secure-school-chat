package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"discord-clone/internal/shared"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req shared.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Hash password (simplified for demo - in production, store this hash)
	_, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Create user
	user := shared.User{
		ID:        uuid.New().String(),
		Username:  req.Username,
		Email:     req.Email,
		Status:    "offline",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save to database (password would be stored separately in production)
	if err := s.db.Create(&user).Error; err != nil {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		return
	}

	response := shared.AuthResponse{
		Success: true,
		User:    &user,
		Token:   user.ID, // Simplified token for demo
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req shared.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user shared.User
	if err := s.db.Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error; err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// In production, verify password hash here
	response := shared.AuthResponse{
		Success: true,
		User:    &user,
		Token:   user.ID, // Simplified token for demo
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		conn.WriteMessage(websocket.TextMessage, []byte(`{"error": "user_id required"}`))
		return
	}

	// Store connection
	s.wsConnsMux.Lock()
	s.wsConnections[userID] = conn
	s.wsConnsMux.Unlock()

	// Remove connection on disconnect
	defer func() {
		s.wsConnsMux.Lock()
		delete(s.wsConnections, userID)
		s.wsConnsMux.Unlock()
	}()

	// Handle messages
	for {
		var msg shared.WebSocketMessage
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}

		s.handleWebSocketMessage(userID, &msg)
	}
}

func (s *Server) handleWebSocketMessage(userID string, msg *shared.WebSocketMessage) {
	switch msg.Type {
	case "join_channel":
		// Handle joining a channel
		s.broadcastToChannel(msg.Data.(map[string]interface{})["channel_id"].(string), shared.WebSocketMessage{
			Type: "user_joined",
			Data: map[string]interface{}{
				"user_id": userID,
			},
		})
	case "leave_channel":
		// Handle leaving a channel
		s.broadcastToChannel(msg.Data.(map[string]interface{})["channel_id"].(string), shared.WebSocketMessage{
			Type: "user_left",
			Data: map[string]interface{}{
				"user_id": userID,
			},
		})
	case "join_voice_channel":
		// Handle joining a voice channel
		data := msg.Data.(map[string]interface{})
		channelID := data["channel_id"].(string)

		s.broadcastToChannel(channelID, shared.WebSocketMessage{
			Type: "user_joined_voice",
			Data: map[string]interface{}{
				"user_id":    userID,
				"channel_id": channelID,
				"video":      data["video"],
			},
		})
	case "leave_voice_channel":
		// Handle leaving a voice channel
		s.broadcastToAll(shared.WebSocketMessage{
			Type: "user_left_voice",
			Data: map[string]interface{}{
				"user_id": userID,
			},
		})
	case "webrtc_offer":
		// Forward WebRTC offer to target user
		data := msg.Data.(map[string]interface{})
		targetUserID := data["to"].(string)
		s.sendToUser(targetUserID, shared.WebSocketMessage{
			Type: "webrtc_offer",
			Data: map[string]interface{}{
				"from":  userID,
				"offer": data["offer"],
			},
		})
	case "webrtc_answer":
		// Forward WebRTC answer to target user
		data := msg.Data.(map[string]interface{})
		targetUserID := data["to"].(string)
		s.sendToUser(targetUserID, shared.WebSocketMessage{
			Type: "webrtc_answer",
			Data: map[string]interface{}{
				"from":   userID,
				"answer": data["answer"],
			},
		})
	case "webrtc_ice_candidate":
		// Forward ICE candidate to target user
		data := msg.Data.(map[string]interface{})
		targetUserID := data["to"].(string)
		s.sendToUser(targetUserID, shared.WebSocketMessage{
			Type: "webrtc_ice_candidate",
			Data: map[string]interface{}{
				"from":      userID,
				"candidate": data["candidate"],
			},
		})
	}
}

func (s *Server) broadcastToChannel(channelID string, msg shared.WebSocketMessage) {
	// In a real implementation, you'd track which users are in which channels
	s.wsConnsMux.RLock()
	defer s.wsConnsMux.RUnlock()

	for _, conn := range s.wsConnections {
		conn.WriteJSON(msg)
	}
}

func (s *Server) broadcastToAll(msg shared.WebSocketMessage) {
	s.wsConnsMux.RLock()
	defer s.wsConnsMux.RUnlock()

	for _, conn := range s.wsConnections {
		conn.WriteJSON(msg)
	}
}

func (s *Server) sendToUser(userID string, msg shared.WebSocketMessage) {
	s.wsConnsMux.RLock()
	defer s.wsConnsMux.RUnlock()

	if conn, exists := s.wsConnections[userID]; exists {
		conn.WriteJSON(msg)
	}
}

func (s *Server) handleGetServers(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Authorization") // Simplified auth

	var servers []shared.Server
	s.db.Preload("Channels").Where("owner_id = ?", userID).Find(&servers)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("Authorization") // Simplified auth

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	server := shared.Server{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		OwnerID:     userID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.db.Create(&server).Error; err != nil {
		http.Error(w, "Failed to create server", http.StatusInternalServerError)
		return
	}

	// Create default channels
	generalChannel := shared.Channel{
		ID:        uuid.New().String(),
		ServerID:  server.ID,
		Name:      "general",
		Type:      "text",
		Position:  0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	voiceChannel := shared.Channel{
		ID:        uuid.New().String(),
		ServerID:  server.ID,
		Name:      "General",
		Type:      "voice",
		Position:  1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	s.db.Create(&generalChannel)
	s.db.Create(&voiceChannel)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server)
}

func (s *Server) handleGetChannels(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverID := vars["serverID"]

	var channels []shared.Channel
	s.db.Where("server_id = ?", serverID).Order("position").Find(&channels)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(channels)
}

func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
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

	channel := shared.Channel{
		ID:        uuid.New().String(),
		ServerID:  serverID,
		Name:      req.Name,
		Type:      req.Type,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.db.Create(&channel).Error; err != nil {
		http.Error(w, "Failed to create channel", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(channel)
}

func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelID := vars["channelID"]

	var messages []shared.Message
	s.db.Preload("User").Where("channel_id = ?", channelID).Order("created_at").Find(&messages)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelID := vars["channelID"]
	userID := r.Header.Get("Authorization") // Simplified auth

	var req struct {
		Content string `json:"content"`
		Type    string `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	message := shared.Message{
		ID:        uuid.New().String(),
		UserID:    userID,
		ChannelID: channelID,
		Content:   req.Content,
		Type:      req.Type,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.db.Create(&message).Error; err != nil {
		http.Error(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	// Load user info
	s.db.Preload("User").First(&message, message.ID)

	// Broadcast to WebSocket connections
	s.broadcastToChannel(channelID, shared.WebSocketMessage{
		Type: "new_message",
		Data: message,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(message)
}
