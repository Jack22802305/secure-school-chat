package shared

import (
	"net"
	"time"
)

// Message types for P2P communication
const (
	MsgTypeRegister    = "register"
	MsgTypeEstablish   = "establish"
	MsgTypeChat        = "chat"
	MsgTypeVoice       = "voice"
	MsgTypeVideo       = "video"
	MsgTypeHeartbeat   = "heartbeat"
	MsgTypeUserJoin    = "user_join"
	MsgTypeUserLeave   = "user_leave"
	MsgTypeChannelMsg  = "channel_message"
	MsgTypeDirectMsg   = "direct_message"
)

// User represents a connected user
type User struct {
	ID          string    `json:"id" gorm:"primaryKey"`
	Username    string    `json:"username" gorm:"unique;not null"`
	Email       string    `json:"email" gorm:"unique;not null"`
	Avatar      string    `json:"avatar"`
	Status      string    `json:"status"` // online, away, busy, offline
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastSeen    time.Time `json:"last_seen"`
}

// Server represents a Discord-like server/guild
type Server struct {
	ID          string    `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"not null"`
	Description string    `json:"description"`
	OwnerID     string    `json:"owner_id" gorm:"not null"`
	Icon        string    `json:"icon"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Channels    []Channel `json:"channels" gorm:"foreignKey:ServerID"`
	Members     []User    `json:"members" gorm:"many2many:server_members;"`
}

// Channel represents a channel within a server
type Channel struct {
	ID          string    `json:"id" gorm:"primaryKey"`
	ServerID    string    `json:"server_id" gorm:"not null"`
	Name        string    `json:"name" gorm:"not null"`
	Type        string    `json:"type"` // text, voice, video
	Topic       string    `json:"topic"`
	Position    int       `json:"position"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Messages    []Message `json:"messages" gorm:"foreignKey:ChannelID"`
}

// Message represents a chat message
type Message struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    string    `json:"user_id" gorm:"not null"`
	ChannelID string    `json:"channel_id"`
	ServerID  string    `json:"server_id"`
	Content   string    `json:"content" gorm:"not null"`
	Type      string    `json:"type"` // text, image, file, system
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	User      User      `json:"user" gorm:"foreignKey:UserID"`
}

// PeerInfo represents information about a connected peer
type PeerInfo struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	PublicAddr net.Addr  `json:"public_addr"`
	LocalAddr  net.Addr  `json:"local_addr"`
	LastSeen   time.Time `json:"last_seen"`
	Status     string    `json:"status"`
}

// P2PMessage represents a message sent between peers
type P2PMessage struct {
	Type      string      `json:"type"`
	From      string      `json:"from"`
	To        string      `json:"to"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
	Encrypted bool        `json:"encrypted"`
}

// EstablishRequest represents a request to establish P2P connection
type EstablishRequest struct {
	PeerID string `json:"peer_id"`
}

// EstablishResponse represents the response for establishing P2P connection
type EstablishResponse struct {
	Success   bool      `json:"success"`
	PeerInfo  *PeerInfo `json:"peer_info,omitempty"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ChatMessage represents a chat message between peers
type ChatMessage struct {
	ID        string    `json:"id"`
	Content   string    `json:"content"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	ChannelID string    `json:"channel_id,omitempty"`
	ServerID  string    `json:"server_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // text, image, file, system
}

// VoiceData represents voice call data
type VoiceData struct {
	UserID    string `json:"user_id"`
	ChannelID string `json:"channel_id"`
	Data      []byte `json:"data"`
	Codec     string `json:"codec"`
}

// VideoData represents video call data
type VideoData struct {
	UserID    string `json:"user_id"`
	ChannelID string `json:"channel_id"`
	Data      []byte `json:"data"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Format    string `json:"format"`
}

// WebSocketMessage represents messages sent over WebSocket
type WebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// AuthRequest represents authentication request
type AuthRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	User    *User  `json:"user,omitempty"`
	Message string `json:"message,omitempty"`
}

// ServerInvite represents a server invitation
type ServerInvite struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	ServerID  string    `json:"server_id" gorm:"not null"`
	Code      string    `json:"code" gorm:"unique;not null"`
	CreatedBy string    `json:"created_by" gorm:"not null"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Uses      int       `json:"uses"`
	MaxUses   int       `json:"max_uses"`
}

