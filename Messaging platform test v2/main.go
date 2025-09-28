package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type User struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	JoinedAt time.Time `json:"joined_at"`
}

type Server struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	OwnerID     string     `json:"owner_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Channels    []*Channel `json:"channels"`
}

type Channel struct {
	ID        string    `json:"id"`
	ServerID  string    `json:"server_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

type Message struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ChannelID string    `json:"channel_id"`
	Content   string    `json:"content"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
	User      *User     `json:"user"`
}

type App struct {
	users       map[string]*User
	servers     map[string]*Server
	channels    map[string]*Channel
	messages    map[string][]*Message
	wsConns     map[string]*websocket.Conn
	onlineUsers map[string]*User
	mutex       sync.RWMutex
	upgrader    websocket.Upgrader
}

func NewApp() *App {
	return &App{
		users:       make(map[string]*User),
		servers:     make(map[string]*Server),
		channels:    make(map[string]*Channel),
		messages:    make(map[string][]*Message),
		wsConns:     make(map[string]*websocket.Conn),
		onlineUsers: make(map[string]*User),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (app *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userID := fmt.Sprintf("user_%d", time.Now().UnixNano())
	user := &User{
		ID:       userID,
		Username: req.Username,
		Email:    req.Email,
		JoinedAt: time.Now(),
	}

	app.mutex.Lock()
	app.users[user.ID] = user
	app.mutex.Unlock()

	response := map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   user.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ User registered: %s", user.Username)
}

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	app.mutex.RLock()
	var user *User
	for _, u := range app.users {
		if u.Username == req.Username {
			user = u
			break
		}
	}
	app.mutex.RUnlock()

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
	log.Printf("✅ User logged in: %s", user.Username)
}

func (app *App) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	userID := r.Header.Get("Authorization")
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	serverID := fmt.Sprintf("server_%d", time.Now().UnixNano())
	server := &Server{
		ID:          serverID,
		Name:        req.Name,
		Description: req.Description,
		OwnerID:     userID,
		CreatedAt:   time.Now(),
	}

	// Create default channels
	generalID := fmt.Sprintf("channel_%d_1", time.Now().UnixNano())
	voiceID := fmt.Sprintf("channel_%d_2", time.Now().UnixNano())

	generalChannel := &Channel{
		ID:        generalID,
		ServerID:  server.ID,
		Name:      "general",
		Type:      "text",
		CreatedAt: time.Now(),
	}

	voiceChannel := &Channel{
		ID:        voiceID,
		ServerID:  server.ID,
		Name:      "General",
		Type:      "voice",
		CreatedAt: time.Now(),
	}

	app.mutex.Lock()
	app.servers[server.ID] = server
	app.channels[generalChannel.ID] = generalChannel
	app.channels[voiceChannel.ID] = voiceChannel
	app.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server)
	log.Printf("✅ Server created: %s", server.Name)
}

func (app *App) handleGetServers(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	userID := r.Header.Get("Authorization")
	app.mutex.RLock()
	var userServers []*Server
	for _, server := range app.servers {
		if server.OwnerID == userID {
			var channels []*Channel
			for _, channel := range app.channels {
				if channel.ServerID == server.ID {
					channels = append(channels, channel)
				}
			}
			server.Channels = channels
			userServers = append(userServers, server)
		}
	}
	app.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userServers)
}

func (app *App) handleGetChannels(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	vars := mux.Vars(r)
	serverID := vars["serverID"]

	app.mutex.RLock()
	var channels []*Channel
	for _, channel := range app.channels {
		if channel.ServerID == serverID {
			channels = append(channels, channel)
		}
	}
	app.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(channels)
}

func (app *App) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	vars := mux.Vars(r)
	serverID := vars["serverID"]

	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	channelID := fmt.Sprintf("channel_%d", time.Now().UnixNano())
	channel := &Channel{
		ID:        channelID,
		ServerID:  serverID,
		Name:      req.Name,
		Type:      req.Type,
		CreatedAt: time.Now(),
	}

	app.mutex.Lock()
	app.channels[channel.ID] = channel
	app.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(channel)
	log.Printf("✅ Channel created: %s", channel.Name)
}

func (app *App) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	vars := mux.Vars(r)
	channelID := vars["channelID"]

	app.mutex.RLock()
	messages := app.messages[channelID]
	app.mutex.RUnlock()

	if messages == nil {
		messages = []*Message{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func (app *App) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	vars := mux.Vars(r)
	channelID := vars["channelID"]
	userID := r.Header.Get("Authorization")

	var req struct {
		Content string `json:"content"`
		Type    string `json:"type"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	app.mutex.RLock()
	user := app.users[userID]
	app.mutex.RUnlock()

	messageID := fmt.Sprintf("msg_%d", time.Now().UnixNano())
	message := &Message{
		ID:        messageID,
		UserID:    userID,
		ChannelID: channelID,
		Content:   req.Content,
		Type:      req.Type,
		CreatedAt: time.Now(),
		User:      user,
	}

	app.mutex.Lock()
	if app.messages[channelID] == nil {
		app.messages[channelID] = []*Message{}
	}
	app.messages[channelID] = append(app.messages[channelID], message)
	app.mutex.Unlock()

	// Broadcast to all WebSocket connections
	app.broadcastMessage(map[string]interface{}{
		"type": "new_message",
		"data": message,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(message)
	log.Printf("📨 Message: %s -> %s", user.Username, req.Content)
}

func (app *App) handleGetOnlineUsers(w http.ResponseWriter, r *http.Request) {
	app.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	app.mutex.RLock()
	var onlineUsersList []map[string]interface{}
	for _, user := range app.onlineUsers {
		onlineUsersList = append(onlineUsersList, map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
		})
	}
	app.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(onlineUsersList)
}

func (app *App) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := app.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		return
	}

	app.mutex.Lock()
	user := app.users[userID]
	if user != nil {
		app.wsConns[userID] = conn
		app.onlineUsers[userID] = user
	}
	app.mutex.Unlock()

	if user == nil {
		return
	}

	log.Printf("🔌 WebSocket connected: %s", user.Username)

	// Broadcast user joined
	app.broadcastMessage(map[string]interface{}{
		"type": "user_joined",
		"data": map[string]interface{}{"user_id": userID, "username": user.Username},
	})

	defer func() {
		app.mutex.Lock()
		delete(app.wsConns, userID)
		delete(app.onlineUsers, userID)
		app.mutex.Unlock()

		log.Printf("🔌 WebSocket disconnected: %s", user.Username)

		app.broadcastMessage(map[string]interface{}{
			"type": "user_left",
			"data": map[string]interface{}{"user_id": userID, "username": user.Username},
		})
	}()

	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}
		// Handle WebSocket messages here if needed
	}
}

func (app *App) broadcastMessage(msg map[string]interface{}) {
	app.mutex.RLock()
	defer app.mutex.RUnlock()

	for userID, conn := range app.wsConns {
		if err := conn.WriteJSON(msg); err != nil {
			log.Printf("❌ Broadcast error to %s: %v", userID, err)
		}
	}
}

func (app *App) setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func (app *App) serveHTML(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Discord Clone - Online</title>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .discord-bg { background-color: #36393f; }
        .discord-sidebar { background-color: #2f3136; }
        .discord-message { background-color: #40444b; }
        .discord-input { background-color: #40444b; }
        .discord-server { background-color: #5865f2; }
        .discord-text { color: #dcddde; }
        .discord-muted { color: #8e9297; }
        .discord-online { color: #3ba55d; }
        .discord-hover:hover { background-color: #34373c; }
    </style>
</head>
<body class="discord-bg">
    <div id="app"></div>
    <script>
        const { createApp, ref, reactive, onMounted } = Vue;
        const App = {
            setup() {
                const SERVER_URL = window.location.origin;
                const WS_URL = window.location.origin.replace('http', 'ws');
                
                const user = ref(null);
                const servers = ref([]);
                const currentServer = ref(null);
                const currentChannel = ref(null);
                const channels = ref([]);
                const messages = ref([]);
                const onlineUsers = ref([]);
                const messageInput = ref('');
                const showLogin = ref(true);
                const connectionStatus = ref('disconnected');
                const loginForm = reactive({
                    username: '',
                    email: '',
                    password: '',
                    isRegister: false
                });

                let socket = null;

                const api = {
                    async post(url, data) {
                        const response = await fetch(SERVER_URL + '/api' + url, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': user.value?.id || ''
                            },
                            body: JSON.stringify(data)
                        });
                        return await response.json();
                    },
                    async get(url) {
                        const response = await fetch(SERVER_URL + '/api' + url, {
                            headers: { 'Authorization': user.value?.id || '' }
                        });
                        return await response.json();
                    }
                };

                const login = async () => {
                    try {
                        const endpoint = loginForm.isRegister ? '/auth/register' : '/auth/login';
                        const result = await api.post(endpoint, loginForm);
                        if (result.success) {
                            user.value = result.user;
                            showLogin.value = false;
                            await loadServers();
                            connectWebSocket();
                        }
                    } catch (error) {
                        alert('Login failed: ' + error.message);
                    }
                };

                const connectWebSocket = () => {
                    if (!user.value) return;
                    const wsUrl = WS_URL + '/api/ws?user_id=' + user.value.id;
                    socket = new WebSocket(wsUrl);
                    
                    socket.onopen = () => {
                        connectionStatus.value = 'connected';
                        console.log('✅ Connected to WebSocket');
                    };
                    
                    socket.onmessage = (event) => {
                        const data = JSON.parse(event.data);
                        if (data.type === 'new_message' && data.data.channel_id === currentChannel.value?.id) {
                            messages.value.push(data.data);
                            setTimeout(() => {
                                const chat = document.getElementById('chat');
                                if (chat) chat.scrollTop = chat.scrollHeight;
                            }, 100);
                        } else if (data.type === 'user_joined' || data.type === 'user_left') {
                            loadOnlineUsers();
                        }
                    };
                    
                    socket.onclose = () => {
                        connectionStatus.value = 'disconnected';
                        if (user.value) {
                            setTimeout(connectWebSocket, 3000);
                        }
                    };
                };

                const loadOnlineUsers = async () => {
                    try {
                        onlineUsers.value = await api.get('/online-users');
                    } catch (error) {
                        console.error('Failed to load online users');
                    }
                };

                const loadServers = async () => {
                    try {
                        servers.value = await api.get('/servers');
                        if (servers.value.length > 0) {
                            selectServer(servers.value[0]);
                        }
                        await loadOnlineUsers();
                    } catch (error) {
                        console.error('Failed to load servers');
                    }
                };

                const createServer = async () => {
                    const name = prompt('Server name:');
                    if (!name) return;
                    try {
                        const server = await api.post('/servers', { name, description: name + ' server' });
                        servers.value.push(server);
                        selectServer(server);
                    } catch (error) {
                        alert('Failed to create server');
                    }
                };

                const selectServer = async (server) => {
                    currentServer.value = server;
                    await loadChannels(server.id);
                };

                const loadChannels = async (serverId) => {
                    try {
                        channels.value = await api.get('/servers/' + serverId + '/channels');
                        if (channels.value.length > 0) {
                            selectChannel(channels.value[0]);
                        }
                    } catch (error) {
                        console.error('Failed to load channels');
                    }
                };

                const createChannel = async () => {
                    if (!currentServer.value) return;
                    const name = prompt('Channel name:');
                    if (!name) return;
                    const type = confirm('Voice channel?') ? 'voice' : 'text';
                    try {
                        const channel = await api.post('/servers/' + currentServer.value.id + '/channels', { name, type });
                        channels.value.push(channel);
                    } catch (error) {
                        alert('Failed to create channel');
                    }
                };

                const selectChannel = async (channel) => {
                    currentChannel.value = channel;
                    await loadMessages(channel.id);
                };

                const loadMessages = async (channelId) => {
                    try {
                        messages.value = await api.get('/channels/' + channelId + '/messages');
                        setTimeout(() => {
                            const chat = document.getElementById('chat');
                            if (chat) chat.scrollTop = chat.scrollHeight;
                        }, 100);
                    } catch (error) {
                        console.error('Failed to load messages');
                    }
                };

                const sendMessage = async () => {
                    if (!messageInput.value.trim() || !currentChannel.value) return;
                    try {
                        await api.post('/channels/' + currentChannel.value.id + '/messages', {
                            content: messageInput.value,
                            type: 'text'
                        });
                        messageInput.value = '';
                    } catch (error) {
                        alert('Failed to send message');
                    }
                };

                const formatTime = (timestamp) => {
                    return new Date(timestamp).toLocaleTimeString();
                };

                const logout = () => {
                    user.value = null;
                    showLogin.value = true;
                    if (socket) socket.close();
                };

                return {
                    user, servers, currentServer, currentChannel, channels, messages,
                    onlineUsers, messageInput, showLogin, connectionStatus, loginForm,
                    login, logout, loadServers, createServer, selectServer, loadChannels,
                    createChannel, selectChannel, sendMessage, formatTime, SERVER_URL
                };
            },
            template: \`
                <div v-if="showLogin" class="min-h-screen flex items-center justify-center">
                    <div class="discord-message p-8 rounded-lg w-96">
                        <h1 class="text-2xl font-bold discord-text mb-4 text-center">Discord Clone</h1>
                        <p class="text-sm discord-muted text-center mb-6">{{ SERVER_URL }}</p>
                        <form @submit.prevent="login" class="space-y-4">
                            <input v-model="loginForm.username" placeholder="Username" required
                                   class="w-full p-3 discord-input rounded discord-text border-0">
                            <input v-if="loginForm.isRegister" v-model="loginForm.email" placeholder="Email" type="email"
                                   class="w-full p-3 discord-input rounded discord-text border-0">
                            <input v-model="loginForm.password" placeholder="Password" type="password" required
                                   class="w-full p-3 discord-input rounded discord-text border-0">
                            <button type="submit" class="w-full discord-server text-white p-3 rounded font-medium">
                                {{ loginForm.isRegister ? 'Register' : 'Login' }}
                            </button>
                        </form>
                        <p class="discord-muted text-center mt-4 text-sm">
                            {{ loginForm.isRegister ? 'Have an account?' : 'Need an account?' }}
                            <button @click="loginForm.isRegister = !loginForm.isRegister" class="text-blue-400 hover:underline ml-1">
                                {{ loginForm.isRegister ? 'Login' : 'Register' }}
                            </button>
                        </p>
                    </div>
                </div>

                <div v-else class="flex h-screen">
                    <div class="w-16 discord-sidebar flex flex-col items-center py-3 space-y-2">
                        <div v-for="server in servers" :key="server.id" @click="selectServer(server)"
                             :class="['w-12 h-12 rounded-full flex items-center justify-center cursor-pointer text-white font-bold text-sm', 
                                     currentServer?.id === server.id ? 'discord-server' : 'discord-message']">
                            {{ server.name.charAt(0).toUpperCase() }}
                        </div>
                        <button @click="createServer" class="w-12 h-12 rounded-full discord-message flex items-center justify-center text-green-400">
                            <i class="fas fa-plus"></i>
                        </button>
                    </div>

                    <div class="w-60 discord-sidebar flex flex-col">
                        <div class="p-4 border-b border-gray-600">
                            <h3 class="discord-text font-bold">{{ currentServer?.name || 'Select Server' }}</h3>
                            <div class="flex items-center mt-2">
                                <div :class="['w-2 h-2 rounded-full mr-2', connectionStatus === 'connected' ? 'bg-green-400' : 'bg-red-400']"></div>
                                <span class="text-xs discord-muted">{{ connectionStatus }}</span>
                            </div>
                        </div>
                        
                        <div class="flex-1 p-2 overflow-y-auto">
                            <div class="mb-4">
                                <div class="flex items-center justify-between mb-2">
                                    <h4 class="discord-muted text-xs font-semibold uppercase">Text Channels</h4>
                                    <button @click="createChannel" class="discord-muted hover:discord-text">
                                        <i class="fas fa-plus text-xs"></i>
                                    </button>
                                </div>
                                <div v-for="channel in channels.filter(c => c.type === 'text')" :key="channel.id" @click="selectChannel(channel)"
                                     :class="['flex items-center p-2 rounded cursor-pointer', currentChannel?.id === channel.id ? 'discord-message' : 'discord-hover']">
                                    <i class="fas fa-hashtag discord-muted mr-2 text-sm"></i>
                                    <span class="discord-text text-sm">{{ channel.name }}</span>
                                </div>
                            </div>
                            
                            <div>
                                <h4 class="discord-muted text-xs font-semibold uppercase mb-2">Voice Channels</h4>
                                <div v-for="channel in channels.filter(c => c.type === 'voice')" :key="channel.id" @click="selectChannel(channel)"
                                     :class="['flex items-center p-2 rounded cursor-pointer', currentChannel?.id === channel.id ? 'discord-message' : 'discord-hover']">
                                    <i class="fas fa-volume-up discord-muted mr-2 text-sm"></i>
                                    <span class="discord-text text-sm">{{ channel.name }}</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="p-3 border-t border-gray-600 flex items-center">
                            <div class="w-8 h-8 rounded-full discord-server flex items-center justify-center text-white text-sm font-bold mr-2">
                                {{ user?.username?.charAt(0).toUpperCase() }}
                            </div>
                            <div class="flex-1">
                                <div class="discord-text text-sm font-medium">{{ user?.username }}</div>
                                <div class="discord-online text-xs">Online</div>
                            </div>
                            <button @click="logout" class="discord-muted hover:discord-text">
                                <i class="fas fa-sign-out-alt"></i>
                            </button>
                        </div>
                    </div>

                    <div class="flex-1 flex flex-col">
                        <div class="p-4 border-b border-gray-600">
                            <h3 class="discord-text font-bold"># {{ currentChannel?.name || 'Select Channel' }}</h3>
                        </div>

                        <div id="chat" class="flex-1 p-4 overflow-y-auto">
                            <div v-if="messages.length === 0" class="text-center discord-muted py-8">
                                <p>No messages yet. Start the conversation!</p>
                            </div>
                            <div v-for="message in messages" :key="message.id" class="mb-4 flex">
                                <div class="w-10 h-10 rounded-full discord-server flex items-center justify-center text-white text-sm font-bold mr-3">
                                    {{ message.user?.username?.charAt(0).toUpperCase() || 'U' }}
                                </div>
                                <div class="flex-1">
                                    <div class="flex items-baseline mb-1">
                                        <span class="discord-text font-medium mr-2">{{ message.user?.username || 'Unknown' }}</span>
                                        <span class="discord-muted text-xs">{{ formatTime(message.created_at) }}</span>
                                    </div>
                                    <div class="discord-text">{{ message.content }}</div>
                                </div>
                            </div>
                        </div>

                        <div class="p-4">
                            <form @submit.prevent="sendMessage" class="flex">
                                <input v-model="messageInput" :placeholder="'Message #' + (currentChannel?.name || 'channel')"
                                       :disabled="connectionStatus !== 'connected'"
                                       class="flex-1 p-3 discord-input rounded-l discord-text border-0">
                                <button type="submit" :disabled="connectionStatus !== 'connected'"
                                        class="px-4 discord-server text-white rounded-r">
                                    <i class="fas fa-paper-plane"></i>
                                </button>
                            </form>
                        </div>
                    </div>

                    <div class="w-60 discord-sidebar p-4">
                        <h4 class="discord-muted text-xs font-semibold uppercase mb-3">Online — {{ onlineUsers.length }}</h4>
                        <div v-for="onlineUser in onlineUsers" :key="onlineUser.id" class="flex items-center mb-2">
                            <div class="w-8 h-8 rounded-full discord-server flex items-center justify-center text-white text-sm font-bold mr-2">
                                {{ onlineUser.username.charAt(0).toUpperCase() }}
                            </div>
                            <span class="discord-text text-sm">{{ onlineUser.username }}</span>
                            <div class="ml-auto w-2 h-2 rounded-full bg-green-400"></div>
                        </div>
                    </div>
                </div>
            \`
        };
        createApp(App).mount('#app');
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	app := NewApp()
	router := mux.NewRouter()

	// CORS middleware
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			app.setCORS(w)
			if r.Method == "OPTIONS" {
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// API routes
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/auth/register", app.handleRegister).Methods("POST", "OPTIONS")
	api.HandleFunc("/auth/login", app.handleLogin).Methods("POST", "OPTIONS")
	api.HandleFunc("/ws", app.handleWebSocket)
	api.HandleFunc("/servers", app.handleGetServers).Methods("GET", "OPTIONS")
	api.HandleFunc("/servers", app.handleCreateServer).Methods("POST", "OPTIONS")
	api.HandleFunc("/servers/{serverID}/channels", app.handleGetChannels).Methods("GET", "OPTIONS")
	api.HandleFunc("/servers/{serverID}/channels", app.handleCreateChannel).Methods("POST", "OPTIONS")
	api.HandleFunc("/channels/{channelID}/messages", app.handleGetMessages).Methods("GET", "OPTIONS")
	api.HandleFunc("/channels/{channelID}/messages", app.handleSendMessage).Methods("POST", "OPTIONS")
	api.HandleFunc("/online-users", app.handleGetOnlineUsers).Methods("GET", "OPTIONS")

	// Serve HTML
	router.PathPrefix("/").HandlerFunc(app.serveHTML)

	fmt.Printf("🚀 Discord Clone Server Starting!\n")
	fmt.Printf("================================\n")
	fmt.Printf("✅ Port: %s\n", port)
	fmt.Printf("🌐 Local: http://localhost:%s\n", port)
	fmt.Printf("🌍 Ready for online deployment!\n")
	fmt.Printf("⏹️  Press Ctrl+C to stop\n\n")

	log.Fatal(http.ListenAndServe(":"+port, router))
}
