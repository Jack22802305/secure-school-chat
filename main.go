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
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

type Class struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	TeacherID   string    `json:"teacher_id"`
	CreatedAt   time.Time `json:"created_at"`
}

type Message struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClassID   string    `json:"class_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	User      *User     `json:"user"`
}

type Server struct {
	users       map[string]*User
	classes     map[string]*Class
	messages    map[string][]*Message
	wsConns     map[string]*websocket.Conn
	onlineUsers map[string]*User
	sessions    map[string]string
	mutex       sync.RWMutex
	upgrader    websocket.Upgrader
}

func NewServer() *Server {
	return &Server{
		users:       make(map[string]*User),
		classes:     make(map[string]*Class),
		messages:    make(map[string][]*Message),
		wsConns:     make(map[string]*websocket.Conn),
		onlineUsers: make(map[string]*User),
		sessions:    make(map[string]string),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (s *Server) setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	userID := fmt.Sprintf("user_%d", time.Now().UnixNano())
	user := &User{
		ID:       userID,
		Username: req.Username,
		Email:    req.Email,
		Role:     req.Role,
		JoinedAt: time.Now(),
	}

	token := fmt.Sprintf("token_%d", time.Now().UnixNano())

	s.mutex.Lock()
	s.users[user.ID] = user
	s.sessions[token] = user.ID
	s.mutex.Unlock()

	response := map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("User registered: %s", user.Username)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	s.mutex.RLock()
	var user *User
	for _, u := range s.users {
		if u.Email == req.Email {
			user = u
			break
		}
	}
	s.mutex.RUnlock()

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	token := fmt.Sprintf("token_%d", time.Now().UnixNano())

	s.mutex.Lock()
	s.sessions[token] = user.ID
	s.mutex.Unlock()

	response := map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("User logged in: %s", user.Username)
}

func (s *Server) validateSession(r *http.Request) *User {
	token := r.Header.Get("Authorization")
	if token == "" {
		return nil
	}

	s.mutex.RLock()
	userID, exists := s.sessions[token]
	if !exists {
		s.mutex.RUnlock()
		return nil
	}
	user := s.users[userID]
	s.mutex.RUnlock()

	return user
}

func (s *Server) handleCreateClass(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	user := s.validateSession(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	classID := fmt.Sprintf("class_%d", time.Now().UnixNano())
	class := &Class{
		ID:          classID,
		Name:        req.Name,
		Description: req.Description,
		TeacherID:   user.ID,
		CreatedAt:   time.Now(),
	}

	s.mutex.Lock()
	s.classes[class.ID] = class
	s.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(class)
	log.Printf("Class created: %s", class.Name)
}

func (s *Server) handleGetClasses(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	user := s.validateSession(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	s.mutex.RLock()
	var userClasses []*Class
	for _, class := range s.classes {
		userClasses = append(userClasses, class)
	}
	s.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userClasses)
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	user := s.validateSession(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	classID := vars["classID"]

	var req struct {
		Content string `json:"content"`
		Type    string `json:"type"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	messageID := fmt.Sprintf("msg_%d", time.Now().UnixNano())
	message := &Message{
		ID:        messageID,
		UserID:    user.ID,
		ClassID:   classID,
		Content:   req.Content,
		CreatedAt: time.Now(),
		User:      user,
	}

	s.mutex.Lock()
	if s.messages[classID] == nil {
		s.messages[classID] = []*Message{}
	}
	s.messages[classID] = append(s.messages[classID], message)
	s.mutex.Unlock()

	s.broadcastMessage(map[string]interface{}{
		"type": "new_message",
		"data": message,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(message)
	log.Printf("Message sent: %s", req.Content)
}

func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	user := s.validateSession(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	classID := vars["classID"]

	s.mutex.RLock()
	messages := s.messages[classID]
	s.mutex.RUnlock()

	if messages == nil {
		messages = []*Message{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func (s *Server) handleGetOnlineUsers(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == "OPTIONS" {
		return
	}

	s.mutex.RLock()
	var onlineUsersList []*User
	for _, user := range s.onlineUsers {
		onlineUsersList = append(onlineUsersList, user)
	}
	s.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(onlineUsersList)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	token := r.URL.Query().Get("token")
	if token == "" {
		return
	}

	s.mutex.RLock()
	userID, exists := s.sessions[token]
	if !exists {
		s.mutex.RUnlock()
		return
	}
	user := s.users[userID]
	s.mutex.RUnlock()

	if user == nil {
		return
	}

	s.mutex.Lock()
	s.wsConns[user.ID] = conn
	s.onlineUsers[user.ID] = user
	s.mutex.Unlock()

	log.Printf("WebSocket connected: %s", user.Username)

	defer func() {
		s.mutex.Lock()
		delete(s.wsConns, user.ID)
		delete(s.onlineUsers, user.ID)
		s.mutex.Unlock()
		log.Printf("WebSocket disconnected: %s", user.Username)
	}()

	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}
	}
}

func (s *Server) broadcastMessage(msg map[string]interface{}) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, conn := range s.wsConns {
		conn.WriteJSON(msg)
	}
}

func (s *Server) serveHTML(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureSchool Chat</title>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        .bg-school { background-color: #1e3a8a; }
        .bg-school-light { background-color: #3b82f6; }
        .text-school { color: #f8fafc; }
        .text-school-muted { color: #cbd5e1; }
    </style>
</head>
<body class="bg-school">
    <div id="app"></div>
    <script>
        const { createApp, ref, reactive } = Vue;
        createApp({
            setup() {
                const user = ref(null);
                const classes = ref([]);
                const currentClass = ref(null);
                const messages = ref([]);
                const onlineUsers = ref([]);
                const messageInput = ref('');
                const showLogin = ref(true);
                const loginForm = reactive({
                    email: '',
                    password: '',
                    username: '',
                    role: 'student',
                    isRegister: false
                });

                let socket = null;
                let token = '';

                const api = {
                    async post(url, data) {
                        const response = await fetch('/api' + url, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': token
                            },
                            body: JSON.stringify(data)
                        });
                        return await response.json();
                    },
                    async get(url) {
                        const response = await fetch('/api' + url, {
                            headers: { 'Authorization': token }
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
                            token = result.token;
                            showLogin.value = false;
                            await loadClasses();
                            connectWebSocket();
                        }
                    } catch (error) {
                        alert('Login failed');
                    }
                };

                const connectWebSocket = () => {
                    const wsUrl = 'ws://' + window.location.host + '/api/ws?token=' + token;
                    socket = new WebSocket(wsUrl);
                    socket.onopen = () => console.log('Connected');
                    socket.onmessage = (event) => {
                        const data = JSON.parse(event.data);
                        if (data.type === 'new_message') {
                            messages.value.push(data.data);
                        }
                    };
                };

                const loadClasses = async () => {
                    classes.value = await api.get('/classes');
                    if (classes.value.length > 0) {
                        selectClass(classes.value[0]);
                    }
                    loadOnlineUsers();
                };

                const createClass = async () => {
                    const name = prompt('Class name:');
                    if (!name) return;
                    const newClass = await api.post('/classes', { name, description: name });
                    classes.value.push(newClass);
                    selectClass(newClass);
                };

                const selectClass = async (cls) => {
                    currentClass.value = cls;
                    messages.value = await api.get('/classes/' + cls.id + '/messages');
                };

                const sendMessage = async () => {
                    if (!messageInput.value.trim()) return;
                    await api.post('/classes/' + currentClass.value.id + '/messages', {
                        content: messageInput.value,
                        type: 'text'
                    });
                    messageInput.value = '';
                };

                const loadOnlineUsers = async () => {
                    onlineUsers.value = await api.get('/online-users');
                };

                const logout = () => {
                    user.value = null;
                    showLogin.value = true;
                    if (socket) socket.close();
                };

                return {
                    user, classes, currentClass, messages, onlineUsers, messageInput,
                    showLogin, loginForm, login, logout, createClass, selectClass,
                    sendMessage, loadOnlineUsers
                };
            },
            template: \`
                <div v-if="showLogin" class="min-h-screen flex items-center justify-center">
                    <div class="bg-school-light p-8 rounded-lg w-96">
                        <h1 class="text-2xl font-bold text-school mb-4 text-center">SecureSchool Chat</h1>
                        <form @submit.prevent="login" class="space-y-4">
                            <input v-if="loginForm.isRegister" v-model="loginForm.username" placeholder="Username" 
                                   class="w-full p-3 rounded border">
                            <input v-model="loginForm.email" placeholder="Email" type="email" required
                                   class="w-full p-3 rounded border">
                            <input v-model="loginForm.password" placeholder="Password" type="password" required
                                   class="w-full p-3 rounded border">
                            <select v-if="loginForm.isRegister" v-model="loginForm.role" class="w-full p-3 rounded border">
                                <option value="student">Student</option>
                                <option value="teacher">Teacher</option>
                            </select>
                            <button type="submit" class="w-full bg-green-600 text-white p-3 rounded">
                                {{ loginForm.isRegister ? 'Register' : 'Login' }}
                            </button>
                        </form>
                        <button @click="loginForm.isRegister = !loginForm.isRegister" 
                                class="w-full mt-4 text-blue-300">
                            {{ loginForm.isRegister ? 'Login Instead' : 'Register Instead' }}
                        </button>
                    </div>
                </div>

                <div v-else class="flex h-screen">
                    <div class="w-60 bg-school-light p-4">
                        <h3 class="text-school font-bold mb-4">Classes</h3>
                        <button v-if="user.role === 'teacher'" @click="createClass" 
                                class="w-full mb-4 bg-green-600 text-white p-2 rounded">Create Class</button>
                        <div v-for="cls in classes" :key="cls.id" @click="selectClass(cls)"
                             class="p-2 mb-2 rounded cursor-pointer hover:bg-blue-600 text-school">
                            {{ cls.name }}
                        </div>
                        <div class="mt-8">
                            <h4 class="text-school-muted text-sm mb-2">Online: {{ onlineUsers.length }}</h4>
                            <div v-for="u in onlineUsers" :key="u.id" class="text-school text-sm mb-1">
                                {{ u.username }} ({{ u.role }})
                            </div>
                        </div>
                        <button @click="logout" class="mt-4 text-red-300">Logout</button>
                    </div>

                    <div class="flex-1 flex flex-col">
                        <div class="bg-school-light p-4 border-b">
                            <h3 class="text-school font-bold">{{ currentClass?.name || 'Select Class' }}</h3>
                        </div>

                        <div class="flex-1 p-4 overflow-y-auto">
                            <div v-for="message in messages" :key="message.id" class="mb-4">
                                <div class="text-school font-bold">{{ message.user.username }} ({{ message.user.role }})</div>
                                <div class="text-school-muted text-sm">{{ new Date(message.created_at).toLocaleTimeString() }}</div>
                                <div class="text-school">{{ message.content }}</div>
                            </div>
                        </div>

                        <div class="p-4">
                            <form @submit.prevent="sendMessage" class="flex">
                                <input v-model="messageInput" placeholder="Type message..." 
                                       class="flex-1 p-3 rounded-l border">
                                <button type="submit" class="px-4 bg-green-600 text-white rounded-r">Send</button>
                            </form>
                        </div>
                    </div>
                </div>
            \`
        }).mount('#app');
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

	server := NewServer()
	router := mux.NewRouter()

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			server.setCORS(w)
			if r.Method == "OPTIONS" {
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/auth/register", server.handleRegister).Methods("POST", "OPTIONS")
	api.HandleFunc("/auth/login", server.handleLogin).Methods("POST", "OPTIONS")
	api.HandleFunc("/ws", server.handleWebSocket)
	api.HandleFunc("/classes", server.handleGetClasses).Methods("GET", "OPTIONS")
	api.HandleFunc("/classes", server.handleCreateClass).Methods("POST", "OPTIONS")
	api.HandleFunc("/classes/{classID}/messages", server.handleGetMessages).Methods("GET", "OPTIONS")
	api.HandleFunc("/classes/{classID}/messages", server.handleSendMessage).Methods("POST", "OPTIONS")
	api.HandleFunc("/online-users", server.handleGetOnlineUsers).Methods("GET", "OPTIONS")

	router.PathPrefix("/").HandlerFunc(server.serveHTML)

	fmt.Printf("SecureSchool Chat Server Starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
