package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type Class struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Message struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	User    *User  `json:"user"`
}

type Server struct {
	users    map[string]*User
	classes  map[string]*Class
	messages map[string][]*Message
	sessions map[string]string
	mutex    sync.RWMutex
}

func NewServer() *Server {
	return &Server{
		users:    make(map[string]*User),
		classes:  make(map[string]*Class),
		messages: make(map[string][]*Message),
		sessions: make(map[string]string),
	}
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
	}

	token := fmt.Sprintf("token_%d", time.Now().UnixNano())

	s.mutex.Lock()
	s.users[userID] = user
	s.sessions[token] = userID
	s.mutex.Unlock()

	response := map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
}

func (s *Server) handleCreateClass(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == "OPTIONS" {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	classID := fmt.Sprintf("class_%d", time.Now().UnixNano())
	class := &Class{
		ID:   classID,
		Name: req.Name,
	}

	s.mutex.Lock()
	s.classes[classID] = class
	s.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(class)
}

func (s *Server) handleGetClasses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == "OPTIONS" {
		return
	}

	s.mutex.RLock()
	var classList []*Class
	for _, class := range s.classes {
		classList = append(classList, class)
	}
	s.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(classList)
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("Authorization")
	s.mutex.RLock()
	userID := s.sessions[token]
	user := s.users[userID]
	s.mutex.RUnlock()

	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Content string `json:"content"`
		ClassID string `json:"class_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	messageID := fmt.Sprintf("msg_%d", time.Now().UnixNano())
	message := &Message{
		ID:      messageID,
		Content: req.Content,
		User:    user,
	}

	s.mutex.Lock()
	if s.messages[req.ClassID] == nil {
		s.messages[req.ClassID] = []*Message{}
	}
	s.messages[req.ClassID] = append(s.messages[req.ClassID], message)
	s.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(message)
}

func (s *Server) serveHTML(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>SecureSchool Chat</title>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <style>
        body { font-family: Arial; background: #1e3a8a; color: white; margin: 0; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .login { background: #3b82f6; padding: 30px; border-radius: 10px; margin-top: 100px; }
        .chat { display: flex; height: 90vh; }
        .sidebar { width: 200px; background: #1e40af; padding: 20px; }
        .messages { flex: 1; padding: 20px; }
        input, button, select { padding: 10px; margin: 5px; border: none; border-radius: 5px; }
        button { background: #10b981; color: white; cursor: pointer; }
        .message { background: #374151; padding: 10px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div id="app"></div>
    <script>
        const { createApp, ref, reactive } = Vue;
        createApp({
            setup() {
                const user = ref(null);
                const classes = ref([]);
                const messages = ref([]);
                const messageInput = ref('');
                const showLogin = ref(true);
                const loginForm = reactive({
                    email: '', password: '', username: '', role: 'student', isRegister: false
                });

                const api = {
                    async post(url, data) {
                        const response = await fetch('/api' + url, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });
                        return await response.json();
                    }
                };

                const login = async () => {
                    const endpoint = loginForm.isRegister ? '/auth/register' : '/auth/login';
                    const result = await api.post(endpoint, loginForm);
                    if (result.success) {
                        user.value = result.user;
                        showLogin.value = false;
                        loadClasses();
                    }
                };

                const loadClasses = async () => {
                    classes.value = await api.post('/classes/list', {});
                };

                const createClass = async () => {
                    const name = prompt('Class name:');
                    if (name) {
                        await api.post('/classes/create', { name });
                        loadClasses();
                    }
                };

                return {
                    user, classes, messages, messageInput, showLogin, loginForm,
                    login, loadClasses, createClass
                };
            },
            template: \`
                <div class="container">
                    <div v-if="showLogin" class="login">
                        <h1>SecureSchool Chat</h1>
                        <form @submit.prevent="login">
                            <div v-if="loginForm.isRegister">
                                <input v-model="loginForm.username" placeholder="Username" required>
                            </div>
                            <input v-model="loginForm.email" placeholder="Email" required>
                            <input v-model="loginForm.password" placeholder="Password" type="password" required>
                            <div v-if="loginForm.isRegister">
                                <select v-model="loginForm.role">
                                    <option value="student">Student</option>
                                    <option value="teacher">Teacher</option>
                                </select>
                            </div>
                            <button type="submit">{{ loginForm.isRegister ? 'Register' : 'Login' }}</button>
                        </form>
                        <button @click="loginForm.isRegister = !loginForm.isRegister">
                            {{ loginForm.isRegister ? 'Login Instead' : 'Register Instead' }}
                        </button>
                    </div>

                    <div v-else class="chat">
                        <div class="sidebar">
                            <h3>Classes</h3>
                            <button v-if="user.role === 'teacher'" @click="createClass">Create Class</button>
                            <div v-for="cls in classes" :key="cls.id">{{ cls.name }}</div>
                        </div>
                        <div class="messages">
                            <h3>Messages</h3>
                            <div v-for="msg in messages" :key="msg.id" class="message">
                                <strong>{{ msg.user.username }}:</strong> {{ msg.content }}
                            </div>
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

	http.HandleFunc("/", server.serveHTML)
	http.HandleFunc("/api/auth/register", server.handleRegister)
	http.HandleFunc("/api/auth/login", server.handleLogin)
	http.HandleFunc("/api/classes/create", server.handleCreateClass)
	http.HandleFunc("/api/classes/list", server.handleGetClasses)
	http.HandleFunc("/api/messages/send", server.handleSendMessage)

	fmt.Printf("Server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, http.DefaultServeMux))
}
