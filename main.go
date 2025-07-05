package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Конфигурация безопасности
const (
	JWT_SECRET_SIZE = 32
	BCRYPT_COST     = 12
	PIN_LENGTH      = 4
	MAX_DEVICES     = 5
	SESSION_TIMEOUT = 24 * time.Hour
)

// Структуры данных
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	PINHash      string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	LastSeen     time.Time `json:"last_seen"`
}

type Device struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Name         string    `json:"name"`
	Model        string    `json:"model"`
	Manufacturer string    `json:"manufacturer"`
	LastActive   time.Time `json:"last_active"`
	IsCurrent    bool      `json:"is_current"`
}

type Chat struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	IsGroup         bool      `json:"is_group"`
	LastMessage     string    `json:"last_message,omitempty"`
	LastMessageTime time.Time `json:"last_message_time,omitempty"`
	UnreadCount     int       `json:"unread_count"`
	CreatedAt       time.Time `json:"created_at"`
}

type Message struct {
	ID          string    `json:"id"`
	ChatID      string    `json:"chat_id"`
	SenderID    string    `json:"sender_id"`
	Content     string    `json:"content"`
	Type        string    `json:"type"`
	Timestamp   time.Time `json:"timestamp"`
	IsRead      bool      `json:"is_read"`
	IsEncrypted bool      `json:"is_encrypted"`
}

type Contact struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name,omitempty"`
	Status      string    `json:"status,omitempty"`
	IsOnline    bool      `json:"is_online"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// API Request/Response структуры
type RegisterRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	DeviceID string `json:"device_id"`
}

type VerifyPinRequest struct {
	PIN          string `json:"pin"`
	SessionToken string `json:"session_token"`
}

type AuthResponse struct {
	Success      bool   `json:"success"`
	SessionToken string `json:"session_token,omitempty"`
	RequiresPin  bool   `json:"requires_pin"`
	Message      string `json:"message,omitempty"`
}

type AddContactRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
}

type SendMessageRequest struct {
	Content   string `json:"content"`
	Type      string `json:"type"`
	Encrypted bool   `json:"encrypted"`
}

// WebSocket клиент
type WSClient struct {
	ID       string
	UserID   string
	Conn     *websocket.Conn
	Send     chan []byte
	server   *Server
	lastSeen time.Time
}

// Основной сервер
type Server struct {
	db         *sql.DB
	clients    map[string]*WSClient
	clientsMux sync.RWMutex
	upgrader   websocket.Upgrader
	jwtSecret  []byte
}

func NewServer() *Server {
	return &Server{
		clients: make(map[string]*WSClient),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
}

// Инициализация базы данных
func (s *Server) initDB() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			pin_hash TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			model TEXT NOT NULL,
			manufacturer TEXT NOT NULL,
			last_active DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_current BOOLEAN DEFAULT FALSE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS chats (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			is_group BOOLEAN DEFAULT FALSE,
			last_message TEXT,
			last_message_time DATETIME,
			unread_count INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS chat_participants (
			chat_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			PRIMARY KEY (chat_id, user_id),
			FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id TEXT PRIMARY KEY,
			chat_id TEXT NOT NULL,
			sender_id TEXT NOT NULL,
			content TEXT NOT NULL,
			type TEXT DEFAULT 'text',
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_read BOOLEAN DEFAULT FALSE,
			is_encrypted BOOLEAN DEFAULT TRUE,
			FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
			FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS contacts (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			contact_username TEXT NOT NULL,
			display_name TEXT,
			status TEXT,
			is_online BOOLEAN DEFAULT FALSE,
			last_seen DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS protocol_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			shared_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
			nonce_counter INTEGER DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return err
		}
	}

	return nil
}

// JWT операции
func (s *Server) generateJWT(userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(SESSION_TIMEOUT).Unix(),
		"iat":     time.Now().Unix(),
	})

	return token.SignedString(s.jwtSecret)
}

func (s *Server) validateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["user_id"].(string)
		if !ok {
			return "", fmt.Errorf("invalid user_id in token")
		}
		return userID, nil
	}

	return "", fmt.Errorf("invalid token")
}

// Middleware для аутентификации
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		userID, err := s.validateJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Обработчики API
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" || req.DeviceID == "" {
		http.Error(w, "Username, password and device_id are required", http.StatusBadRequest)
		return
	}

	// Проверка существования пользователя
	var existingID string
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", req.Username).Scan(&existingID)
	if err == nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Хеширование пароля
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), BCRYPT_COST)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Создание пользователя
	userID := s.generateID()
	_, err = s.db.Exec(`
		INSERT INTO users (id, username, password_hash, created_at, last_seen)
		VALUES (?, ?, ?, ?, ?)
	`, userID, req.Username, string(passwordHash), time.Now(), time.Now())
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Создание устройства
	_, err = s.db.Exec(`
		INSERT INTO devices (id, user_id, name, model, manufacturer, last_active, is_current)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, req.DeviceID, userID, req.DeviceName, "Android", "Unknown", time.Now(), true)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Генерация JWT токена
	token, err := s.generateJWT(userID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := AuthResponse{
		Success:      true,
		SessionToken: token,
		RequiresPin:  false,
		Message:      "Registration successful",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" || req.DeviceID == "" {
		http.Error(w, "Username, password and device_id are required", http.StatusBadRequest)
		return
	}

	// Поиск пользователя
	var user User
	err := s.db.QueryRow(`
		SELECT id, username, password_hash, pin_hash, created_at, last_seen
		FROM users WHERE username = ?
	`, req.Username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.PINHash,
		&user.CreatedAt, &user.LastSeen,
	)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Проверка пароля
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Проверка устройства
	var deviceID string
	err = s.db.QueryRow("SELECT id FROM devices WHERE id = ? AND user_id = ?", req.DeviceID, user.ID).Scan(&deviceID)
	if err != nil {
		// Устройство не найдено, создаем новое
		_, err = s.db.Exec(`
			INSERT INTO devices (id, user_id, name, model, manufacturer, last_active, is_current)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, req.DeviceID, user.ID, "Android Device", "Android", "Unknown", time.Now(), true)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		// Обновляем активность устройства
		_, err = s.db.Exec("UPDATE devices SET last_active = ?, is_current = ? WHERE id = ?", time.Now(), true, req.DeviceID)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Обновляем last_seen пользователя
	_, err = s.db.Exec("UPDATE users SET last_seen = ? WHERE id = ?", time.Now(), user.ID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Проверяем, нужен ли PIN
	requiresPin := user.PINHash != ""

	var response AuthResponse
	if requiresPin {
		// Генерируем временный токен для верификации PIN
		tempToken, err := s.generateJWT(user.ID)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response = AuthResponse{
			Success:      true,
			SessionToken: tempToken,
			RequiresPin:  true,
			Message:      "PIN verification required",
		}
	} else {
		// Генерируем полный токен
		token, err := s.generateJWT(user.ID)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response = AuthResponse{
			Success:      true,
			SessionToken: token,
			RequiresPin:  false,
			Message:      "Login successful",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleVerifyPin(w http.ResponseWriter, r *http.Request) {
	var req VerifyPinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.PIN == "" || req.SessionToken == "" {
		http.Error(w, "PIN and session_token are required", http.StatusBadRequest)
		return
	}

	// Валидация временного токена
	userID, err := s.validateJWT(req.SessionToken)
	if err != nil {
		http.Error(w, "Invalid session token", http.StatusUnauthorized)
		return
	}

	// Получение PIN хеша
	var pinHash string
	err = s.db.QueryRow("SELECT pin_hash FROM users WHERE id = ?", userID).Scan(&pinHash)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if pinHash == "" {
		http.Error(w, "PIN not set for user", http.StatusBadRequest)
		return
	}

	// Проверка PIN
	err = bcrypt.CompareHashAndPassword([]byte(pinHash), []byte(req.PIN))
	if err != nil {
		http.Error(w, "Invalid PIN", http.StatusUnauthorized)
		return
	}

	// Генерация полного токена
	token, err := s.generateJWT(userID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := AuthResponse{
		Success:      true,
		SessionToken: token,
		RequiresPin:  false,
		Message:      "PIN verification successful",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Обработчики протокола
func (s *Server) handleHandshake(w http.ResponseWriter, r *http.Request) {
	var req HandshakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateHandshakeRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Поиск пользователя
	var user User
	err := s.db.QueryRow(`
		SELECT id, username, password_hash, created_at, last_seen
		FROM users WHERE username = ?
	`, req.Username).Scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.CreatedAt, &user.LastSeen,
	)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Проверка пароля
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Генерация ephemeral ключей сервера
	serverPublicKey, serverPrivateKey, err := generateKeyPair()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Получение клиентского ключа
	clientPublicKey, err := decodeBase64(req.EphemeralKey)
	if err != nil {
		http.Error(w, "Invalid ephemeral key", http.StatusBadRequest)
		return
	}

	// Вычисление общего секрета
	sharedSecret, err := computeSharedSecret(serverPrivateKey, clientPublicKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Создание сессии
	session, err := s.createSession(user.ID, req.DeviceID, sharedSecret)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := HandshakeResponse{
		Success:      true,
		SessionID:    session.ID,
		EphemeralKey: encodeBase64(serverPublicKey),
		Message:      "Handshake successful",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleSecureMessage(w http.ResponseWriter, r *http.Request) {
	var msg SecureMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateSecureMessage(&msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Получение сессии
	session, err := s.getSession(msg.SessionID)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Проверка активности сессии
	if time.Since(session.LastActivity) > PROTOCOL_SESSION_TIMEOUT {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	// Декодирование nonce и payload
	nonce, err := decodeBase64(msg.Nonce)
	if err != nil {
		http.Error(w, "Invalid nonce", http.StatusBadRequest)
		return
	}

	payload, err := decodeBase64(msg.Payload)
	if err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Проверка replay атаки
	if !session.checkReplayAttack(nonce) {
		http.Error(w, "Replay attack detected", http.StatusBadRequest)
		return
	}

	// Дешифрование сообщения
	plaintext, err := decryptMessage(session.SharedKey, nonce, payload)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	// Парсинг payload
	var messagePayload MessagePayload
	if err := json.Unmarshal(plaintext, &messagePayload); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		return
	}

	// Обновление активности сессии
	if err := s.updateSessionActivity(session.ID); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Обработка сообщения в зависимости от типа
	var response interface{}
	switch messagePayload.Type {
	case "get_profile":
		response = s.handleGetProfileRequest(session.UserID)
	case "get_chats":
		response = s.handleGetChatsRequest(session.UserID)
	case "get_messages":
		if data, ok := messagePayload.Data.(map[string]interface{}); ok {
			if chatID, ok := data["chat_id"].(string); ok {
				response = s.handleGetMessagesRequest(session.UserID, chatID)
			}
		}
	case "send_message":
		if data, ok := messagePayload.Data.(map[string]interface{}); ok {
			if chatID, ok := data["chat_id"].(string); ok {
				if content, ok := data["content"].(string); ok {
					response = s.handleSendMessageRequest(session.UserID, chatID, content)
				}
			}
		}
	case "get_contacts":
		response = s.handleGetContactsRequest(session.UserID)
	case "add_contact":
		if data, ok := messagePayload.Data.(map[string]interface{}); ok {
			if username, ok := data["username"].(string); ok {
				response = s.handleAddContactRequest(session.UserID, username)
			}
		}
	default:
		http.Error(w, "Unknown message type", http.StatusBadRequest)
		return
	}

	// Шифрование ответа
	responseData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	responseNonce, err := generateNonce()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	encryptedResponse, err := encryptMessage(session.SharedKey, responseNonce, responseData)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	secureResponse := SecureMessage{
		SessionID: session.ID,
		Nonce:     encodeBase64(responseNonce),
		Payload:   encodeBase64(encryptedResponse),
		MAC:       encodeBase64([]byte{}), // MAC включен в AEAD
		Timestamp: time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secureResponse)
}

// Обработчики запросов протокола
func (s *Server) handleGetProfileRequest(userID string) map[string]interface{} {
	var user User
	err := s.db.QueryRow(`
		SELECT id, username, created_at, last_seen
		FROM users WHERE id = ?
	`, userID).Scan(&user.ID, &user.Username, &user.CreatedAt, &user.LastSeen)
	if err != nil {
		return map[string]interface{}{"error": "User not found"}
	}

	return map[string]interface{}{
		"success": true,
		"profile": user,
	}
}

func (s *Server) handleGetChatsRequest(userID string) map[string]interface{} {
	rows, err := s.db.Query(`
		SELECT c.id, c.name, c.is_group, c.last_message, c.last_message_time, c.unread_count, c.created_at
		FROM chats c
		JOIN chat_participants cp ON c.id = cp.chat_id
		WHERE cp.user_id = ?
		ORDER BY c.last_message_time DESC NULLS LAST
	`, userID)
	if err != nil {
		return map[string]interface{}{"error": "Database error"}
	}
	defer rows.Close()

	var chats []Chat
	for rows.Next() {
		var chat Chat
		err := rows.Scan(
			&chat.ID, &chat.Name, &chat.IsGroup, &chat.LastMessage,
			&chat.LastMessageTime, &chat.UnreadCount, &chat.CreatedAt,
		)
		if err != nil {
			continue
		}
		chats = append(chats, chat)
	}

	return map[string]interface{}{
		"success": true,
		"chats":   chats,
	}
}

func (s *Server) handleGetMessagesRequest(userID, chatID string) map[string]interface{} {
	// Проверка участия в чате
	var participantID string
	err := s.db.QueryRow(`
		SELECT user_id FROM chat_participants 
		WHERE chat_id = ? AND user_id = ?
	`, chatID, userID).Scan(&participantID)
	if err != nil {
		return map[string]interface{}{"error": "Chat not found or access denied"}
	}

	rows, err := s.db.Query(`
		SELECT id, chat_id, sender_id, content, type, timestamp, is_read, is_encrypted
		FROM messages 
		WHERE chat_id = ?
		ORDER BY timestamp ASC
		LIMIT 100
	`, chatID)
	if err != nil {
		return map[string]interface{}{"error": "Database error"}
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		err := rows.Scan(
			&msg.ID, &msg.ChatID, &msg.SenderID, &msg.Content,
			&msg.Type, &msg.Timestamp, &msg.IsRead, &msg.IsEncrypted,
		)
		if err != nil {
			continue
		}
		messages = append(messages, msg)
	}

	// Отмечаем сообщения как прочитанные
	_, err = s.db.Exec(`
		UPDATE messages SET is_read = TRUE 
		WHERE chat_id = ? AND sender_id != ? AND is_read = FALSE
	`, chatID, userID)

	return map[string]interface{}{
		"success":  true,
		"messages": messages,
	}
}

func (s *Server) handleSendMessageRequest(userID, chatID, content string) map[string]interface{} {
	// Проверка участия в чате
	var participantID string
	err := s.db.QueryRow(`
		SELECT user_id FROM chat_participants 
		WHERE chat_id = ? AND user_id = ?
	`, chatID, userID).Scan(&participantID)
	if err != nil {
		return map[string]interface{}{"error": "Chat not found or access denied"}
	}

	// Создание сообщения
	messageID := s.generateID()
	_, err = s.db.Exec(`
		INSERT INTO messages (id, chat_id, sender_id, content, type, timestamp, is_read, is_encrypted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, messageID, chatID, userID, content, "text", time.Now(), false, true)
	if err != nil {
		return map[string]interface{}{"error": "Failed to save message"}
	}

	// Обновление последнего сообщения в чате
	_, err = s.db.Exec(`
		UPDATE chats 
		SET last_message = ?, last_message_time = ?, unread_count = unread_count + 1
		WHERE id = ?
	`, content, time.Now(), chatID)

	return map[string]interface{}{
		"success":    true,
		"message_id": messageID,
	}
}

func (s *Server) handleGetContactsRequest(userID string) map[string]interface{} {
	rows, err := s.db.Query(`
		SELECT id, user_id, contact_username, display_name, status, is_online, last_seen
		FROM contacts 
		WHERE user_id = ?
		ORDER BY display_name, contact_username
	`, userID)
	if err != nil {
		return map[string]interface{}{"error": "Database error"}
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contact Contact
		err := rows.Scan(
			&contact.ID, &contact.UserID, &contact.Username,
			&contact.DisplayName, &contact.Status, &contact.IsOnline, &contact.LastSeen,
		)
		if err != nil {
			continue
		}
		contacts = append(contacts, contact)
	}

	return map[string]interface{}{
		"success":  true,
		"contacts": contacts,
	}
}

func (s *Server) handleAddContactRequest(userID, username string) map[string]interface{} {
	// Проверка существования пользователя
	var contactUserID string
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&contactUserID)
	if err != nil {
		return map[string]interface{}{"error": "User not found"}
	}

	if contactUserID == userID {
		return map[string]interface{}{"error": "Cannot add yourself as contact"}
	}

	// Проверка существования контакта
	var existingID string
	err = s.db.QueryRow(`
		SELECT id FROM contacts 
		WHERE user_id = ? AND contact_username = ?
	`, userID, username).Scan(&existingID)
	if err == nil {
		return map[string]interface{}{"error": "Contact already exists"}
	}

	// Добавление контакта
	contactID := s.generateID()
	_, err = s.db.Exec(`
		INSERT INTO contacts (id, user_id, contact_username, display_name, status)
		VALUES (?, ?, ?, ?, ?)
	`, contactID, userID, username, username, "offline")
	if err != nil {
		return map[string]interface{}{"error": "Failed to add contact"}
	}

	return map[string]interface{}{
		"success":    true,
		"contact_id": contactID,
	}
}

// WebSocket обработчики
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &WSClient{
		ID:       s.generateID(),
		Conn:     conn,
		Send:     make(chan []byte, 256),
		server:   s,
		lastSeen: time.Now(),
	}

	s.addClient(client)

	go client.readPump()
	go client.writePump()
}

func (s *Server) addClient(client *WSClient) {
	s.clientsMux.Lock()
	defer s.clientsMux.Unlock()
	s.clients[client.ID] = client
}

func (s *Server) removeClient(clientID string) {
	s.clientsMux.Lock()
	defer s.clientsMux.Unlock()
	if client, exists := s.clients[clientID]; exists {
		close(client.Send)
		delete(s.clients, clientID)
	}
}

func (s *Server) getClient(clientID string) (*WSClient, bool) {
	s.clientsMux.RLock()
	defer s.clientsMux.RUnlock()
	client, exists := s.clients[clientID]
	return client, exists
}

func (c *WSClient) readPump() {
	defer func() {
		c.server.removeClient(c.ID)
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(512)
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			}
			break
		}

		c.lastSeen = time.Now()

		// Обработка сообщения
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		// Эхо ответ
		response := map[string]interface{}{
			"type":    "echo",
			"message": msg,
			"time":    time.Now().Unix(),
		}

		responseData, _ := json.Marshal(response)
		select {
		case c.Send <- responseData:
		default:
			c.server.removeClient(c.ID)
			return
		}
	}
}

func (c *WSClient) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Утилиты
func (s *Server) generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (s *Server) generateJWTSecret() error {
	s.jwtSecret = make([]byte, JWT_SECRET_SIZE)
	_, err := rand.Read(s.jwtSecret)
	return err
}

func setupTLS() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

func main() {
	server := NewServer()

	// Генерация JWT секрета
	if err := server.generateJWTSecret(); err != nil {
		log.Fatal("Failed to generate JWT secret:", err)
	}

	// Подключение к базе данных
	db, err := sql.Open("sqlite3", "./j20s.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	server.db = db

	// Инициализация базы данных
	if err := server.initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Настройка роутера
	router := mux.NewRouter()

	// REST API endpoints
	router.HandleFunc("/api/register", server.handleRegister).Methods("POST")
	router.HandleFunc("/api/login", server.handleLogin).Methods("POST")
	router.HandleFunc("/api/verify-pin", server.handleVerifyPin).Methods("POST")

	// Протокольные endpoints
	router.HandleFunc("/api/handshake", server.handleHandshake).Methods("POST")
	router.HandleFunc("/api/secure", server.handleSecureMessage).Methods("POST")

	// WebSocket
	router.HandleFunc("/ws", server.handleWebSocket)

	// Настройка сервера
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		TLSConfig:    setupTLS(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	// Запуск сервера
	log.Println("Starting J20S server on :8080")
	if err := srv.ListenAndServeTLS("/etc/ssl/j20s/cert.pem", "/etc/ssl/j20s/key.pem"); err != nil && err != http.ErrServerClosed {
		log.Fatal("Server failed:", err)
	}
}
