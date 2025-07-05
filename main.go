package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/blake2b"
)

type Server struct {
	clients   map[string]*Client
	messages  map[string]*EncryptedMessage
	mu        sync.RWMutex
	gcm       cipher.AEAD
	serverKey []byte
	upgrader  websocket.Upgrader
}

type Client struct {
	ID       string
	Conn     *websocket.Conn
	LastSeen time.Time
}

type EncryptedMessage struct {
	ID        string
	Data      []byte
	Nonce     []byte
	AuthTag   []byte
	Timestamp time.Time
	TTL       time.Duration
}

type Packet struct {
	Type      string `json:"type"`
	From      string `json:"from"`
	To        string `json:"to"`
	Data      []byte `json:"data"`
	Timestamp int64  `json:"timestamp"`
}

func NewServer() *Server {
	serverKey := make([]byte, 38)
	if _, err := rand.Read(serverKey); err != nil {
		log.Fatal("Failed to generate server key:", err)
	}

	aesKey := blake2b.Sum256(serverKey)
	block, err := aes.NewCipher(aesKey[:32])
	if err != nil {
		log.Fatal("Failed to create AES cipher:", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("Failed to create GCM:", err)
	}

	return &Server{
		clients:   make(map[string]*Client),
		messages:  make(map[string]*EncryptedMessage),
		serverKey: serverKey,
		gcm:       gcm,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
}

func (s *Server) encryptMessage(data []byte) (*EncryptedMessage, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := s.gcm.Seal(nil, nonce, data, nil)

	msgID := make([]byte, 16)
	rand.Read(msgID)

	return &EncryptedMessage{
		ID:        fmt.Sprintf("%x", msgID),
		Data:      ciphertext,
		Nonce:     nonce,
		Timestamp: time.Now(),
		TTL:       24 * time.Hour,
	}, nil
}

func (s *Server) decryptMessage(msg *EncryptedMessage) ([]byte, error) {
	return s.gcm.Open(nil, msg.Nonce, msg.Data, nil)
}

func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR: Missing client ID"))
		return
	}

	client := &Client{
		ID:       clientID,
		Conn:     conn,
		LastSeen: time.Now(),
	}

	s.mu.Lock()
	s.clients[clientID] = client
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, clientID)
		s.mu.Unlock()
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var packet Packet
		if err := json.Unmarshal(message, &packet); err != nil {
			continue
		}

		switch packet.Type {
		case "message":
			s.handleMessage(&packet)
		case "get_messages":
			s.handleGetMessages(client, &packet)
		case "key_exchange":
			s.handleKeyExchange(&packet)
		}

		client.LastSeen = time.Now()
	}
}

func (s *Server) handleMessage(packet *Packet) {
	encMsg, err := s.encryptMessage(packet.Data)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		return
	}

	s.mu.Lock()
	s.messages[encMsg.ID] = encMsg
	s.mu.Unlock()

	s.mu.RLock()
	targetClient, exists := s.clients[packet.To]
	s.mu.RUnlock()

	if exists {
		response := map[string]interface{}{
			"type":   "new_message",
			"from":   packet.From,
			"msg_id": encMsg.ID,
			"data":   packet.Data,
		}
		responseJSON, _ := json.Marshal(response)
		targetClient.Conn.WriteMessage(websocket.TextMessage, responseJSON)
	}
}

func (s *Server) handleGetMessages(client *Client, packet *Packet) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var messages []map[string]interface{}
	for _, msg := range s.messages {
		if time.Since(msg.Timestamp) < msg.TTL {
			data, err := s.decryptMessage(msg)
			if err != nil {
				continue
			}

			messages = append(messages, map[string]interface{}{
				"id":        msg.ID,
				"data":      data,
				"timestamp": msg.Timestamp.Unix(),
			})
		}
	}

	response := map[string]interface{}{
		"type":     "messages",
		"messages": messages,
	}
	responseJSON, _ := json.Marshal(response)
	client.Conn.WriteMessage(websocket.TextMessage, responseJSON)
}

func (s *Server) handleKeyExchange(packet *Packet) {
	s.mu.RLock()
	targetClient, exists := s.clients[packet.To]
	s.mu.RUnlock()

	if exists {
		response := map[string]interface{}{
			"type": "key_exchange",
			"from": packet.From,
			"data": packet.Data,
		}
		responseJSON, _ := json.Marshal(response)
		targetClient.Conn.WriteMessage(websocket.TextMessage, responseJSON)
	}
}

func (s *Server) cleanupExpiredMessages() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		for id, msg := range s.messages {
			if time.Since(msg.Timestamp) > msg.TTL {
				for i := range msg.Data {
					msg.Data[i] = 0
				}
				for i := range msg.Nonce {
					msg.Nonce[i] = 0
				}
				delete(s.messages, id)
			}
		}
		s.mu.Unlock()
	}
}

func main() {
	server := NewServer()

	go server.cleanupExpiredMessages()

	http.HandleFunc("/ws", server.handleConnection)

	fmt.Println("Secure server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
