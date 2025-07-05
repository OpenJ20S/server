package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type Client struct {
	ID       string
	Conn     *websocket.Conn
	Send     chan []byte
	server   *Server
	lastSeen time.Time
}

type Message struct {
	Type      string    `json:"type"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

type Server struct {
	clients    map[string]*Client
	clientsMux sync.RWMutex
	upgrader   websocket.Upgrader
}

func NewServer() *Server {
	return &Server{
		clients: make(map[string]*Client),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
}

func (s *Server) addClient(client *Client) {
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

func (s *Server) getClient(clientID string) (*Client, bool) {
	s.clientsMux.RLock()
	defer s.clientsMux.RUnlock()
	client, exists := s.clients[clientID]
	return client, exists
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		log.Printf("Missing client ID")
		return
	}

	client := &Client{
		ID:       clientID,
		Conn:     conn,
		Send:     make(chan []byte, 256),
		server:   s,
		lastSeen: time.Now(),
	}

	s.addClient(client)
	defer s.removeClient(clientID)

	go client.writePump()
	client.readPump()
}

func (c *Client) readPump() {
	defer c.Conn.Close()

	c.Conn.SetReadLimit(1024)
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, messageBytes, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		c.lastSeen = time.Now()

		var msg Message
		if err := json.Unmarshal(messageBytes, &msg); err != nil {
			log.Printf("Invalid message format: %v", err)
			continue
		}

		msg.From = c.ID
		msg.Timestamp = time.Now()

		if msg.Type == "message" && msg.To != "" {
			if targetClient, exists := c.server.getClient(msg.To); exists {
				messageBytes, _ := json.Marshal(msg)
				select {
				case targetClient.Send <- messageBytes:
				default:
					close(targetClient.Send)
					c.server.removeClient(msg.To)
				}
			}
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer ticker.Stop()
	defer c.Conn.Close()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("Write error: %v", err)
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

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	s.clientsMux.RLock()
	clientCount := len(s.clients)
	s.clientsMux.RUnlock()

	status := map[string]interface{}{
		"status":  "running",
		"clients": clientCount,
	}

	json.NewEncoder(w).Encode(status)
}

func setupTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

func main() {
	certFile := "/etc/ssl/j20s/cert.pem"
	keyFile := "/etc/ssl/j20s/key.pem"

	if len(os.Args) > 2 {
		certFile = os.Args[1]
		keyFile = os.Args[2]
	}

	server := NewServer()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", server.handleWebSocket)
	mux.HandleFunc("/api/status", server.handleStatus)

	httpServer := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		TLSConfig:    setupTLS(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("J20S Server starting on :8443")
	log.Printf("TLS cert: %s", certFile)
	log.Printf("TLS key: %s", keyFile)

	go func() {
		if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Printf("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Printf("Server stopped")
}
