package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Константы протокола
const (
	PROTOCOL_SESSION_TIMEOUT = 10 * time.Minute // Пересоздание сессии каждые 10 минут
	MAX_MESSAGE_SIZE         = 64 * 1024        // Максимальный размер сообщения 64KB
	NONCE_SIZE               = 12               // Размер nonce для ChaCha20-Poly1305
	KEY_SIZE                 = 32               // Размер ключа
	PUBLIC_KEY_SIZE          = 32               // Размер публичного ключа X25519
	PRIVATE_KEY_SIZE         = 32               // Размер приватного ключа X25519
	SIGNATURE_SIZE           = 64               // Размер подписи Ed25519
	SESSION_ID_SIZE          = 32               // Размер ID сессии
	MAX_REPLAY_WINDOW        = 1000             // Максимальное количество nonce в окне
)

// Структуры протокола
type Session struct {
	ID           string
	UserID       string
	DeviceID     string
	SharedKey    []byte
	CreatedAt    time.Time
	LastActivity time.Time
	NonceCounter uint64
	ReplayWindow map[uint64]bool
}

type HandshakeRequest struct {
	DeviceID     string `json:"device_id"`
	EphemeralKey string `json:"ephemeral_key"` // base64 encoded X25519 public key
	Username     string `json:"username"`
	Password     string `json:"password"`
	Timestamp    int64  `json:"timestamp"`
}

type HandshakeResponse struct {
	Success      bool   `json:"success"`
	SessionID    string `json:"session_id"`
	EphemeralKey string `json:"ephemeral_key"` // base64 encoded X25519 public key
	Message      string `json:"message,omitempty"`
}

type SecureMessage struct {
	SessionID string `json:"session_id"`
	Nonce     string `json:"nonce"`   // base64 encoded nonce
	Payload   string `json:"payload"` // base64 encoded encrypted data
	MAC       string `json:"mac"`     // base64 encoded MAC
	Timestamp int64  `json:"timestamp"`
}

type MessagePayload struct {
	Type    string      `json:"type"`
	Data    interface{} `json:"data"`
	Counter uint64      `json:"counter"`
}

// Криптографические операции
func generateKeyPair() (publicKey, privateKey []byte, err error) {
	privateKey = make([]byte, PRIVATE_KEY_SIZE)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

func computeSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, publicKey)
}

func deriveSessionKey(sharedSecret []byte, sessionID string) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret, []byte("J20S-Session-Key"), []byte(sessionID))
	sessionKey := make([]byte, KEY_SIZE)
	_, err := hkdf.Read(sessionKey)
	return sessionKey, err
}

func generateNonce() ([]byte, error) {
	nonce := make([]byte, NONCE_SIZE)
	_, err := rand.Read(nonce)
	return nonce, err
}

func generateSessionID() (string, error) {
	id := make([]byte, SESSION_ID_SIZE)
	_, err := rand.Read(id)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(id), nil
}

// Шифрование/дешифрование
func encryptMessage(key []byte, nonce []byte, payload []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, payload, nil)
	return ciphertext, nil
}

func decryptMessage(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Подписи
func signData(privateKey []byte, data []byte) ([]byte, error) {
	signature := ed25519.Sign(privateKey, data)
	return signature, nil
}

func verifySignature(publicKey []byte, data []byte, signature []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}

// Валидация
func validateHandshakeRequest(req *HandshakeRequest) error {
	if req.DeviceID == "" {
		return fmt.Errorf("device_id is required")
	}
	if req.EphemeralKey == "" {
		return fmt.Errorf("ephemeral_key is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	// Проверка timestamp (не старше 5 минут)
	now := time.Now().Unix()
	if abs(now-req.Timestamp) > 300 {
		return fmt.Errorf("timestamp too old or too new")
	}

	// Проверка размера ephemeral key
	key, err := base64.StdEncoding.DecodeString(req.EphemeralKey)
	if err != nil {
		return fmt.Errorf("invalid ephemeral_key format")
	}
	if len(key) != PUBLIC_KEY_SIZE {
		return fmt.Errorf("invalid ephemeral_key size")
	}

	return nil
}

func validateSecureMessage(msg *SecureMessage) error {
	if msg.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if msg.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	if msg.Payload == "" {
		return fmt.Errorf("payload is required")
	}
	if msg.MAC == "" {
		return fmt.Errorf("mac is required")
	}

	// Проверка timestamp (не старше 1 минуты)
	now := time.Now().Unix()
	if abs(now-msg.Timestamp) > 60 {
		return fmt.Errorf("message timestamp too old or too new")
	}

	return nil
}

// Утилиты
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Сессионные операции
func (s *Server) createSession(userID, deviceID string, sharedKey []byte) (*Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:           sessionID,
		UserID:       userID,
		DeviceID:     deviceID,
		SharedKey:    sharedKey,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		NonceCounter: 0,
		ReplayWindow: make(map[uint64]bool),
	}

	// Сохранение сессии в базе данных
	_, err = s.db.Exec(`
		INSERT INTO protocol_sessions (id, user_id, device_id, shared_key, created_at, last_activity, nonce_counter)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, session.ID, session.UserID, session.DeviceID, encodeBase64(session.SharedKey),
		session.CreatedAt, session.LastActivity, session.NonceCounter)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *Server) getSession(sessionID string) (*Session, error) {
	var session Session
	var sharedKeyStr string

	err := s.db.QueryRow(`
		SELECT id, user_id, device_id, shared_key, created_at, last_activity, nonce_counter
		FROM protocol_sessions WHERE id = ?
	`, sessionID).Scan(
		&session.ID, &session.UserID, &session.DeviceID, &sharedKeyStr,
		&session.CreatedAt, &session.LastActivity, &session.NonceCounter,
	)
	if err != nil {
		return nil, err
	}

	session.SharedKey, err = decodeBase64(sharedKeyStr)
	if err != nil {
		return nil, err
	}

	session.ReplayWindow = make(map[uint64]bool)
	return &session, nil
}

func (s *Server) updateSessionActivity(sessionID string) error {
	_, err := s.db.Exec(`
		UPDATE protocol_sessions SET last_activity = ? WHERE id = ?
	`, time.Now(), sessionID)
	return err
}

func (s *Server) cleanupExpiredSessions() error {
	_, err := s.db.Exec(`
		DELETE FROM protocol_sessions WHERE last_activity < ?
	`, time.Now().Add(-PROTOCOL_SESSION_TIMEOUT))
	return err
}

// Проверка replay атак
func (session *Session) checkReplayAttack(nonce []byte) bool {
	if len(nonce) < 8 {
		return false
	}

	counter := binary.BigEndian.Uint64(nonce[:8])

	// Проверка в окне replay
	if session.ReplayWindow[counter] {
		return false
	}

	// Добавление в окно
	session.ReplayWindow[counter] = true

	// Очистка старых записей если окно переполнено
	if len(session.ReplayWindow) > MAX_REPLAY_WINDOW {
		// Простая очистка - удаляем все кроме последних 100
		newWindow := make(map[uint64]bool)
		count := 0
		for k := range session.ReplayWindow {
			if count < MAX_REPLAY_WINDOW/2 {
				newWindow[k] = true
				count++
			}
		}
		session.ReplayWindow = newWindow
	}

	return true
}
