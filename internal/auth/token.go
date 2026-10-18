package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Claims struct {
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"exp"`
}

type Manager struct {
	secret   []byte
	username string
	password string
}

func New(secret, username, password string) *Manager {
	return &Manager{secret: []byte(secret), username: username, password: password}
}

func (m *Manager) Authenticate(username, password string) (string, error) {
	if subtle.ConstantTimeCompare([]byte(username), []byte(m.username)) != 1 || subtle.ConstantTimeCompare([]byte(password), []byte(m.password)) != 1 {
		return "", errors.New("用户名或密码错误")
	}
	return m.Issue(Claims{Subject: username, Role: "analyst", ExpiresAt: time.Now().Add(8 * time.Hour).Unix()})
}

func (m *Manager) Issue(claims Claims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	sig := hmac.New(sha256.New, m.secret)
	_, _ = sig.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(sig.Sum(nil)), nil
}

func (m *Manager) Verify(token string) (Claims, error) {
	var claims Claims
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return claims, errors.New("invalid token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, errors.New("invalid signature")
	}
	expected := hmac.New(sha256.New, m.secret)
	_, _ = expected.Write([]byte(parts[0]))
	if !hmac.Equal(signature, expected.Sum(nil)) {
		return claims, errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return claims, errors.New("invalid claims")
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return claims, errors.New("token expired")
	}
	return claims, nil
}
