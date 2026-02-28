package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultTTL = 30 * time.Minute

// Vault manages temporary PII token-to-original mappings in Redis
type Vault struct {
	client    *redis.Client
	ttl       time.Duration
	encryptor *Encryptor // nil = no encryption
}

// New creates a Vault connected to the given Redis instance
func New(addr, password string, db int) *Vault {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &Vault{
		client: client,
		ttl:    defaultTTL,
	}
}

// NewWithClient creates a Vault from an existing Redis client (useful for testing)
func NewWithClient(client *redis.Client) *Vault {
	return &Vault{
		client: client,
		ttl:    defaultTTL,
	}
}

// Ping checks Redis connectivity
func (v *Vault) Ping(ctx context.Context) error {
	return v.client.Ping(ctx).Err()
}

// sessionKey builds the Redis hash key for a session
func sessionKey(sessionID string) string {
	return fmt.Sprintf("pii:session:%s", sessionID)
}

// Store saves a batch of token->original mappings for a session
func (v *Vault) Store(ctx context.Context, sessionID string, mappings map[string]string) error {
	if len(mappings) == 0 {
		return nil
	}

	key := sessionKey(sessionID)
	pipe := v.client.Pipeline()

	for token, original := range mappings {
		val, err := v.encrypt(original)
		if err != nil {
			return fmt.Errorf("encrypt PII: %w", err)
		}
		pipe.HSet(ctx, key, token, val)
	}
	pipe.Expire(ctx, key, v.ttl)

	_, err := pipe.Exec(ctx)
	return err
}

// Lookup retrieves the original value for a single token in a session
func (v *Vault) Lookup(ctx context.Context, sessionID, token string) (string, error) {
	val, err := v.client.HGet(ctx, sessionKey(sessionID), token).Result()
	if err != nil {
		return "", err
	}
	return v.decrypt(val)
}

// LookupAll retrieves all token->original mappings for a session
func (v *Vault) LookupAll(ctx context.Context, sessionID string) (map[string]string, error) {
	raw, err := v.client.HGetAll(ctx, sessionKey(sessionID)).Result()
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(raw))
	for token, encrypted := range raw {
		val, err := v.decrypt(encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt token %s: %w", token, err)
		}
		result[token] = val
	}
	return result, nil
}

// Delete removes all mappings for a session
func (v *Vault) Delete(ctx context.Context, sessionID string) error {
	return v.client.Del(ctx, sessionKey(sessionID)).Err()
}

// SetTTL configures the TTL for session mappings
func (v *Vault) SetTTL(ttl time.Duration) {
	v.ttl = ttl
}

// SetEncryptor enables AES-256-GCM encryption for stored PII values
func (v *Vault) SetEncryptor(enc *Encryptor) {
	v.encryptor = enc
}

func (v *Vault) encrypt(plaintext string) (string, error) {
	if v.encryptor == nil {
		return plaintext, nil
	}
	return v.encryptor.Encrypt(plaintext)
}

func (v *Vault) decrypt(ciphertext string) (string, error) {
	if v.encryptor == nil {
		return ciphertext, nil
	}
	return v.encryptor.Decrypt(ciphertext)
}

// Close shuts down the Redis client
func (v *Vault) Close() error {
	return v.client.Close()
}
