package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vurakit/agentveil/internal/auth"
	"github.com/vurakit/agentveil/internal/detector"
	"github.com/vurakit/agentveil/internal/logging"
	"github.com/vurakit/agentveil/internal/promptguard"
	"github.com/vurakit/agentveil/internal/proxy"
	"github.com/vurakit/agentveil/internal/ratelimit"
	"github.com/vurakit/agentveil/internal/vault"
)

func handleProxy(args []string) {
	if len(args) == 0 || args[0] != "start" {
		fmt.Println("Usage: agentveil proxy start")
		return
	}

	logger := logging.Setup(envOr("LOG_LEVEL", "info"), os.Stdout)
	logger.Info("starting Agent Veil proxy", "version", version)

	targetURL := envOr("TARGET_URL", "https://api.openai.com")
	listenAddr := envOr("LISTEN_ADDR", ":8080")
	redisAddr := envOr("REDIS_ADDR", "localhost:6379")
	redisPassword := envOr("REDIS_PASSWORD", "")
	encryptionKey := envOr("VEIL_ENCRYPTION_KEY", "")

	// Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Warn("Redis not available", "error", err)
	} else {
		logger.Info("Redis connected", "addr", redisAddr)
	}

	// Vault
	v := vault.NewWithClient(redisClient)
	if encryptionKey != "" {
		keyBytes, err := hex.DecodeString(encryptionKey)
		if err != nil || len(keyBytes) != 32 {
			logger.Error("VEIL_ENCRYPTION_KEY must be 64 hex chars")
			os.Exit(1)
		}
		enc, err := vault.NewEncryptor(keyBytes)
		if err != nil {
			logger.Error("encryptor error", "error", err)
			os.Exit(1)
		}
		v.SetEncryptor(enc)
		logger.Info("vault encryption enabled")
	}

	// Components
	det := detector.New()
	authMgr := auth.NewManager(redisClient)
	rl := ratelimit.New(ratelimit.DefaultConfig())
	defer rl.Close()
	pg := promptguard.New()

	srv, err := proxy.New(
		proxy.Config{TargetURL: targetURL},
		det, v,
		proxy.WithAuth(authMgr),
		proxy.WithPromptGuard(pg),
	)
	if err != nil {
		logger.Error("proxy create error", "error", err)
		os.Exit(1)
	}

	handler := rl.Middleware(srv.Handler())

	httpServer := &http.Server{
		Addr:         listenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("proxy listening", "addr", listenAddr, "target", targetURL)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-done
	logger.Info("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	httpServer.Shutdown(shutdownCtx)
	redisClient.Close()
	logger.Info("stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
