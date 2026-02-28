package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vurakit/agentveil/internal/auth"
	"github.com/vurakit/agentveil/internal/detector"
	"github.com/vurakit/agentveil/internal/logging"
	"github.com/vurakit/agentveil/internal/proxy"
	"github.com/vurakit/agentveil/internal/ratelimit"
	"github.com/vurakit/agentveil/internal/router"
	"github.com/vurakit/agentveil/internal/vault"
	"github.com/vurakit/agentveil/internal/webhook"
)

func main() {
	// Structured logging
	logLevel := envOr("LOG_LEVEL", "info")
	logger := logging.Setup(logLevel, os.Stdout)
	logger.Info("starting Agent Veil")

	// Configuration
	targetURL := envOr("TARGET_URL", "https://api.openai.com")
	listenAddr := envOr("LISTEN_ADDR", ":8080")
	redisAddr := envOr("REDIS_ADDR", "localhost:6379")
	redisPassword := envOr("REDIS_PASSWORD", "")
	encryptionKey := envOr("VEIL_ENCRYPTION_KEY", "") // 64 hex chars = 32 bytes
	tlsCert := envOr("TLS_CERT", "")
	tlsKey := envOr("TLS_KEY", "")

	// Redis client (shared between vault and auth)
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Warn("Redis not available, running without persistence", "error", err)
	} else {
		logger.Info("Redis connected", "addr", redisAddr)
	}

	// Vault
	v := vault.NewWithClient(redisClient)
	if encryptionKey != "" {
		keyBytes, err := hex.DecodeString(encryptionKey)
		if err != nil || len(keyBytes) != 32 {
			logger.Error("VEIL_ENCRYPTION_KEY must be 64 hex chars (32 bytes)", "len", len(encryptionKey))
			os.Exit(1)
		}
		enc, err := vault.NewEncryptor(keyBytes)
		if err != nil {
			logger.Error("failed to create encryptor", "error", err)
			os.Exit(1)
		}
		v.SetEncryptor(enc)
		logger.Info("vault encryption enabled (AES-256-GCM)")
	}

	// Detector
	det := detector.New()

	// Auth manager
	authMgr := auth.NewManager(redisClient)

	// Rate limiter
	rl := ratelimit.New(ratelimit.DefaultConfig())
	defer rl.Close()

	// Webhook dispatcher
	var dispatcher *webhook.Dispatcher
	discordURL := envOr("VEIL_DISCORD_WEBHOOK_URL", "")
	slackURL := envOr("VEIL_SLACK_WEBHOOK_URL", "")
	if discordURL != "" || slackURL != "" {
		whCfg := webhook.DefaultConfig()
		if discordURL != "" {
			whCfg.Discord = &webhook.DiscordConfig{WebhookURL: discordURL}
			logger.Info("discord webhook enabled")
		}
		if slackURL != "" {
			whCfg.Slack = &webhook.SlackConfig{WebhookURL: slackURL}
			logger.Info("slack webhook enabled")
		}
		dispatcher = webhook.NewDispatcher(whCfg)
		defer dispatcher.Close()
	}

	// Build handler: router mode or single-target mode
	routerConfig := envOr("VEIL_ROUTER_CONFIG", "")

	var handler http.Handler

	if routerConfig != "" {
		// Multi-provider router mode
		cfg, err := router.LoadConfig(routerConfig)
		if err != nil {
			logger.Error("failed to load router config", "path", routerConfig, "error", err)
			os.Exit(1)
		}

		rt, err := router.New(cfg)
		if err != nil {
			logger.Error("failed to create router", "error", err)
			os.Exit(1)
		}

		// Wire PII anonymization into the router's request modifier
		rt.SetRequestModifier(proxy.AnonymizeRequest(det, v, dispatcher))

		// Build mux with utility endpoints + router as catch-all
		mux := http.NewServeMux()
		healthHandler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok"}`))
		}
		mux.HandleFunc("/health", healthHandler)
		mux.HandleFunc("/healthz", healthHandler)

		var routerHandler http.Handler = rt
		if authMgr != nil {
			routerHandler = authMgr.Middleware(routerHandler)
		}
		mux.Handle("/", routerHandler)

		handler = rl.Middleware(mux)

		logger.Info("router mode enabled", "config", routerConfig, "providers", rt.GetProviders())
	} else {
		// Single-target proxy mode (original behavior)
		opts := []proxy.Option{proxy.WithAuth(authMgr)}
		if dispatcher != nil {
			opts = append(opts, proxy.WithWebhook(dispatcher))
		}
		srv, err := proxy.New(
			proxy.Config{TargetURL: targetURL},
			det, v,
			opts...,
		)
		if err != nil {
			logger.Error("failed to create proxy", "error", err)
			os.Exit(1)
		}

		handler = rl.Middleware(srv.Handler())
	}

	// HTTP server
	httpServer := &http.Server{
		Addr:         listenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		if routerConfig != "" {
			logger.Info("proxy listening (router mode)", "addr", listenAddr)
		} else {
			logger.Info("proxy listening", "addr", listenAddr, "target", targetURL)
		}
		if tlsCert != "" && tlsKey != "" {
			logger.Info("TLS enabled", "cert", tlsCert)
			if err := httpServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				os.Exit(1)
			}
		} else {
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
				os.Exit(1)
			}
		}
	}()

	<-done
	logger.Info("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}
	if err := redisClient.Close(); err != nil {
		logger.Error("redis close error", "error", err)
	}

	logger.Info("stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
