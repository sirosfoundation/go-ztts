package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirosfoundation/go-ztts/pkg/auth"
	"github.com/sirosfoundation/go-ztts/pkg/authz"
	"github.com/sirosfoundation/go-ztts/pkg/config"
	"github.com/sirosfoundation/go-ztts/pkg/handler"
	"github.com/sirosfoundation/go-ztts/pkg/replay"
	"github.com/sirosfoundation/go-ztts/pkg/revocation"
	"github.com/sirosfoundation/go-ztts/pkg/service"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	profilesPath := flag.String("profiles", "", "path to separate profiles YAML file (overrides config profiles)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Optionally load profiles from a separate YAML file
	if *profilesPath != "" {
		profiles, err := config.LoadProfiles(*profilesPath)
		if err != nil {
			log.Fatalf("failed to load profiles: %v", err)
		}
		cfg.Profiles = profiles
	}

	// Load CA bundle for client certificate verification
	clientCAs, err := auth.LoadCABundle(cfg.Auth.CABundle)
	if err != nil {
		log.Fatalf("failed to load CA bundle: %v", err)
	}

	// Optionally set up CRL checking
	var crlChecker auth.CRLChecker
	if cfg.Auth.CRLURL != "" || cfg.Auth.CRLPath != "" {
		cacheTTL := cfg.Auth.CRLCacheDuration
		if cacheTTL == 0 {
			cacheTTL = 5 * time.Minute
		}
		crlChecker, err = auth.NewCRLChecker(cfg.Auth.CRLURL, cfg.Auth.CRLPath, cacheTTL)
		if err != nil {
			log.Fatalf("failed to create CRL checker: %v", err)
		}
		slog.Info("CRL checking enabled", "url", cfg.Auth.CRLURL, "path", cfg.Auth.CRLPath)
	}

	authorizer, err := authz.NewAuthorizer(cfg.Profiles)
	if err != nil {
		log.Fatalf("failed to create authorizer: %v", err)
	}

	revStore, err := revocation.NewStore(cfg.Revocation.StorePath)
	if err != nil {
		log.Fatalf("failed to create revocation store: %v", err)
	}

	replayGuard := replay.NewGuard()

	stop := make(chan struct{})
	cleanupInterval := cfg.Revocation.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = 5 * time.Minute
	}
	go revStore.StartCleanup(cleanupInterval, stop)
	go replayGuard.StartCleanup(time.Minute, stop)

	issuer := cfg.Server.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("https://%s", cfg.Server.ListenAddr)
	}

	svc, err := service.NewTokenService(issuer, authorizer, cfg.Profiles, revStore, replayGuard)
	if err != nil {
		log.Fatalf("failed to create token service: %v", err)
	}

	h := handler.NewHandler(svc)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.HealthHandler)
	mux.Handle("/token", auth.Middleware(crlChecker)(http.HandlerFunc(h.TokenHandler)))
	mux.Handle("/revoke", auth.Middleware(crlChecker)(http.HandlerFunc(h.RevokeHandler)))

	srv := &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientCAs:  clientCAs,
			ClientAuth: tls.RequireAndVerifyClientCert,
			MinVersion: tls.VersionTLS12,
		},
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down...")
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("server shutdown error", "err", err)
		}
	}()

	slog.Info("ztts starting", "addr", cfg.Server.ListenAddr, "issuer", issuer)
	if err := srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
