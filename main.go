package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

// Config holds configuration values
type Config struct {
	Secret    string
	Address   string
	LogLevel  string
	LogFormat string
}

// App encapsulates the application logic and dependencies
type App struct {
	config Config
	logger *slog.Logger
}

var application = App{}

// NewApp creates a new App instance
func NewApp(config Config) *App {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	return &App{config: config, logger: logger}
}

// ValidateSignature validates the GitHub webhook signature
func (app *App) ComputeSignature(body []byte) string {
	computedHash := hmac.New(sha256.New, []byte(app.config.Secret))
	computedHash.Write(body)
	return "sha256=" + hex.EncodeToString(computedHash.Sum(nil))
}

// WebhookHandler handles GitHub webhook requests
func (app *App) WebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		app.logger.Error("not-allowed", "method", r.Method, "path", r.URL.Path)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		app.logger.Error("reading", "error", err, "method", r.Method, "path", r.URL.Path)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	signatureHeader := r.Header.Get("X-Hub-Signature-256")
	app.logger.Info("request", "method", r.Method, "path", r.URL.Path, "signature", signatureHeader)
	if signatureHeader == "" || len(signatureHeader) < 7 {
		app.logger.Warn("signature-header-invalid", "signature", signatureHeader)
		http.Error(w, "Unauthorized - Invalid Signature Header", http.StatusUnauthorized)
	}
	computeSignature := app.ComputeSignature(body)
	if !hmac.Equal([]byte(computeSignature), []byte(signatureHeader)) {
		app.logger.Warn("signature-mismatch", "compute", computeSignature, "expected", signatureHeader)
		http.Error(w, "Unauthorized - Signature Mismatch", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("OK\n"))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

var rootCmd = &cobra.Command{
	Use: "oidc-redirect",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var lvl slog.Level
		if err := lvl.UnmarshalText([]byte(application.config.LogLevel)); err != nil {
			return err
		}
		switch application.config.LogFormat {
		case "fmt":
			application.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
		case "json":
			application.logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
		default:
			return errors.New("log-format invalid")
		}
		if application.config.Secret == "" {
			application.config.Secret = os.Getenv("WEBHOOK_SECRET")
		}
		if application.config.Secret == "" {
			return errors.New("missing webhook secret")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		mux := http.NewServeMux()
		mux.HandleFunc("/", application.WebhookHandler)
		mux.HandleFunc("GET /healthz", healthHandler)

		application.logger.Info("listening", "addr", application.config.Address)
		if err := http.ListenAndServe(application.config.Address, mux); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	flags := rootCmd.Flags()
	flags.StringVar(&application.config.Address, "address", ":8080", "Address for listening")
	flags.StringVar(&application.config.LogLevel, "log-level", "INFO", "loglevel")
	flags.StringVar(&application.config.LogFormat, "log-format", "json", "logformat (fmt, json)")
	flags.StringVar(&application.config.Secret, "secret", "", "webhook secret (env: WEBHOOK_SECRET)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error("startup", "error", err)
	}
}
