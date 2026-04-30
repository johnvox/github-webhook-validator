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
func (app *App) ValidateSignature(body []byte, signatureHeader string) bool {
	if signatureHeader == "" || len(signatureHeader) < 7 {
		app.logger.Error("Invalid signature header")
		return false
	}
	app.logger.Debug("Validating signature...")

	computedHash := hmac.New(sha256.New, []byte(app.config.Secret))
	computedHash.Write(body)
	expectedSig := hex.EncodeToString(computedHash.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(signatureHeader[7:]))
}

// WebhookHandler handles GitHub webhook requests
func (app *App) WebhookHandler(w http.ResponseWriter, r *http.Request) {
	app.logger.Debug("Received webhook request")

	if r.Method != http.MethodPost {
		app.logger.Error("not-allowed", "method", r.Method)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		app.logger.Error("reading", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	signatureHeader := r.Header.Get("X-Hub-Signature-256")
	if app.ValidateSignature(body, signatureHeader) {
		app.logger.Info("Payload Validated")
		w.Write([]byte("Payload Validated\n"))
	} else {
		app.logger.Warn("Unauthorized - Signature Mismatch")
		http.Error(w, "Unauthorized - Signature Mismatch", http.StatusUnauthorized)
	}
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
		mux.HandleFunc("/webhook", application.WebhookHandler)
		mux.HandleFunc("/healthz", healthHandler)

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
