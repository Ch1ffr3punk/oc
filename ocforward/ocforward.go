package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

// UserConfig for configuration file
type UserConfig struct {
	OnionAddress string `yaml:"onion_address"`
}

// ForwardConfig contains all user configurations
type ForwardConfig struct {
	Users map[string]UserConfig `yaml:"users"`
	
	// Retry configuration
	MaxRetries      int `yaml:"max_retries"`       // Maximum retry attempts
	InitialDelay    int `yaml:"initial_delay"`     // Initial delay in seconds
	MaxDelay        int `yaml:"max_delay"`         // Maximum delay in seconds
	BackoffFactor   float64 `yaml:"backoff_factor"` // Exponential backoff factor
	Jitter          bool   `yaml:"jitter"`         // Add random jitter
}

var (
	startTime time.Time
	config    *ForwardConfig
)

func main() {
	// 1. Get username (called from .forward file)
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting user: %v\n", err)
		os.Exit(1)
	}

	username := currentUser.Username
	
	// 2. Load configuration
	userConfig, forwardConfig, err := loadConfig(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Make sure user '%s' exists in config file\n", username)
		os.Exit(1)
	}
	
	config = forwardConfig
	if config.MaxRetries == 0 {
		config.MaxRetries = 3 // Default
	}
	if config.InitialDelay == 0 {
		config.InitialDelay = 1 // Default 1 second
	}
	if config.MaxDelay == 0 {
		config.MaxDelay = 30 // Default 30 seconds
	}
	if config.BackoffFactor == 0 {
		config.BackoffFactor = 2.0 // Default exponential backoff
	}

	// 3. Read email from stdin
	fmt.Fprint(os.Stderr, "Reading email from stdin...\n")
	emailData, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading email: %v\n", err)
		os.Exit(1)
	}

	if len(emailData) == 0 {
		fmt.Fprint(os.Stderr, "No data received\n")
		os.Exit(1)
	}

	// 4. Build server URL (always port 8088)
	serverURL := fmt.Sprintf("http://%s:8088/upload", userConfig.OnionAddress)
	fmt.Fprintf(os.Stderr, "Sending to: %s\n", serverURL)
	
	// 5. Send via Tor with retry mechanism
	err = uploadEmailWithRetry(serverURL, emailData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error after %d attempts: %v\n", config.MaxRetries, err)
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "Email forwarded successfully\n")
}

func loadConfig(username string) (*UserConfig, *ForwardConfig, error) {
	// Look for config files in standard locations
	configPaths := []string{
		"/etc/ocforward/ocforward.yaml",
		"/usr/local/etc/ocforward/ocforward.yaml",
		filepath.Join(os.Getenv("HOME"), ".ocforward.yaml"),
	}

	var configData []byte
	var err error

	for _, path := range configPaths {
		configData, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("Config file not found: %v", err)
	}

	var forwardConfig ForwardConfig
	if err := yaml.Unmarshal(configData, &forwardConfig); err != nil {
		return nil, nil, fmt.Errorf("Error parsing config: %v", err)
	}

	// Get user configuration
	userConfig, exists := forwardConfig.Users[username]
	if !exists {
		return nil, nil, fmt.Errorf("No configuration for user '%s' found", username)
	}

	// Clean onion address
	userConfig.OnionAddress = strings.TrimPrefix(userConfig.OnionAddress, "http://")
	userConfig.OnionAddress = strings.TrimPrefix(userConfig.OnionAddress, "https://")

	return &userConfig, &forwardConfig, nil
}

func uploadEmailWithRetry(serverURL string, emailData []byte) error {
	var lastError error
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Calculate delay with exponential backoff
			delay := calculateBackoff(attempt)
			fmt.Fprintf(os.Stderr, "Retry attempt %d/%d in %.1f seconds...\n", 
				attempt, config.MaxRetries, delay.Seconds())
			
			time.Sleep(delay)
		}
		
		fmt.Fprint(os.Stderr, "Attempting connection...\n")
		err := uploadEmail(serverURL, emailData, attempt)
		
		if err == nil {
			// Success!
			if attempt > 0 {
				fmt.Fprintf(os.Stderr, "Success on retry %d!\n", attempt)
			}
			return nil
		}
		
		lastError = err
		fmt.Fprintf(os.Stderr, "Attempt %d failed: %v\n", attempt, err)
		
		// Check if error is retryable
		if !isRetryableError(err) {
			fmt.Fprint(os.Stderr, "Non-retryable error, aborting\n")
			return err
		}
	}
	
	return fmt.Errorf("All %d attempts failed. Last error: %v", config.MaxRetries, lastError)
}

func uploadEmail(serverURL string, emailData []byte, attempt int) error {
	if attempt == 0 {
		startTime = time.Now()
	}
	
	// Tor SOCKS5 proxy (standard port 9050)
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("Can't connect to Tor proxy: %v", err)
	}
	
	// HTTP transport with Tor
	httpTransport := &http.Transport{
		Dial: dialer.Dial,
	}
	
	// HTTP client with Tor transport and per-attempt timeout
	timeout := 30 * time.Second
	if attempt > 0 {
		// Increase timeout for retries
		timeout = 45 * time.Second
	}
	
	client := &http.Client{
		Transport: httpTransport,
		Timeout:   timeout,
	}
	
	// Prepare HTTP request
	request, err := http.NewRequest("POST", serverURL, bytes.NewReader(emailData))
	if err != nil {
		return fmt.Errorf("Failed to create request: %w", err)
	}
	
	// Set headers
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Attempt", fmt.Sprintf("%d", attempt+1))
	
	fmt.Fprint(os.Stderr, "Starting transfer...\n")
	
	// Send request
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("Failed to send request: %w", err)
	}
	defer response.Body.Close()
	
	// Read response
	responseBody, _ := io.ReadAll(response.Body)
	
	// Check status
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", 
			response.StatusCode, 
			strings.TrimSpace(string(responseBody)))
	}
	
	// Success!
	elapsedTime := time.Since(startTime)
	fmt.Fprintf(os.Stderr, "\nTransfer successful! Elapsed Time: %s\n", formatDuration(elapsedTime))
	
	return nil
}

func calculateBackoff(attempt int) time.Duration {
	// Exponential backoff: delay = initial * factor^attempt
	delay := float64(config.InitialDelay) * 
		pow(config.BackoffFactor, float64(attempt-1))
	
	// Cap at max delay
	if delay > float64(config.MaxDelay) {
		delay = float64(config.MaxDelay)
	}
	
	// Add jitter if enabled (±20%)
	if config.Jitter {
		jitter := 0.8 + 0.4*rand.Float64() // Random between 0.8 and 1.2
		delay *= jitter
	}
	
	return time.Duration(delay * float64(time.Second))
}

func pow(x, y float64) float64 {
	result := 1.0
	for i := 0; i < int(y); i++ {
		result *= x
	}
	return result
}

func isRetryableError(err error) bool {
	errStr := err.Error()
	
	// Non-retryable errors (permanent failures)
	nonRetryable := []string{
		"no such host",
		"connection refused",
		"404", "403", "401", // HTTP client errors
		"invalid onion address",
		"config file not found",
		"no configuration for user",
	}
	
	for _, pattern := range nonRetryable {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return false
		}
	}
	
	// Retryable errors (transient failures)
	retryable := []string{
		"timeout",
		"deadline exceeded",
		"network is unreachable",
		"connection reset",
		"temporary failure",
		"503", "502", "504", // HTTP server errors
		"i/o timeout",
		"no route to host",
	}
	
	for _, pattern := range retryable {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}
	
	// Default: retry other errors
	return true
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// Initialize random seed
func init() {
	rand.Seed(time.Now().UnixNano())
}
