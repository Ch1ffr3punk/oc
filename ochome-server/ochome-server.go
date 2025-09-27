package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// Alphanumeric characters for random filename
	alphanumeric   = "abcdefghijklmnopqrstuvwxyz0123456789"
	filenameLength = 12
	defaultInbox   = "inbox"
)

var (
	inboxPath  string
	timestamp  bool
)

func main() {
	// Define command line flags
	flag.StringVar(&inboxPath, "p", defaultInbox, "Path to the inbox directory")
	flag.BoolVar(&timestamp, "t", false, "Set file timestamp to 1.1.1970 UTC")
	flag.Parse()

	// Create inbox directory if it doesn't exist
	if err := createInboxDir(); err != nil {
		log.Fatalf("Error creating inbox directory: %v", err)
	}

	http.HandleFunc("/upload", handleUpload)

	fmt.Printf("Onion Courier home server running on http://localhost:8080\n")
	fmt.Printf("Inbox directory: %s\n", inboxPath)
	fmt.Printf("Timestamp mode: %v\n", timestamp)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// createInboxDir creates the inbox directory if it doesn't exist
func createInboxDir() error {
	if err := os.MkdirAll(inboxPath, 0755); err != nil {
		return fmt.Errorf("failed to create inbox directory '%s': %v", inboxPath, err)
	}
	log.Printf("Inbox directory created/verified: %s", inboxPath)
	return nil
}

// generateRandomFilename generates a random alphanumeric filename of specified length
func generateRandomFilename(length int) (string, error) {
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		if err != nil {
			return "", err
		}
		b[i] = alphanumeric[n.Int64()]
	}
	return string(b), nil
}

// setFileTimestamp sets the file timestamp to 1.1.1970 UTC (cross-platform)
func setFileTimestamp(filePath string) error {
	// Create timestamp for 1.1.1970 00:00:00 UTC
	epochTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	
	// For cross-platform compatibility, we need to handle both atime and mtime
	// We set both to the same epoch time
	return os.Chtimes(filePath, epochTime, epochTime)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	// Anonymous response with random delay
	defer func() {
		delay := time.Duration(time.Now().UnixNano()%5000+1000) * time.Millisecond
		time.Sleep(delay)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, "OK")
	}()

	if r.Method != http.MethodPost {
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		return
	}
	defer file.Close()

	content, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}

	// Extract payload (ignore To: header)
	messageStr := string(content)
	var payload string
	if idx := strings.Index(messageStr, "\n\n"); idx != -1 {
		payload = messageStr[idx+2:]
	} else {
		payload = messageStr
	}

	// Save directly as plain text (no Base64 decoding or decryption)
	savePlainTextMessage([]byte(payload))
}

func savePlainTextMessage(data []byte) {
	// Generate random filename
	filename, err := generateRandomFilename(filenameLength)
	if err != nil {
		log.Printf("Error generating filename: %v", err)
		// Fallback to timestamp if random generation fails
		filename = fmt.Sprintf("%d", time.Now().Unix())
	}

	// Create full path including inbox directory
	fullPath := filepath.Join(inboxPath, filename)

	// Save the message in plain text
	err = ioutil.WriteFile(fullPath, data, 0600)
	if err != nil {
		log.Printf("Error saving plain text message: %v", err)
		return
	}

	// Set timestamp to 1.1.1970 if -t flag is provided
	if timestamp {
		if err := setFileTimestamp(fullPath); err != nil {
		  } else {
			return
		}
	}
}
