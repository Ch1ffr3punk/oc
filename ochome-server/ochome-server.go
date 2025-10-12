package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	alphanumeric   = "abcdefghijklmnopqrstuvwxyz0123456789"
	filenameLength = 12
	defaultInbox   = "inbox"
)

var (
	inboxPath string
)

func main() {
	flag.StringVar(&inboxPath, "p", defaultInbox, "Path to the inbox directory")
	flag.Parse()

	if err := os.MkdirAll(inboxPath, 0755); err != nil {
		log.Fatalf("Cannot create inbox directory: %v", err)
	}

	http.HandleFunc("/upload", handleUpload)
	fmt.Printf("Server running on http://localhost:8088, inbox: %s\n", inboxPath)
	log.Fatal(http.ListenAndServe(":8088", nil))
}

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

func handleUpload(w http.ResponseWriter, r *http.Request) {
	defer func() {
		randomDelay := time.Duration(time.Now().UnixNano()%5000+1000) * time.Millisecond
		time.Sleep(randomDelay)
		fmt.Fprint(w, "OK")
	}()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(content) == 0 {
		log.Println("Received empty message")
		return
	}

	filename, err := generateRandomFilename(filenameLength)
	if err != nil {
		filename = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	fullPath := filepath.Join(inboxPath, filename)
	if err := os.WriteFile(fullPath, content, 0600); err != nil {
		log.Printf("Error saving file: %v", err)
		http.Error(w, "Error saving file", http.StatusInternalServerError)
	} else {
		log.Printf("File saved: %s (%d bytes)", fullPath, len(content))
	}
}
