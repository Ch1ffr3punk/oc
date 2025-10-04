package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
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
	crlf           = "\r\n"
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

func normalizeLineEndings(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\n"), []byte(crlf))
	return data
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

	var content []byte
	var err error

	contentType := r.Header.Get("Content-Type")
	if contentType != "" && contentType != "application/octet-stream" {
		if err := r.ParseMultipartForm(10 << 20); err == nil {
			if fileHeader := r.MultipartForm.File["file"]; len(fileHeader) > 0 {
				file, err := fileHeader[0].Open()
				if err == nil {
					defer file.Close()
					content, err = ioutil.ReadAll(file)
				}
			}
		}
	}

	if content == nil {
		content, err = ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading raw body: %v", err)
			return
		}
	}
	defer r.Body.Close()

	if len(content) == 0 {
		log.Println("Received empty message")
		return
	}

	normalized := normalizeLineEndings(content)
	savePlainTextMessage(normalized)
}

func savePlainTextMessage(data []byte) {
	filename, err := generateRandomFilename(filenameLength)
	if err != nil {
		filename = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	fullPath := filepath.Join(inboxPath, filename)
	if err := ioutil.WriteFile(fullPath, data, 0600); err != nil {
		log.Printf("Error saving file: %v", err)
	} else {
		log.Printf("Message saved: %s (%d bytes)", fullPath, len(data))
	}
}
