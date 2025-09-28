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

	os.MkdirAll(inboxPath, 0755)
	http.HandleFunc("/upload", handleUpload)
	fmt.Printf("Server running on http://localhost:8080, inbox: %s\n", inboxPath)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func generateRandomFilename(length int) (string, error) {
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		b[i] = alphanumeric[n.Int64()]
	}
	return string(b), nil
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	defer func() {
		time.Sleep(time.Duration(time.Now().UnixNano()%5000+1000) * time.Millisecond)
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

	content, _ := ioutil.ReadAll(file)
	messageStr := string(content)
	
	var payload string
	if idx := strings.Index(messageStr, "\n\n"); idx != -1 {
		payload = messageStr[idx+2:]
	} else {
		payload = messageStr
	}

	savePlainTextMessage([]byte(payload))
}

func savePlainTextMessage(data []byte) {
	filename, err := generateRandomFilename(filenameLength)
	if err != nil {
		filename = fmt.Sprintf("%d", time.Now().Unix())
	}

	fullPath := filepath.Join(inboxPath, filename)
	ioutil.WriteFile(fullPath, data, 0600)

	log.Printf("Message saved as: %s", fullPath)
}
