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
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	alphanumeric   = "abcdefghijklmnopqrstuvwxyz0123456789"
	filenameLength = 12
	defaultInbox   = "inbox"
)

var (
	inboxPath string
	timestamp bool

	windowsSpecialTime = time.Date(1758, time.January, 1, 0, 0, 0, 0, time.UTC)
)

func main() {
	flag.StringVar(&inboxPath, "p", defaultInbox, "Path to the inbox directory")
	flag.BoolVar(&timestamp, "t", false, "Set file timestamp to 01.01.1758 UTC +0000")
	flag.Parse()

	os.MkdirAll(inboxPath, 0755)
	http.HandleFunc("/upload", handleUpload)
	fmt.Printf("Server running on http://localhost:8080, inbox: %s, timestamp: %v\n", inboxPath, timestamp)
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

// SetFileEpochTimestamp
func SetFileEpochTimestamp(path string) error {
	if err := os.Chtimes(path, windowsSpecialTime, windowsSpecialTime); err != nil {
		return err
	}
		if runtime.GOOS == "windows" {
		return setFileTimestampWindows(path, windowsSpecialTime)
	}

	return nil
}

// setFileTimestampWindows 
func setFileTimestampWindows(filePath string, targetTime time.Time) error {
	modkernel32 := syscall.NewLazyDLL("kernel32.dll")
	procSetFileTime := modkernel32.NewProc("SetFileTime")

	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}

	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(handle)

	createTime := syscall.NsecToFiletime(targetTime.UnixNano())
	accessTime := syscall.NsecToFiletime(targetTime.UnixNano())
	writeTime := syscall.NsecToFiletime(targetTime.UnixNano())

	r1, _, err := procSetFileTime.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&createTime)),
		uintptr(unsafe.Pointer(&accessTime)),
		uintptr(unsafe.Pointer(&writeTime)),
	)

	if r1 == 0 {
		return fmt.Errorf("SetFileTime failed: %v", err)
	}

	return nil
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	defer func() {
		time.Sleep(time.Duration(time.Now().UnixNano()%5000+1000) * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
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
		log.Printf("Error generating filename: %v", err)
		filename = fmt.Sprintf("%d", time.Now().Unix())
	}

	fullPath := filepath.Join(inboxPath, filename)

	err = ioutil.WriteFile(fullPath, data, 0600)
	if err != nil {
		log.Printf("Error saving plain text message: %v", err)
		return
	}

	if timestamp {
		if err := SetFileEpochTimestamp(fullPath); err != nil {
			log.Printf("Error setting file timestamp: %v", err)
			log.Printf("Message saved as: %s", fullPath)
		} else {
			log.Printf("Message saved as: %s (ALL timestamps set to 01.01.1758 UTC +0000)", fullPath)
		}
	} else {
		log.Printf("Message saved as: %s", fullPath)
	}
}
