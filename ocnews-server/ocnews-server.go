package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"golang.org/x/net/proxy"
)

const (
	crlf = "\r\n"
)

func main() {
	http.HandleFunc("/upload", handleUpload)
	fmt.Printf("🧅 Onion Courier Mixnet endpoint server for dizum m2n running 🚀\n")
	log.Fatal(http.ListenAndServe(":8088", nil))
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

	// Read raw binary data
	content, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		return
	}
	defer r.Body.Close()

	if len(content) == 0 {
		return
	}

	// Normalize line endings and forward (NO header modification)
	normalized := normalizeLineEndings(content)
	forwardViaEmail(normalized)
}

func forwardViaEmail(message []byte) {
	// Extract sender FROM THE MESSAGE
	sender := extractSender(message)
	if sender == "" {
		sender = "anonymous@anonymous.invalid"
	}
	
	to := "mail2news@dizum.com"
	host := "smtp.dizum.com"
	port := ":2525"
	proxyAddr := "127.0.0.1:9050"

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return
	}

	smtpClient, err := dialSMTP(dialer, host, port)
	if err != nil {
		return
	}
	defer smtpClient.Quit()

	if err = smtpClient.StartTLS(&tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}); err != nil {
		return
	}

	// Use the sender FROM THE MESSAGE
	if err = smtpClient.Mail(sender); err != nil {
		return
	}
	if err = smtpClient.Rcpt(to); err != nil {
		return
	}

	w, err := smtpClient.Data()
	if err != nil {
		return
	}
	_, err = w.Write(message)
	if err != nil {
		return
	}
	err = w.Close()
	if err != nil {
		return
	}
}

func extractSender(message []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(message))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "from:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				fromField := strings.TrimSpace(parts[1])
				if idx := strings.Index(fromField, "<"); idx != -1 {
					if idx2 := strings.Index(fromField, ">"); idx2 != -1 {
						return strings.TrimSpace(fromField[idx+1 : idx2])
					}
				}
				return strings.TrimSpace(fromField)
			}
		}
		if line == "" {
			break
		}
	}
	return ""
}

func dialSMTP(dialer proxy.Dialer, host, port string) (*smtp.Client, error) {
	conn, err := dialer.Dial("tcp", host+port)
	if err != nil {
		return nil, err
	}
	return smtp.NewClient(conn, host)
}
