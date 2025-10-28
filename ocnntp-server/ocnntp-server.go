package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	server   = "news.tcpreset.net:119"
	torProxy = "127.0.0.1:9050"
	crlf     = "\r\n"
)

func main() {
	http.HandleFunc("/upload", handleUpload)
	fmt.Println("Server is running on http://localhost:8088")
	http.ListenAndServe(":8088", nil)
}

func normalizeLineEndings(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\n"), []byte(crlf))
	return data
}

func generateMessageID() string {
	randomBytes := make([]byte, 11)
	rand.Read(randomBytes)
	randomPart := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("<%s@oc2mxnet>", randomPart)
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

	content, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		return
	}
	defer r.Body.Close()

	if len(content) == 0 {
		return
	}

	normalized := normalizeLineEndings(content)
	
	articleWithHeaders := addHeaders(normalized)
	reader := bytes.NewReader(articleWithHeaders)
	sendArticle(reader)
}

func addHeaders(content []byte) []byte {
	var buffer bytes.Buffer
	
	buffer.WriteString("From: Onion Courier <noreply@oc2mx.net>")
	buffer.WriteString(crlf)
	
	userHeaders := extractUserHeaders(content)
	contentWithoutHeaders := removeUserHeaders(content)
	
	if subject, exists := userHeaders["Subject"]; exists {
		buffer.WriteString("Subject: ")
		buffer.WriteString(subject)
		buffer.WriteString(crlf)
	}
	
	if references, exists := userHeaders["References"]; exists {
		buffer.WriteString("References: ")
		buffer.WriteString(references)
		buffer.WriteString(crlf)
	}
	
	buffer.WriteString("Message-ID: ")
	buffer.WriteString(generateMessageID())
	buffer.WriteString(crlf)
	
	buffer.WriteString("Date: ")
	buffer.WriteString(time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 +0000"))
	buffer.WriteString(crlf)
	
	buffer.WriteString("MIME-Version: 1.0")
	buffer.WriteString(crlf)
	buffer.WriteString("Content-Type: text/plain; charset=utf-8")
	buffer.WriteString(crlf)
	buffer.WriteString("Content-Transfer-Encoding: 8bit")
	buffer.WriteString(crlf)
	
	if newsgroups, exists := userHeaders["Newsgroups"]; exists {
		buffer.WriteString("Newsgroups: ")
		buffer.WriteString(newsgroups)
		buffer.WriteString(crlf)
	}
	
	buffer.WriteString(crlf)
	
	buffer.Write(contentWithoutHeaders)
	
	return buffer.Bytes()
}

func extractUserHeaders(content []byte) map[string]string {
	headers := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // Ende der Header
		}
		
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headerName := strings.TrimSpace(parts[0])
				headerValue := strings.TrimSpace(parts[1])
				
				if headerName == "Subject" || headerName == "References" || headerName == "Newsgroups" {
					headers[headerName] = headerValue
				}
			}
		}
	}
	
	return headers
}

func removeUserHeaders(content []byte) []byte {
	var buffer bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(content))
	headerSectionEnded := false
	firstLine := true
	
	for scanner.Scan() {
		line := scanner.Text()
		
		if !headerSectionEnded {
			if line == "" {
				headerSectionEnded = true
				continue
			}
			
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					headerName := strings.TrimSpace(parts[0])
					if headerName != "Subject" && headerName != "References" && headerName != "Newsgroups" {
						if !firstLine {
							buffer.WriteString(crlf)
						}
						buffer.WriteString(line)
						firstLine = false
					}
					continue
				}
			}
		}
		
		// Body-Inhalt
		if headerSectionEnded {
			if !firstLine {
				buffer.WriteString(crlf)
			}
			buffer.WriteString(line)
			firstLine = false
		}
	}
	
	return buffer.Bytes()
}

func sendArticle(reader io.Reader) error {
	dialer, err := proxy.SOCKS5("tcp", torProxy, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("error creating SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", server)
	if err != nil {
		return fmt.Errorf("error connecting to the server through Tor: %v", err)
	}
	defer conn.Close()

	bufReader := bufio.NewReader(conn)
	response, err := bufReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error when reading the server greeting: %v", err)
	}

	fmt.Fprintf(conn, "POST\r\n")
	response, err = bufReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading the POST response: %v", err)
	}

	if !strings.HasPrefix(response, "340") {
		return fmt.Errorf("server does not accept POST")
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(conn, "%s\r\n", line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading the input: %v", err)
	}

	fmt.Fprintf(conn, ".\r\n")

	_, err = bufReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading the server response: %v", err)
	}

	fmt.Fprintf(conn, "QUIT\r\n")

	return nil
}
