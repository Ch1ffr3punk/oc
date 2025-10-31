package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

const (
	crlf = "\r\n"
)

var (
	whitelistFile   string
	blacklistFile   string
	allowedDomains  []string
	blockedDomains  []string
	allowedEmails   []string
	blockedEmails   []string
	fixedFrom       string
	messageIDDomain string
)

func main() {
	flag.StringVar(&whitelistFile, "w", "", "Whitelist file (one email/domain per line)")
	flag.StringVar(&blacklistFile, "b", "", "Blacklist file (one email/domain per line)")
	flag.StringVar(&fixedFrom, "f", "Onion Courier <noreply@oc2mx.net>", "Fixed From header address")
	flag.StringVar(&messageIDDomain, "m", "oc2mx.net", "Domain for Message-ID generation")
	flag.Parse()

	if whitelistFile != "" {
		loadWhitelist(whitelistFile)
		log.Printf("Loaded whitelist from %s: %d domains, %d emails", whitelistFile, len(allowedDomains), len(allowedEmails))
	} else if blacklistFile != "" {
		loadBlacklist(blacklistFile)
		log.Printf("Loaded blacklist from %s: %d domains, %d emails", blacklistFile, len(blockedDomains), len(blockedEmails))
	} else {
		log.Println("Warning: Running without access control - this might be an open relay!")
	}

	log.Printf("Using fixed From address: %s", fixedFrom)
	log.Printf("Using Message-ID domain: %s", messageIDDomain)

	http.HandleFunc("/upload", handleUpload)
	fmt.Printf("Server running on http://localhost:8088 - forwarding messages to local Postfix\n")
	log.Fatal(http.ListenAndServe(":8088", nil))
}

func loadWhitelist(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening whitelist file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "@") {
			allowedEmails = append(allowedEmails, strings.ToLower(line))
		} else {
			allowedDomains = append(allowedDomains, strings.ToLower(line))
		}
	}
}

func loadBlacklist(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening blacklist file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "@") {
			blockedEmails = append(blockedEmails, strings.ToLower(line))
		} else {
			blockedDomains = append(blockedDomains, strings.ToLower(line))
		}
	}
}

func isAllowed(recipient string) bool {
	recipient = strings.ToLower(recipient)

	if blacklistFile != "" {
		for _, blocked := range blockedEmails {
			if blocked == recipient {
				return false
			}
		}
		parts := strings.Split(recipient, "@")
		if len(parts) == 2 {
			for _, domain := range blockedDomains {
				if domain == parts[1] {
					return false
				}
			}
		}
		return true
	}

	if whitelistFile != "" {
		for _, allowed := range allowedEmails {
			if allowed == recipient {
				return true
			}
		}
		parts := strings.Split(recipient, "@")
		if len(parts) == 2 {
			for _, domain := range allowedDomains {
				if domain == parts[1] {
					return true
				}
			}
		}
		return false
	}

	return true
}

func generateMessageID() string {
    const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    randomBytes := make([]byte, 21)
    rand.Read(randomBytes)
    
    var randomPart strings.Builder
    randomPart.Grow(21)
    for _, b := range randomBytes {
        randomPart.WriteByte(chars[b % byte(len(chars))])
    }
    
    return fmt.Sprintf("<%s@oc2mx.net>", randomPart.String())
}

func formatUTCDate() string {
	return time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700")
}

func modifyHeaders(original []byte) []byte {
    var buffer bytes.Buffer
    scanner := bufio.NewScanner(bytes.NewReader(original))

    hasMimeVersion := false
    hasContentType := false
    hasContentTransferEncoding := false
    hasSubject := false
    hasReferences := false
    
    var subjectHeader strings.Builder
    var referencesHeader strings.Builder
    var otherHeaders bytes.Buffer

    buffer.WriteString("From: " + fixedFrom + crlf)
    buffer.WriteString("Comment: This message did not originate from the sender address above." + crlf)
    buffer.WriteString("Comment: It was mailed anonymously through the Onion Courier Mixnet." + crlf)
    buffer.WriteString("Contact: info@oc2mx.net" + crlf)

    inSubject := false
    inReferences := false

    for scanner.Scan() {
        line := scanner.Text()
        
        if line == "" {
            break
        }

        isFolded := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
        
        if isFolded {
            if inSubject {
                subjectHeader.WriteString(crlf + line)
                continue
            } else if inReferences {
                referencesHeader.WriteString(crlf + line)
                continue
            }
            otherHeaders.WriteString(crlf + line)
            continue
        }

        inSubject = false
        inReferences = false
        
        lowerLine := strings.ToLower(line)
        
        if strings.HasPrefix(lowerLine, "subject:") {
            inSubject = true
            hasSubject = true
            subjectHeader.WriteString(line)
            continue
        }
        
        if strings.HasPrefix(lowerLine, "references:") {
            inReferences = true
            hasReferences = true
            referencesHeader.WriteString(line)
            continue
        }

        if strings.HasPrefix(lowerLine, "from:") || 
           strings.HasPrefix(lowerLine, "message-id:") || 
           strings.HasPrefix(lowerLine, "date:") {
            continue
        }

        otherHeaders.WriteString(line + crlf)

        if strings.HasPrefix(lowerLine, "mime-version:") {
            hasMimeVersion = true
        }
        if strings.HasPrefix(lowerLine, "content-type:") {
            hasContentType = true
        }
        if strings.HasPrefix(lowerLine, "content-transfer-encoding:") {
            hasContentTransferEncoding = true
        }
    }

    if hasSubject {
        buffer.WriteString(subjectHeader.String() + crlf)
    }
    if hasReferences {
        buffer.WriteString(referencesHeader.String() + crlf)
    }

    buffer.WriteString("Message-ID: " + generateMessageID() + crlf)
    buffer.WriteString("Date: " + formatUTCDate() + crlf)

    buffer.WriteString(otherHeaders.String())

    if !hasMimeVersion {
        buffer.WriteString("MIME-Version: 1.0" + crlf)
    }
    if !hasContentType {
        buffer.WriteString("Content-Type: text/plain; charset=UTF-8" + crlf)
    }
    if !hasContentTransferEncoding {
        buffer.WriteString("Content-Transfer-Encoding: 8bit" + crlf)
    }

    buffer.WriteString(crlf)

    for scanner.Scan() {
        buffer.WriteString(scanner.Text() + crlf)
    }

    return buffer.Bytes()
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
		log.Printf("Error reading body: %v", err)
		return
	}
	defer r.Body.Close()

	if len(content) == 0 {
		log.Println("Received empty message")
		return
	}

	// Normalize line endings and modify headers
	normalized := normalizeLineEndings(content)
	modified := modifyHeaders(normalized)
	forwardToPostfix(modified)
}

func forwardToPostfix(message []byte) {
    recipient := extractRecipient(message)
    if recipient == "" {
        log.Printf("Error: No recipient found in message")
        return
    }

    if !isAllowed(recipient) {
        log.Printf("Access denied for recipient: %s", recipient)
        return
    }

    host := "127.0.0.1"
    port := ":25"
        
    // Connecting
    client, err := smtp.Dial(host + port)
    if err != nil {
        log.Printf("Error connecting to Postfix: %v", err)
        return
    }
    defer func() {
        if err := client.Quit(); err != nil {
            log.Printf("Error during QUIT: %v", err)
        }
    }()

    // HELO/EHLO
    if err := client.Hello("localhost"); err != nil {
        log.Printf("Error sending EHLO: %v", err)
        return
    }
   
    // MAIL FROM
    if err := client.Mail("noreply@oc2mx.net"); err != nil {
        log.Printf("Error setting MAIL FROM: %v", err)
        return
    }
    
    // RCPT TO
    if err := client.Rcpt(recipient); err != nil {
        log.Printf("Error setting RCPT TO %s: %v", recipient, err)
        return
    }

    // DATA
    w, err := client.Data()
    if err != nil {
        log.Printf("Error preparing DATA: %v", err)
        return
    }

    // Send message
    _, err = w.Write(message)
    if err != nil {
        log.Printf("Error writing message: %v", err)
        return
    }
    
    err = w.Close()
    if err != nil {
        log.Printf("Error closing DATA: %v", err)
        return
    }
    
}

func extractRecipient(message []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(message))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "to:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				toField := strings.TrimSpace(parts[1])
				if idx := strings.Index(toField, "<"); idx != -1 {
					if idx2 := strings.Index(toField, ">"); idx2 != -1 {
						return strings.TrimSpace(toField[idx+1 : idx2])
					}
				}
				return strings.TrimSpace(toField)
			}
		}
		if line == "" {
			break
		}
	}
	return ""
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
