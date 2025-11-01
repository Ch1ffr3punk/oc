package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
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
)

// HMID implementation
const password = "mysecretpassword"

var passwortHash = sha256.Sum256([]byte(password))
var passwortHashHex = fmt.Sprintf("%x", passwortHash)

const base36Chars = "abcdefghijklmnopqrstuvwxyz0123456789"

func toBase36Fixed(data []byte) string {
	if len(data) != 13 {
		panic("data must be exactly 13 bytes")
	}
	
	bigInt := new(big.Int)
	bigInt.SetBytes(data)
	
	result := make([]byte, 0, 21)
	temp := new(big.Int)
	
	for i := 0; i < 21; i++ {
		bigInt.DivMod(bigInt, big.NewInt(36), temp)
		result = append([]byte{base36Chars[temp.Int64()]}, result...)
	}
	
	return string(result)
}

func fromBase36Fixed(s string) ([]byte, error) {
	if len(s) != 21 {
		return nil, fmt.Errorf("must be exactly 21 characters")
	}
	
	bigInt := big.NewInt(0)
	
	for i := 0; i < len(s); i++ {
		c := s[i]
		var digit int64
		
		if c >= 'a' && c <= 'z' {
			digit = int64(c - 'a')
		} else if c >= '0' && c <= '9' {
			digit = int64(c - '0' + 26)
		} else {
			return nil, fmt.Errorf("invalid character: %c")
		}
		
		bigInt.Mul(bigInt, big.NewInt(36))
		bigInt.Add(bigInt, big.NewInt(digit))
	}
	
	result := make([]byte, 13)
	bytes := bigInt.Bytes()
	
	if len(bytes) < 13 {
		copy(result[13-len(bytes):], bytes)
	} else if len(bytes) == 13 {
		copy(result, bytes)
	} else {
		copy(result, bytes[len(bytes)-13:])
	}
	
	return result, nil
}

func hmidgen() string {
	iv := make([]byte, 10)
	_, err := rand.Read(iv)
	if err != nil {
		panic(err)
	}

	digest := sha256.New()
	digest.Write(iv)
	digest.Write(passwortHash[:])
	hash := digest.Sum(nil)[:3]

	data := append(iv, hash...)
	return toBase36Fixed(data)
}

func main() {
	flag.StringVar(&whitelistFile, "w", "", "Whitelist file (one email/domain per line)")
	flag.StringVar(&blacklistFile, "b", "", "Blacklist file (one email/domain per line)")
	flag.Parse()

	if whitelistFile != "" {
		loadWhitelist(whitelistFile)
	} else if blacklistFile != "" {
		loadBlacklist(blacklistFile)
	}

	http.HandleFunc("/upload", handleUpload)
	fmt.Printf("Server running on http://localhost:8088\n")
	fmt.Printf("\nPassword hash used for generation: %s\n", passwortHashHex)
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
    // Generate HMID as the local part of Message-ID
    hmidPart := hmidgen()
    
    return fmt.Sprintf("<%s@oc2mx.net>", hmidPart)
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

    buffer.WriteString("From: Onion Courier <noreply@oc2mx.net>" + crlf)
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
		return
	}
	defer r.Body.Close()

	if len(content) == 0 {
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
        return
    }

    if !isAllowed(recipient) {
        return
    }

    host := "127.0.0.1"
    port := ":25"
        
    // Connecting to Postfix
    client, err := smtp.Dial(host + port)
    if err != nil {
        return
    }
    defer func() {
        client.Quit()
    }()

    // HELO/EHLO
    if err := client.Hello("localhost"); err != nil {
        return
    }
   
    // MAIL FROM
    if err := client.Mail("noreply@oc2mx.net"); err != nil {
        return
    }
    
    // RCPT TO
    if err := client.Rcpt(recipient); err != nil {
        return
    }

    // DATA
    w, err := client.Data()
    if err != nil {
        return
    }

    // Send message
    _, err = w.Write(message)
    if err != nil {
        return
    }
    
    w.Close()
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
