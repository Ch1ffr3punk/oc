// Onion Courier CLI Mixnet Client

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/proxy"
)

var startTime time.Time

// Config holds client configuration paths and URLs
type Config struct {
	PubKeysURL   string `json:"pubkeys_url"`
	MixnodesURL  string `json:"mixnodes_url"`
	ConfigFile   string `json:"config_file"`
	PubKeysFile  string `json:"pubkeys_file"`
	MixnodesFile string `json:"mixnodes_file"`
}

// KeyEntry represents a public key with a name
type KeyEntry struct {
	Name string
	Key  [32]byte
}

// MixnodeEntry represents a mix node with name and address
type MixnodeEntry struct {
	Name    string
	Address string
	Status  string
}

// Constants for message sizing and padding
const (
	PaddingHeader  = "-----BEGIN PADDING-----"
	PaddingFooter  = "-----END PADDING-----"
	MaxUserPayload = 20480  // 20 KB maximum user message size
	MinTotalSize   = 1024   // 1 KB minimum total message size after padding
	MaxTotalSize   = 25600  // 25 KB maximum total message size after padding
)

// randInt generates a cryptographically secure random integer between 0 and max-1
func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return int(time.Now().UnixNano()) % max
	}
	return int(n.Int64())
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// adaptivePadding applies padding that automatically adapts to available space
func adaptivePadding(message []byte, maxTotalSize int) ([]byte, error) {
	if !bytes.HasPrefix(message, []byte("To:")) {
		return nil, fmt.Errorf("message must start with 'To:' header")
	}

	messageSize := len(message)
	
	// Calculate available space for padding
	availableSpace := maxTotalSize - messageSize
	overhead := len(PaddingHeader) + len(PaddingFooter) + 4 // 4 bytes for newlines
	
	// If not enough space for padding, return original message
	if availableSpace <= overhead {
		return message, nil
	}

	// Maximum padding based on available space
	maxPaddingSize := availableSpace - overhead
	
	// Choose random padding size within available space
	targetPaddingSize := randInt(maxPaddingSize + 1) // +1 because randInt is exclusive

	// At least 1 byte padding if possible
	if targetPaddingSize == 0 && maxPaddingSize > 0 {
		targetPaddingSize = 1
	}

	// Generate padding bytes
	padding := make([]byte, targetPaddingSize)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %v", err)
	}

	// Construct padded message
	padded := fmt.Sprintf("%s\n%s\n%s\n%s", 
		PaddingHeader,
		string(padding),
		PaddingFooter,
		string(message))

	// FINAL SIZE VALIDATION - Ensure we don't exceed the limit
	if len(padded) > maxTotalSize {
		// If still too large, use maximum possible size
		availableSpace = maxTotalSize - messageSize - overhead
		if availableSpace > 0 {
			padding = make([]byte, availableSpace)
			if _, err := rand.Read(padding); err != nil {
				return message, nil // Fallback to original message
			}
			padded = fmt.Sprintf("%s\n%s\n%s\n%s", 
				PaddingHeader,
				string(padding),
				PaddingFooter,
				string(message))
		} else {
			return message, nil // No space for padding
		}
	}

	return []byte(padded), nil
}

// extractRecipient extracts the recipient from the message
func extractRecipient(message []byte) string {
	lines := strings.SplitN(string(message), "\n", 2)
	if len(lines) > 0 && strings.HasPrefix(lines[0], "To:") {
		return strings.TrimSpace(strings.TrimPrefix(lines[0], "To:"))
	}
	return ""
}

// pingMixnodes checks the status of all mixnodes
func pingMixnodes() {
	config, err := ensureConfig()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
	if err != nil {
		fmt.Printf("Error loading mix node addresses: %v\n", err)
		fmt.Printf("Please run 'ocmix -i' first to download the mix nodes list\n")
		os.Exit(1)
	}

	fmt.Println("Checking mix node status via Tor...\n")

	for i := range mixnodes {
		status := checkNodeStatus(mixnodes[i].Address)
		mixnodes[i].Status = status
		fmt.Printf("%s\t\t\t%s\n", mixnodes[i].Name, mixnodes[i].Status)
	}
}

// checkNodeStatus checks if mixnode is online
func checkNodeStatus(address string) string {
    if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
        address = "http://" + address
    }

    if !strings.Contains(address, ":") {
        address = address + ":8080"
    } else if strings.Contains(address, "http://") && !strings.Contains(address, ":") {
        address = strings.Replace(address, "http://", "http://", 1) + ":8080"
    }

    testURL := address
    if !strings.HasSuffix(testURL, "/upload") {
        if strings.HasSuffix(testURL, "/") {
            testURL = testURL + "upload"
        } else {
            testURL = testURL + "/upload"
        }
    }

    // HTTP-Request via Tor
    dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
    if err != nil {
        return "n/a"
    }

    client := &http.Client{
        Transport: &http.Transport{
            Dial: dialer.Dial,
        },
        Timeout: 15 * time.Second, // Longer timeout for Tor
    }

    body := &bytes.Buffer{}
    writer := multipart.NewWriter(body)
    part, err := writer.CreateFormFile("file", "ping.test")
    if err != nil {
        return "n/a"
    }
    part.Write([]byte("ping"))
    writer.Close()

    req, err := http.NewRequest("POST", testURL, body)
    if err != nil {
        return "n/a"
    }
    req.Header.Set("Content-Type", writer.FormDataContentType())
    req.Header.Set("User-Agent", "OnionCourier-Ping/1.0")

    resp, err := client.Do(req)
    if err != nil {
        return "n/a"
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusOK || 
       resp.StatusCode == http.StatusMethodNotAllowed || 
       resp.StatusCode == http.StatusBadRequest ||
       resp.StatusCode == http.StatusInternalServerError {
        return "OK"
    }

    return "n/a"
}

// loadConfig loads or creates default config
func loadConfig() (*Config, error) {
	configDir := filepath.Join(".", "oc")
	configFile := filepath.Join(configDir, "config.json")
	
	defaultConfig := &Config{
		PubKeysURL:   "https://example.com/pubring.txt",
		MixnodesURL:  "https://example.com/mixnodes.txt",
		ConfigFile:   configFile,
		PubKeysFile:  filepath.Join(configDir, "pubring.txt"),
		MixnodesFile: filepath.Join(configDir, "mixnodes.txt"),
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfig, createDefaultConfig(defaultConfig, configDir)
		}
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	
	configDir = filepath.Dir(config.ConfigFile)
	config.PubKeysFile = filepath.Join(configDir, filepath.Base(config.PubKeysFile))
	config.MixnodesFile = filepath.Join(configDir, filepath.Base(config.MixnodesFile))
	
	return &config, nil
}

func createDefaultConfig(config *Config, configDir string) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(config.ConfigFile, data, 0600)
}

func ensureConfig() (*Config, error) {
	config, err := loadConfig()
	if err != nil {
		return nil, err
	}
	
	if _, err := os.Stat(config.MixnodesFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("mix nodes file not found: %s\nRun 'ocmix -i' first to download configuration", config.MixnodesFile)
	}
	
	return config, nil
}

// downloadConfigurations fetches keys and mixnodes via Tor
func downloadConfigurations() {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	if strings.Contains(config.PubKeysURL, "example.com") || strings.Contains(config.MixnodesURL, "example.com") {
		fmt.Println("WARNING: Configuration uses example URLs. Please edit the config file first:")
		fmt.Printf("  %s\n", config.ConfigFile)
		fmt.Println("\nUpdate the pub keys URL and mix nodes URL with actual URLs.")
		os.Exit(1)
	}

	fmt.Printf("Downloading config files via Tor...\n")
	fmt.Printf("Config directory: %s\n", filepath.Dir(config.ConfigFile))

	if err := os.MkdirAll(filepath.Dir(config.ConfigFile), 0700); err != nil {
		fmt.Printf("Error creating config directory: %v\n", err)
		os.Exit(1)
	}

	if err := downloadFileViaTor(config.PubKeysURL, config.PubKeysFile); err != nil {
		fmt.Printf("Error downloading pub keys: %v\n", err)
		os.Exit(1)
	}
	if err := downloadFileViaTor(config.MixnodesURL, config.MixnodesFile); err != nil {
		fmt.Printf("Error downloading mix nodes: %v\n", err)
		os.Exit(1)
	}
	
	if _, err := os.Stat(config.MixnodesFile); err == nil {
		fmt.Printf("✓ mix nodes file created: %s\n", config.MixnodesFile)
	}
	if _, err := os.Stat(config.PubKeysFile); err == nil {
		fmt.Printf("✓ pub keys file created: %s\n", config.PubKeysFile)
	}
	
	fmt.Println("Configuration updated successfully!")
}

func downloadFileViaTor(url, filename string) error {
	dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	if err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   30 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	os.MkdirAll(filepath.Dir(filename), 0700)
	return os.WriteFile(filename, data, 0600)
}

// encryptAndUploadRandom selects 2-5 random mix nodes and sends the message
func encryptAndUploadRandom(plaintext []byte) {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
	if err != nil {
		fmt.Printf("Error loading mix node addresses: %v\n", err)
		os.Exit(1)
	}

	numHops := 2 + randInt(4) // 2 to 5 hops

	if len(mixnodes) < numHops {
		fmt.Printf("Not enough mix nodes available. Need %d, have %d\n", numHops, len(mixnodes))
		os.Exit(1)
	}

	selectedNodes := selectRandomNodes(mixnodes, numHops)
	var nodeNames []string
	for _, node := range selectedNodes {
		nodeNames = append(nodeNames, node.Name)
	}

	encryptAndUpload(nodeNames, plaintext, config)
}

// sendDummyTraffic sends a single cover message
func sendDummyTraffic() {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
	if err != nil {
		fmt.Printf("Error loading mix node addresses: %v\n", err)
		os.Exit(1)
	}

	if len(mixnodes) < 1 {
		fmt.Printf("No mix nodes available for cover traffic\n")
		os.Exit(1)
	}

	fmt.Println("Sending message...")
	err = sendSingleDummyMessage(config, mixnodes, 1)
	if err != nil {
		fmt.Printf("Error sending cover message: %v\n", err)
		os.Exit(1)
	}
}

// sendSingleDummyMessage sends one dummy message through a random chain
func sendSingleDummyMessage(config *Config, mixnodes []MixnodeEntry, messageCount int) error {
	chainLength := 1 + randInt(5)
	if len(mixnodes) < chainLength {
		return fmt.Errorf("not enough mix nodes. Need %d, have %d", chainLength, len(mixnodes))
	}

	selectedNodes := selectRandomNodes(mixnodes, chainLength)
	var nodeNames []string
	for _, node := range selectedNodes {
		nodeNames = append(nodeNames, node.Name)
	}

	minSize := 100
	maxSize := MaxUserPayload
	if maxSize <= minSize {
		maxSize = minSize + 1000
	}
	payloadSize := minSize + randInt(maxSize-minSize)
	
	dummyPayload := generateRandomPayload(payloadSize)

	// For dummy traffic, create payload with .dummy recipient
	dummyRecipient := fmt.Sprintf("%s.dummy", nodeNames[len(nodeNames)-1])
	dummyMessageContent := fmt.Sprintf("To: %s\n\n%s", dummyRecipient, string(dummyPayload))

	dummyMessage, err := createDummyMessage(nodeNames, dummyMessageContent, mixnodes, config)
	if err != nil {
		return err
	}

	firstNode := selectedNodes[0]
	return uploadFile(firstNode.Address, strings.NewReader(dummyMessage))
}

// createDummyMessage builds an encrypted dummy message
func createDummyMessage(nodeNames []string, payload string, mixnodes []MixnodeEntry, config *Config) (string, error) {
	pubKeys, err := loadPublicKeys(config.PubKeysFile)
	if err != nil {
		return "", err
	}

	// Build the complete onion first
	currentMessage := payload
	for i := len(nodeNames) - 1; i >= 0; i-- {
		name := strings.TrimSpace(nodeNames[i])
		pubKey, found := findPublicKey(pubKeys, name)
		if !found {
			return "", fmt.Errorf("public key not found for: %s", name)
		}

		encryptedData, err := encryptMessage([]byte(currentMessage), pubKey)
		if err != nil {
			return "", err
		}

		if i > 0 {
			currentNodeName := strings.TrimSpace(nodeNames[i])
			currentMixnode, found := findMixnode(mixnodes, currentNodeName)
			if !found {
				return "", fmt.Errorf("mixnode not found: %s", currentNodeName)
			}
			currentMessage = fmt.Sprintf("To: %s\n\n%s", currentMixnode.Address, encryptedData)
		} else {
			currentMessage = encryptedData
		}
	}

	// Use adaptive padding for dummy messages
	paddedMessage, err := adaptivePadding([]byte(currentMessage), 28672)
	if err != nil {
		return "", err
	}

	// Encrypt the padded message for the first mix
	firstName := strings.TrimSpace(nodeNames[0])
	firstPubKey, found := findPublicKey(pubKeys, firstName)
	if !found {
		return "", fmt.Errorf("public key not found for first mixnode: %s", firstName)
	}

	// Use raw encryption for dummy messages
	encryptedRaw, err := encryptMessageRaw([]byte(paddedMessage), firstPubKey)
	if err != nil {
		return "", err
	}

	return string(encryptedRaw), nil
}

// generateRandomPayload creates a random alphanumeric payload
func generateRandomPayload(size int) []byte {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, size)
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		for i := range result {
			result[i] = charset[randInt(len(charset))]
		}
		return result
	}
	for i, b := range randomBytes {
		result[i] = charset[int(b)%len(charset)]
	}
	return result
}

// encryptAndUploadManual handles user-specified node chain
func encryptAndUploadManual(namesArg string, plaintext []byte) {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	names := strings.Split(namesArg, ",")
	if len(names) == 0 {
		fmt.Println("No node names provided")
		os.Exit(1)
	}

	if hasDuplicates(names) {
		fmt.Println("Duplicate node names not allowed")
		os.Exit(1)
	}

	encryptAndUpload(names, plaintext, config)
}

// selectRandomNodes picks 'count' random mix nodes
func selectRandomNodes(mixnodes []MixnodeEntry, count int) []MixnodeEntry {
	nodes := make([]MixnodeEntry, len(mixnodes))
	copy(nodes, mixnodes)
	
	for i := len(nodes) - 1; i > 0; i-- {
		j := randInt(i + 1)
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
	return nodes[:count]
}

// encryptMessageRaw encrypts using NaCl Box with raw binary output
func encryptMessageRaw(plaintext []byte, serverPubKey [32]byte) ([]byte, error) {
    ephemeralPublic, ephemeralPrivate, err := box.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("key generation failed: %v", err)
    }

    var nonce [24]byte
    if _, err := rand.Read(nonce[:]); err != nil {
        return nil, fmt.Errorf("nonce generation failed: %v", err)
    }

    encrypted := box.Seal(nil, plaintext, &nonce, &serverPubKey, ephemeralPrivate)

    output := make([]byte, 32+24+len(encrypted))
    copy(output[0:32], ephemeralPublic[:])
    copy(output[32:56], nonce[:])
    copy(output[56:], encrypted)
    
    return output, nil
}

// encryptMessage encrypts using NaCl Box and returns RAW binary output (no base64)
func encryptMessage(plaintext []byte, serverPubKey [32]byte) (string, error) {
    raw, err := encryptMessageRaw(plaintext, serverPubKey)
    if err != nil {
        return "", err
    }
    return string(raw), nil
}

// findMixnode looks up a mix node by name
func findMixnode(mixnodes []MixnodeEntry, name string) (MixnodeEntry, bool) {
	cleanName := strings.TrimSpace(name)
	for _, m := range mixnodes {
		if strings.TrimSpace(m.Name) == cleanName {
			return m, true
		}
	}
	return MixnodeEntry{}, false
}

// formatDuration returns human-readable duration
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := d / time.Minute
	s := (d - m*time.Minute) / time.Second
	if m > 0 {
		return fmt.Sprintf("%d min %d sec", m, s)
	}
	return fmt.Sprintf("%d sec", s)
}

// hasDuplicates checks for duplicate node names
func hasDuplicates(names []string) bool {
	seen := make(map[string]bool)
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if seen[trimmed] {
			return true
		}
		seen[trimmed] = true
	}
	return false
}

// loadPublicKeys parses PEM-formatted public keys
func loadPublicKeys(filename string) ([]KeyEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	content := strings.ReplaceAll(string(data), "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	sections := strings.Split(content, "\n\n")

	var keys []KeyEntry
	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}
		lines := strings.Split(section, "\n")
		if len(lines) < 2 {
			continue
		}
		name := strings.TrimSpace(lines[0])
		pemData := strings.Join(lines[1:], "\n")
		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			return nil, fmt.Errorf("invalid PEM for %s", name)
		}
		if len(block.Bytes) != 32 {
			return nil, fmt.Errorf("key must be 32 bytes: %s", name)
		}
		var key [32]byte
		copy(key[:], block.Bytes)
		keys = append(keys, KeyEntry{Name: name, Key: key})
	}
	return keys, nil
}

// loadMixnodeAddresses loads name/address pairs
func loadMixnodeAddresses(filename string) ([]MixnodeEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	content := strings.ReplaceAll(string(data), "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	sections := strings.Split(content, "\n\n")

	var mixnodes []MixnodeEntry
	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}
		lines := strings.Split(section, "\n")
		if len(lines) < 2 {
			continue
		}
		name := strings.TrimSpace(lines[0])
		address := strings.TrimSpace(lines[1])
		
		if !strings.Contains(address, ":") {
			address = address + ":8080"
		}
		
		mixnodes = append(mixnodes, MixnodeEntry{Name: name, Address: address})
	}
	return mixnodes, nil
}

// findPublicKey looks up a key by name
func findPublicKey(keys []KeyEntry, name string) ([32]byte, bool) {
	cleanName := strings.TrimSpace(name)
	for _, k := range keys {
		if strings.TrimSpace(k.Name) == cleanName {
			return k.Key, true
		}
	}
	return [32]byte{}, false
}

func uploadFile(serverAddress string, data io.Reader) error {
    if !strings.Contains(serverAddress, ":") {
        serverAddress = serverAddress + ":8080"
    }
    
    if !strings.HasPrefix(serverAddress, "http://") && !strings.HasPrefix(serverAddress, "https://") {
        serverAddress = "http://" + serverAddress
    }
    
    serverURL := serverAddress + "/upload"

    messageData, err := io.ReadAll(data)
    if err != nil {
        return err
    }

    body := &bytes.Buffer{}
    writer := multipart.NewWriter(body)
    
    part, err := writer.CreateFormFile("file", "message.bin")
    if err != nil {
        return err
    }
    
    if _, err := part.Write(messageData); err != nil {
        return err
    }
    
    if err := writer.Close(); err != nil {
        return err
    }

    dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
    if err != nil {
        return err
    }

    client := &http.Client{
        Transport: &http.Transport{Dial: dialer.Dial},
        Timeout: 120 * time.Second,
    }
    
    req, err := http.NewRequest("POST", serverURL, body)
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", writer.FormDataContentType())
    req.Header.Set("User-Agent", "OnionCourier/1.0")

    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("server error %s: %s", resp.Status, string(body))
    }

    elapsed := time.Since(startTime)
    fmt.Printf("Message sent successfully. Time: %s\n", formatDuration(elapsed))
    return nil
}

// encryptAndUpload builds the encrypted onion message and sends it through the mixnet
func encryptAndUpload(names []string, plaintext []byte, config *Config) {
    if len(plaintext) > MaxUserPayload {
        fmt.Printf("ERROR: Payload too large: %d > %d bytes\n", len(plaintext), MaxUserPayload)
        os.Exit(1)
    }

    pubKeys, err := loadPublicKeys(config.PubKeysFile)
    if err != nil {
        fmt.Printf("Error loading public keys: %v\n", err)
        os.Exit(1)
    }

    mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
    if err != nil {
        fmt.Printf("Error loading mix nodes: %v\n", err)
        os.Exit(1)
    }
    
    for _, name := range names {
        if _, found := findMixnode(mixnodes, name); !found {
            fmt.Printf("ERROR: mix node '%s' not found\n", name)
            os.Exit(1)
        }
        if _, found := findPublicKey(pubKeys, name); !found {
            fmt.Printf("ERROR: Public key for '%s' not found\n", name)
            os.Exit(1)
        }
    }

    firstNodeName := strings.TrimSpace(names[0])
    firstMixnode, _ := findMixnode(mixnodes, firstNodeName)

    finalRecipient := extractRecipient(plaintext)
    if finalRecipient == "" {
        fmt.Printf("Invalid message format: missing 'To:' header\n")
        os.Exit(1)
    }

    currentMessage := plaintext

    for i := len(names) - 1; i >= 0; i-- {
        currentNode := strings.TrimSpace(names[i])

        pubKey, found := findPublicKey(pubKeys, currentNode)
        if !found {
            fmt.Printf("FATAL: Public key not found for: %s\n", currentNode)
            os.Exit(1)
        }

        var nextHop string
        if i == len(names)-1 {
            nextHop = finalRecipient
        } else {
            nextNode := strings.TrimSpace(names[i+1])
            nextMixnode, found := findMixnode(mixnodes, nextNode)
            if !found {
                fmt.Printf("FATAL: Next mix node not found.")
                os.Exit(1)
            }
            nextHop = nextMixnode.Address
        }

        var payloadToEncrypt []byte
        
        if i == len(names)-1 {
            payloadToEncrypt = currentMessage
        } else {
            routingHeader := []byte("To: " + nextHop + "\n\n")
            payloadToEncrypt = append(routingHeader, currentMessage...)
        }

        // ALWAYS APPLY PADDING (for first hop only)
        if i == 0 {
            paddedPayload, err := adaptivePadding(payloadToEncrypt, 28672)
            if err != nil {
                // If padding fails, use original message
                paddedPayload = payloadToEncrypt
            }
            payloadToEncrypt = paddedPayload
        }

        encryptedPayload, err := encryptMessageRaw(payloadToEncrypt, pubKey)
        if err != nil {
            fmt.Printf("Encryption error.")
            os.Exit(1)
        }

        if i > 0 {
            currentMessage = encryptedPayload
        } else {
            routingHeader := []byte("To: " + nextHop + "\n\n")
            currentMessage = append(routingHeader, encryptedPayload...)
        }
        
        // FINAL VALIDATION - If too large, correct it
        if len(currentMessage) > 28672 {
            // Reduce to maximum allowed size
            fmt.Printf("Warning: Message too large, adjusting...\n")
            currentMessage = currentMessage[:28672]
        }
    }

    // Final size check
    if len(currentMessage) > 28672 {
        currentMessage = currentMessage[:28672]
    }

    fmt.Println("Sending message...")
    if err := uploadFile(firstMixnode.Address, bytes.NewReader(currentMessage)); err != nil {
        fmt.Printf("Upload failed.")
        os.Exit(1)
    }

}

func main() {
	startTime = time.Now()
	
	randomFlag := flag.Bool("r", false, "Send through 2-5 random mix nodes")
	infoFlag := flag.Bool("i", false, "Download and update configuration files")
	dummyFlag := flag.Bool("c", false, "Enable cover traffic mode")
	pingFlag := flag.Bool("p", false, "Check status of all mix nodes")
	flag.Parse()

	if *pingFlag {
		pingMixnodes()
		return
	}

	if *infoFlag {
		downloadConfigurations()
		return
	}

	if *dummyFlag {
		sendDummyTraffic()
		return
	}

	if !*randomFlag && flag.NArg() == 0 {
		fmt.Printf("Usage:\n")
		fmt.Printf("  ocmix -i                              Download configuration files\n")
		fmt.Printf("  ocmix -r < infile                     Send through 2-5 random mix nodes\n")
		fmt.Printf("  ocmix node1,node2,node3 < infile      Send through specific mix nodes\n")
		fmt.Printf("  ocmix -c                              Send cover traffic\n")
		fmt.Printf("  ocmix -p                              Check status of all mix nodes\n")
		os.Exit(1)
	}

	// Read plaintext (max 20 KB)
	plaintext, err := io.ReadAll(io.LimitReader(os.Stdin, MaxUserPayload))
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}

	if len(plaintext) > MaxUserPayload {
		fmt.Printf("ERROR: Payload too large!\n")
		fmt.Printf("Current size: %d bytes\n", len(plaintext))
		fmt.Printf("Maximum allowed: %d bytes\n", MaxUserPayload)
		os.Exit(1)
	}

	if *randomFlag {
		encryptAndUploadRandom(plaintext)
	} else {
		namesArg := flag.Arg(0)
		encryptAndUploadManual(namesArg, plaintext)
	}
}
