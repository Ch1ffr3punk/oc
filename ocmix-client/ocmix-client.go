package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
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

// Config represents the client configuration
type Config struct {
	PubKeysURL   string `json:"pubkeys_url"`
	MixnodesURL  string `json:"mixnodes_url"`
	ConfigFile   string `json:"config_file"`
	PubKeysFile  string `json:"pubkeys_file"`
	MixnodesFile string `json:"mixnodes_file"`
}

// KeyEntry represents a public key entry
type KeyEntry struct {
	Name string
	Key  [32]byte
}

// MixnodeEntry represents a mixnode address entry
type MixnodeEntry struct {
	Name    string
	Address string
}

// Constants for message sizing
const (
	TotalMessageSize   = 138240 // 135 KB base size per hop
	MaxUserPayload     = 24576  // 24 KB fixed user payload
	MaxPaddingPerHop   = 3072   // Maximum padding per hop
	EncryptionOverhead = 56     // 32B pubkey + 24B nonce
	SafetyMargin       = 1024   // Safety buffer
	Base64Factor       = 1.37   // Base64 overhead
)

func main() {
	randomFlag := flag.Bool("r", false, "Send through 2-5 random nodes")
	infoFlag := flag.Bool("i", false, "Download and update configuration files")
	dummyFlag := flag.Bool("c", false, "Enable cover traffic mode")
	flag.Parse()

	if *infoFlag {
		downloadConfigurations()
		return
	}

	if *dummyFlag {
		// Dummy/cover traffic mode
		sendDummyTraffic()
		return
	}

	if !*randomFlag && flag.NArg() == 0 {
		fmt.Printf("Usage:\n")
		fmt.Printf("  ocmix -i                              Download configuration files\n")
		fmt.Printf("  ocmix -r < infile                     Send through 2-5 random nodes\n")
		fmt.Printf("  ocmix node1,node2,node3 < infile      Send through specific nodes\n")
		fmt.Printf("  ocmix -c                              Send cover traffic\n")
		os.Exit(1)
	}

	// Read plaintext first to get size
	plaintext, err := io.ReadAll(io.LimitReader(os.Stdin, MaxUserPayload))
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}

	if len(plaintext) > MaxUserPayload {
		fmt.Printf("ERROR: Payload too large!\n")
		fmt.Printf("Current size: %d bytes\n", len(plaintext))
		fmt.Printf("Maximum allowed: %d bytes\n", MaxUserPayload)
		fmt.Printf("Reduce your message by %d bytes\n", len(plaintext)-MaxUserPayload)
		os.Exit(1)
	}

	if *randomFlag {
		// Random mode with 2-5 hops
		encryptAndUploadRandom(plaintext)
	} else {
		// Manual mode with specific nodes
		namesArg := flag.Arg(0)
		encryptAndUploadManual(namesArg, plaintext)
	}
}

// encryptAndUploadRandom handles random hop selection (2-5 hops)
func encryptAndUploadRandom(plaintext []byte) {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Load available nodes
	mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
	if err != nil {
		fmt.Printf("Error loading Mixnode addresses: %v\n", err)
		os.Exit(1)
	}

	// Generate random number of hops between 2 and 5
	mrand.Seed(time.Now().UnixNano())
	numHops := 2 + mrand.Intn(4) // 2-5 hops

	if len(mixnodes) < numHops {
		fmt.Printf("Not enough mixnodes available. Need %d, have %d\n", numHops, len(mixnodes))
		os.Exit(1)
	}

	// Select random nodes
	selectedNodes := selectRandomNodes(mixnodes, numHops)
	var nodeNames []string
	for _, node := range selectedNodes {
		nodeNames = append(nodeNames, node.Name)
	}

	fmt.Printf("Selected %d-hop random chain: %s\n", numHops, strings.Join(nodeNames, " → "))

	encryptAndUpload(nodeNames, plaintext, config)
}

// sendDummyTraffic sends a single dummy/cover traffic message
func sendDummyTraffic() {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Load available nodes
	mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
	if err != nil {
		fmt.Printf("Error loading Mixnode addresses: %v\n", err)
		os.Exit(1)
	}

	if len(mixnodes) < 1 {
		fmt.Printf("No mixnodes available for cover traffic\n")
		os.Exit(1)
	}

	fmt.Println("Sending message...")
	
	err = sendSingleDummyMessage(config, mixnodes, 1)
	if err != nil {
		fmt.Printf("Error sending cover message: %v\n", err)
		os.Exit(1)
	}

}

// sendSingleDummyMessage sends one dummy message with random chain
func sendSingleDummyMessage(config *Config, mixnodes []MixnodeEntry, messageCount int) error {
	// Generate random chain length (1-5 hops)
	chainLength := 1 + mrand.Intn(5)
	
	if len(mixnodes) < chainLength {
		return fmt.Errorf("not enough mixnodes available. Need %d, have %d", chainLength, len(mixnodes))
	}

	// Select random nodes for the chain
	selectedNodes := selectRandomNodes(mixnodes, chainLength)
	var nodeNames []string
	for _, node := range selectedNodes {
		nodeNames = append(nodeNames, node.Name)
	}

	// Generate random dummy payload with variable size
	payloadSize := 1000 + mrand.Intn(MaxUserPayload-1000) // 1KB to MaxUserPayload
	dummyPayload := generateRandomPayload(payloadSize)

	// Create dummy message with .dummy address for the last node
	dummyMessage, err := createDummyMessage(nodeNames, dummyPayload, mixnodes, config)
	if err != nil {
		return err
	}

	// Upload to first node
	firstNode := selectedNodes[0]
		
	return uploadFile(firstNode.Address, strings.NewReader(dummyMessage))
}

// createDummyMessage creates an encrypted dummy message with .dummy address
func createDummyMessage(nodeNames []string, payload []byte, mixnodes []MixnodeEntry, config *Config) (string, error) {
	// Load public keys
	pubKeys, err := loadPublicKeys(config.PubKeysFile)
	if err != nil {
		return "", err
	}

	// Generate ephemeral key pair for dummy encryption (not using real server keys)
	dummyPubKey, dummyPrivKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	// Start with the dummy payload
	currentMessage := string(payload)

	// Encrypt for each node in reverse order (from last to first)
	for i := len(nodeNames) - 1; i >= 0; i-- {
		name := strings.TrimSpace(nodeNames[i])

		// For the last node, use .dummy address instead of real address
		if i == len(nodeNames)-1 {
			// Last node gets dummy routing
			paddedMessage := addAdaptivePaddingForHop(currentMessage, i, len(nodeNames), len(payload))
			_ , err := encryptDummyMessage([]byte(paddedMessage), dummyPubKey, dummyPrivKey)
			if err != nil {
				return "", err
			}
			continue
		}

		// For intermediate nodes, use real encryption
		pubKey, found := findPublicKey(pubKeys, name)
		if !found {
			return "", fmt.Errorf("public key not found for: %s", name)
		}

		paddedMessage := addAdaptivePaddingForHop(currentMessage, i, len(nodeNames), len(payload))
		encryptedData, err := encryptMessage([]byte(paddedMessage), pubKey)
		if err != nil {
			return "", err
		}

		// Add routing header for the next hop
		if i > 0 {
			nextNodeName := strings.TrimSpace(nodeNames[i-1])
			nextMixnode, found := findMixnode(mixnodes, nextNodeName)
			if !found {
				return "", fmt.Errorf("mixnode not found for next node: %s", nextNodeName)
			}
			currentMessage = fmt.Sprintf("To: %s\n\n%s", nextMixnode.Address, encryptedData)
		} else {
			// First node gets the raw encrypted data
			currentMessage = encryptedData
		}
	}

	return currentMessage, nil
}

// encryptDummyMessage encrypts with ephemeral keys (not using server keys)
func encryptDummyMessage(plaintext []byte, pubKey, privKey *[32]byte) (string, error) {
	// Generate nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}

	// Encrypt the message with dummy keys
	ciphertext := box.Seal(nil, plaintext, &nonce, pubKey, privKey)

	// Output format: [32-byte public key][24-byte nonce][ciphertext]
	output := append(pubKey[:], nonce[:]...)
	output = append(output, ciphertext...)

	// Encode as base64
	encoded := base64.StdEncoding.EncodeToString(output)

	// Wrap at 76 characters per line
	return wrapText(encoded, 76), nil
}

// generateRandomPayload generates random alphanumeric payload
func generateRandomPayload(size int) []byte {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, size)
	
	// Use crypto/rand for security
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Fallback to math/rand
		mrand.Seed(time.Now().UnixNano())
		for i := range result {
			result[i] = charset[mrand.Intn(len(charset))]
		}
		return result
	}

	// Map random bytes to charset
	for i, b := range randomBytes {
		result[i] = charset[int(b)%len(charset)]
	}
	
	return result
}

// loadConfig loads the client configuration from JSON file (cross-platform)
func loadConfig() (*Config, error) {
	configFile := "oc/config.json"
	
	// Default configuration with cross-platform paths
	defaultConfig := &Config{
		PubKeysURL:   "https://example.com/pubring.txt",
		MixnodesURL:  "https://example.com/mixnodes.txt", 
		ConfigFile:   filepath.Join("oc", "config.json"),
		PubKeysFile:  filepath.Join("oc", "pubring.txt"),
		MixnodesFile: filepath.Join("oc", "mixnodes.txt"),
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		// Create default config file if it doesn't exist
		if os.IsNotExist(err) {
			return defaultConfig, createDefaultConfig(defaultConfig)
		}
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// createDefaultConfig creates a default configuration file (cross-platform)
func createDefaultConfig(config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	
	// Create oc directory with cross-platform permissions
	os.MkdirAll("oc", 0700)
	
	return os.WriteFile("oc/config.json", data, 0600)
}

// downloadConfigurations downloads the configuration files via Tor
func downloadConfigurations() {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	if config.PubKeysURL == "https://example.com/pubring.txt" || 
	   config.MixnodesURL == "https://example.com/mixnodes.txt" {
		fmt.Printf("WARNING: Configuration still uses example URLs.\n")
		fmt.Printf("Please edit ocmix_config.json with actual URLs before using.\n")
		os.Exit(1)
	}

	fmt.Println("Downloading configuration files via Tor...")

	// Create oc directory with cross-platform permissions
	os.MkdirAll("oc", 0700)

	// Download public keys
	fmt.Printf("Downloading public keys from: %s\n", config.PubKeysURL)
	err = downloadFileViaTor(config.PubKeysURL, config.PubKeysFile)
	if err != nil {
		fmt.Printf("Error downloading public keys: %v\n", err)
		os.Exit(1)
	}

	// Download mixnodes
	fmt.Printf("Downloading mixnodes from: %s\n", config.MixnodesURL)
	err = downloadFileViaTor(config.MixnodesURL, config.MixnodesFile)
	if err != nil {
		fmt.Printf("Error downloading mixnodes: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Configuration files updated successfully!")
	fmt.Printf("Public keys: %s\n", config.PubKeysFile)
	fmt.Printf("Mixnodes: %s\n", config.MixnodesFile)
}

// downloadFileViaTor downloads a file via Tor proxy
func downloadFileViaTor(url, filename string) error {
	// Set up SOCKS5 proxy through Tor
	dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	if err != nil {
		return err
	}

	httpTransport := &http.Transport{Dial: dialer.Dial}
	client := &http.Client{
		Transport: httpTransport,
		Timeout:   30 * time.Second,
	}

	// Create HTTP request
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	// Execute the request
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// Check response status
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status: %s", response.Status)
	}

	// Read response body
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	// Save to file with cross-platform permissions
	return os.WriteFile(filename, data, 0600)
}

// encryptAndUploadManual handles manual node selection
func encryptAndUploadManual(namesArg string, plaintext []byte) {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	names := strings.Split(namesArg, ",")
	if len(names) == 0 {
		fmt.Printf("No names provided\n")
		os.Exit(1)
	}

	// Check for duplicate names in the chain
	if hasDuplicates(names) {
		fmt.Printf("Duplicate node names in chain are not allowed.\nUse different nodes for proper mixing.\n")
		os.Exit(1)
	}

	encryptAndUpload(names, plaintext, config)
}

// selectRandomNodes selects random nodes for the chain
func selectRandomNodes(mixnodes []MixnodeEntry, count int) []MixnodeEntry {
	mrand.Seed(time.Now().UnixNano())
	
	// Create a copy to avoid modifying original
	nodes := make([]MixnodeEntry, len(mixnodes))
	copy(nodes, mixnodes)
	
	// Shuffle nodes
	mrand.Shuffle(len(nodes), func(i, j int) {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	})
	
	return nodes[:count]
}

// encryptAndUpload handles the main encryption and upload logic
func encryptAndUpload(names []string, plaintext []byte, config *Config) {
	// Load public keys
	pubKeys, err := loadPublicKeys(config.PubKeysFile)
	if err != nil {
		fmt.Printf("Error loading public keys: %v\n", err)
		os.Exit(1)
	}

	// Load Mixnode addresses
	mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
	if err != nil {
		fmt.Printf("Error loading Mixnode addresses: %v\n", err)
		os.Exit(1)
	}

	// Store the first node info for upload
	firstNodeName := strings.TrimSpace(names[0])
	firstMixnode, found := findMixnode(mixnodes, firstNodeName)
	if !found {
		fmt.Printf("Mixnode not found for first node.")
		os.Exit(1)
	}

	// Start with the original message
	currentMessage := string(plaintext)

	// Encrypt for each node in reverse order (from last to first)
	for i := len(names) - 1; i >= 0; i-- {
		name := strings.TrimSpace(names[i])

		// Find public key for this mix node
		pubKey, found := findPublicKey(pubKeys, name)
		if !found {
			fmt.Printf("Public key not found for: %s\n", name)
			os.Exit(1)
		}

		// Add adaptive padding for each hop
		paddedMessage := addAdaptivePaddingForHop(currentMessage, i, len(names), len(plaintext))
		
		// Encrypt the padded message
		encryptedData, err := encryptMessage([]byte(paddedMessage), pubKey)
		if err != nil {
			fmt.Printf("Error encrypting for %s: %v\n", name, err)
			os.Exit(1)
		}

		// Add routing header for the next hop if not the first node
		if i > 0 {
			nextNodeName := strings.TrimSpace(names[i-1])
			nextMixnode, found := findMixnode(mixnodes, nextNodeName)
			if !found {
				fmt.Printf("Mixnode not found for next node.")
				os.Exit(1)
			}
			// Format: "To: address\n\nencrypted_data"
			currentMessage = fmt.Sprintf("To: %s\n\n%s", nextMixnode.Address, encryptedData)
		} else {
			// First node gets the raw encrypted data without headers
			currentMessage = encryptedData
		}
	}

	// Upload the encrypted message to the first server
	fmt.Println("Sending message...")
	err = uploadFile(firstMixnode.Address, strings.NewReader(currentMessage))
	if err != nil {
		fmt.Printf("Error uploading file: %v\n", err)
		os.Exit(1)
	}
}

// calculateAvailableSize calculates available size for a specific hop
func calculateAvailableSize(hopIndex int, totalHops int) int {
	available := TotalMessageSize - SafetyMargin
	
	// Calculate forward from base to current hop
	for i := 0; i <= hopIndex; i++ {
		available = available - EncryptionOverhead
		available = int(float64(available) / Base64Factor)
	}
	
	return available
}

// calculateDynamicPadding calculates random padding for each hop
func calculateDynamicPadding(plaintextSize int, hopIndex int, totalHops int) int {
	// Calculate available size for this hop
	available := calculateAvailableSize(hopIndex, totalHops)
	
	// Calculate minimum padding needed
	minPadding := available - plaintextSize - 100 // 100 bytes buffer
	if minPadding < 100 {
		minPadding = 100 // Minimum padding
	}
	
	// Calculate maximum possible padding
	maxPossible := available - plaintextSize
	maxPadding := MaxPaddingPerHop
	if maxPadding > maxPossible {
		maxPadding = maxPossible
	}
	
	// Ensure minPadding doesn't exceed maxPadding
	if minPadding > maxPadding {
		minPadding = maxPadding
	}
	
	// Generate random seed based on time and hop index
	mrand.Seed(time.Now().UnixNano() + int64(hopIndex*1000))
	
	// Random padding between min and max
	if maxPadding > minPadding {
		return minPadding + mrand.Intn(maxPadding-minPadding)
	}
	
	return minPadding
}

// addAdaptivePaddingForHop adds random padding for each hop
func addAdaptivePaddingForHop(data string, hopIndex int, totalHops int, plaintextSize int) string {
	// Calculate dynamic padding size
	paddingSize := calculateDynamicPadding(plaintextSize, hopIndex, totalHops)
	
	// Generate random padding bytes (using crypto/rand for security)
	paddingBytes := make([]byte, paddingSize)
	_, err := rand.Read(paddingBytes)
	if err != nil {
		// Fallback to math/rand if crypto/rand fails
		mrand.Seed(time.Now().UnixNano())
		for i := range paddingBytes {
			paddingBytes[i] = byte(mrand.Intn(256))
		}
	}
	
	// Base64 encoding without line breaks
	paddingB64 := base64.StdEncoding.EncodeToString(paddingBytes)
	paddingB64 = strings.ReplaceAll(paddingB64, "\n", "")
	
	// Create padding block
	paddingBlock := "-----BEGIN PADDING-----\n" + paddingB64 + "\n-----END PADDING-----\n"
	
	return paddingBlock + data
}

// hasDuplicates checks for duplicate node names in the chain
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

// encryptMessage encrypts plaintext using NaCl Box with the server's public key
func encryptMessage(plaintext []byte, serverPubKey [32]byte) (string, error) {
	// Generate ephemeral key pair
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("error generating key pair: %v", err)
	}

	var clientPubKey, clientPrivKey [32]byte
	copy(clientPubKey[:], publicKey[:])
	copy(clientPrivKey[:], privateKey[:])

	// Generate nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}

	// Encrypt the message
	ciphertext := box.Seal(nil, plaintext, &nonce, &serverPubKey, &clientPrivKey)

	// Output format: [32-byte client public key][24-byte nonce][ciphertext]
	output := append(clientPubKey[:], nonce[:]...)
	output = append(output, ciphertext...)

	// Encode as base64
	encoded := base64.StdEncoding.EncodeToString(output)

	// Wrap at 76 characters per line
	return wrapText(encoded, 76), nil
}

// uploadFile uploads a file to the specified server address without password authentication
func uploadFile(serverAddress string, data io.Reader) error {
	// Ensure server address has http:// prefix
	if !strings.HasPrefix(serverAddress, "http://") && !strings.HasPrefix(serverAddress, "https://") {
		serverAddress = "http://" + serverAddress
	}
	serverURL := serverAddress + "/upload"

	pipeReader, pipeWriter := io.Pipe()
	writer := multipart.NewWriter(pipeWriter)

	startTime = time.Now()

	// Goroutine to write the multipart data
	go func() {
		defer pipeWriter.Close()
		defer writer.Close()

		part, err := writer.CreateFormFile("file", "uploaded_file")
		if err != nil {
			return
		}

		_, err = io.Copy(part, data)
		if err != nil {
			return
		}
	}()

	// Set up SOCKS5 proxy through Tor
	dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	if err != nil {
		return err
	}

	httpTransport := &http.Transport{Dial: dialer.Dial}
	client := &http.Client{Transport: httpTransport}

	// Create HTTP request
	request, err := http.NewRequest("POST", serverURL, pipeReader)
	if err != nil {
		return err
	}

	// Set content type header (no password header needed)
	request.Header.Set("Content-Type", writer.FormDataContentType())

	// Execute the request
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// Check response status
	if response.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(response.Body)
		return fmt.Errorf("server returned status: %s - %s", response.Status, string(responseBody))
	}

	// Print success message
	elapsedTime := time.Since(startTime)
	fmt.Printf("Message sent successfully. Total time: %s\n", formatDuration(elapsedTime))

	// Read and print response body (the "OK" from server)
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(responseBody))

	return nil
}

// loadPublicKeys loads public keys from a PEM file (cross-platform)
func loadPublicKeys(filename string) ([]KeyEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var keys []KeyEntry
	content := string(data)
	
	// Cross-platform line ending normalization
	content = normalizeLineEndings(content)
	
	// Split by empty lines (multiple newlines)
	sections := splitByEmptyLines(content)

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
		
		// Extract PEM data (handle multiple lines)
		pemData := extractPEMData(lines[1:])
		if pemData == "" {
			continue
		}

		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			return nil, fmt.Errorf("invalid PEM format for %s", name)
		}
		
		if block.Type != "X25519 PUBLIC KEY" && block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("unexpected PEM type for %s: %s", name, block.Type)
		}

		if len(block.Bytes) != 32 {
			return nil, fmt.Errorf("public key must be 32 bytes for %s, got %d bytes", name, len(block.Bytes))
		}

		var key [32]byte
		copy(key[:], block.Bytes)

		keys = append(keys, KeyEntry{Name: name, Key: key})
	}

	return keys, nil
}

// normalizeLineEndings handles all line ending types (cross-platform)
func normalizeLineEndings(content string) string {
	// Replace Windows line endings
	content = strings.ReplaceAll(content, "\r\n", "\n")
	// Replace old Mac line endings
	content = strings.ReplaceAll(content, "\r", "\n")
	return content
}

// splitByEmptyLines splits content by multiple newlines
func splitByEmptyLines(content string) []string {
	// Split by two or more newlines
	return strings.Split(content, "\n\n")
}

// extractPEMData extracts PEM data from lines
func extractPEMData(lines []string) string {
	var pemLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			pemLines = append(pemLines, line)
		}
	}
	return strings.Join(pemLines, "\n")
}

// loadMixnodeAddresses loads mixnode addresses from a configuration file (cross-platform)
func loadMixnodeAddresses(filename string) ([]MixnodeEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var mixnodes []MixnodeEntry
	content := string(data)
	
	// Cross-platform line ending normalization
	content = normalizeLineEndings(content)
	
	// Split by empty lines (multiple newlines)
	sections := splitByEmptyLines(content)

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
		addressLine := strings.TrimSpace(lines[1])

		// Parse the address line - take everything after the name
		address := strings.TrimSpace(addressLine)

		mixnodes = append(mixnodes, MixnodeEntry{
			Name:    name,
			Address: address,
		})
	}

	return mixnodes, nil
}

// findPublicKey finds a public key by name
func findPublicKey(keys []KeyEntry, name string) ([32]byte, bool) {
	for _, key := range keys {
		if key.Name == name {
			return key.Key, true
		}
	}
	return [32]byte{}, false
}

// findMixnode finds a mixnode by name
func findMixnode(mixnodes []MixnodeEntry, name string) (MixnodeEntry, bool) {
	for _, mixnode := range mixnodes {
		if mixnode.Name == name {
			return mixnode, true
		}
	}
	return MixnodeEntry{}, false
}

// wrapText wraps text at the specified line length
func wrapText(text string, lineWidth int) string {
	if lineWidth <= 0 {
		return text
	}

	var result strings.Builder
	for i := 0; i < len(text); i += lineWidth {
		end := i + lineWidth
		if end > len(text) {
			end = len(text)
		}
		result.WriteString(text[i:end])
		if end < len(text) {
			result.WriteString("\n")
		}
	}
	return result.String()
}

// formatDuration formats a duration for human-readable output
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if m > 0 {
		return fmt.Sprintf("%d minutes %d seconds", m, s)
	} else {
		return fmt.Sprintf("%d seconds", s)
	}
}
