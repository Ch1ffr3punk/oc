// Onion Courier GUI Mixnet Client
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/proxy"
	"github.com/awnumar/memguard"
)

var startTime time.Time
var statusLabel *widget.Label
var statusScroll *container.Scroll
var textArea *widget.Entry
var chainEntry *widget.Entry
var currentTheme string
var myApp fyne.App
var myWindow fyne.Window

type Config struct {
	PubKeysURL   string `json:"pubkeys_url"`
	MixnodesURL  string `json:"mixnodes_url"`
	ConfigFile   string `json:"config_file"`
	PubKeysFile  string `json:"pubkeys_file"`
	MixnodesFile string `json:"mixnodes_file"`
}

type KeyEntry struct {
	Name string
	Key  [32]byte
}

type MixnodeEntry struct {
	Name    string
	Address string
	Status  string
}

const (
	PaddingHeader  = "-----BEGIN PADDING-----"
	PaddingFooter  = "-----END PADDING-----"
	MaxUserPayload = 20480
	MinTotalSize   = 1024
	MaxTotalSize   = 28672
)

func init() {
	memguard.CatchInterrupt()
	defer memguard.Purge()
}

func wrapText(text string, maxLineLength int) string {
	if len(text) <= maxLineLength {
		return text
	}

	var result strings.Builder
	lines := strings.Split(text, "\n")
	
	for _, line := range lines {
		if len(line) <= maxLineLength {
			result.WriteString(line + "\n")
			continue
		}

		words := strings.Fields(line)
		if len(words) == 0 {
			result.WriteString("\n")
			continue
		}

		currentLine := words[0]
		for _, word := range words[1:] {
			if len(currentLine)+len(word)+1 <= maxLineLength {
				currentLine += " " + word
			} else {
				result.WriteString(currentLine + "\n")
				currentLine = word
			}
		}
		result.WriteString(currentLine + "\n")
	}

	return strings.TrimSpace(result.String())
}

func updateStatus(text string) {
	wrappedText := wrapText(text, 76)
	fyne.Do(func() {
		statusLabel.SetText(wrappedText)
		statusScroll.ScrollToBottom()
	})
}

func appendStatus(text string) {
	currentText := statusLabel.Text
	if currentText != "" {
		currentText += "\n"
	}
	updateStatus(currentText + text)
}

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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func adaptivePadding(message []byte, maxTotalSize int) ([]byte, error) {
	messageSize := len(message)
	
	if messageSize >= maxTotalSize {
		return message, nil
	}

	availableSpace := maxTotalSize - messageSize
	overhead := len(PaddingHeader) + len(PaddingFooter) + 4
	
	if availableSpace <= overhead {
		return message, nil
	}

	maxPaddingSize := availableSpace - overhead
	targetPaddingSize := randInt(maxPaddingSize + 1)

	if targetPaddingSize == 0 && maxPaddingSize > 0 {
		targetPaddingSize = 1
	}

	padding := make([]byte, targetPaddingSize)
	if _, err := rand.Read(padding); err != nil {
		return message, nil
	}

	padded := fmt.Sprintf("%s\n%s\n%s\n%s", 
		PaddingHeader,
		string(padding),
		PaddingFooter,
		string(message))

	return []byte(padded), nil
}

func extractRecipient(message []byte) string {
	lines := strings.SplitN(string(message), "\n", 2)
	if len(lines) > 0 && strings.HasPrefix(lines[0], "To:") {
		return strings.TrimSpace(strings.TrimPrefix(lines[0], "To:"))
	}
	return ""
}

func pingMixnodes() {
	config, err := ensureConfig()
	if err != nil {
		updateStatus(fmt.Sprintf("Error: %v", err))
		return
	}

	mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
	if err != nil {
		updateStatus(fmt.Sprintf("Error loading mix node addresses: %v\nPlease run 'Info' first to download the mix nodes list", err))
		return
	}

	sort.Slice(mixnodes, func(i, j int) bool {
		return strings.ToLower(mixnodes[i].Name) < strings.ToLower(mixnodes[j].Name)
	})

	updateStatus("Checking mix node status via Tor...\n")
	
	resultMap := make(map[string]string)
	resultMutex := &sync.Mutex{}
	resultReady := make(chan string, len(mixnodes))
	
	for i := range mixnodes {
		go func(index int, name string) {
			status := checkNodeStatus(mixnodes[index].Address)
			resultMutex.Lock()
			resultMap[name] = status
			resultMutex.Unlock()
			resultReady <- name
		}(i, mixnodes[i].Name)
	}

	completed := 0
	for completed < len(mixnodes) {
		<-resultReady
		completed++
		
		var currentOutput strings.Builder
		currentOutput.WriteString("Checking mix node status via Tor...\n\n")
		
		resultMutex.Lock()
		for _, node := range mixnodes {
			if status, exists := resultMap[node.Name]; exists {
				currentOutput.WriteString(fmt.Sprintf("%s\t\t\t%s\n", node.Name, status))
			} else {
				currentOutput.WriteString(fmt.Sprintf("%s\t\t\tchecking...\n", node.Name))
			}
		}
		resultMutex.Unlock()
		
		fyne.Do(func() {
			statusLabel.SetText(strings.TrimSpace(currentOutput.String()))
			statusScroll.ScrollToBottom()
		})
		
		time.Sleep(100 * time.Millisecond)
	}
	
	var finalOutput strings.Builder
	finalOutput.WriteString("Checking mix node status via Tor...\n\n")

	resultMutex.Lock()
	for _, node := range mixnodes {
		finalOutput.WriteString(fmt.Sprintf("%s\t\t\t%s\n", node.Name, resultMap[node.Name]))
	}
	resultMutex.Unlock()
	finalOutput.WriteString("\nPing completed!")
	
	updateStatus(finalOutput.String())
}

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

    dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
    if err != nil {
        return "n/a"
    }

    client := &http.Client{
        Transport: &http.Transport{
            Dial: dialer.Dial,
        },
        Timeout: 15 * time.Second,
    }

    body := bytes.NewReader([]byte("ping"))
    req, err := http.NewRequest("POST", testURL, body)
    if err != nil {
        return "n/a"
    }
    req.Header.Set("Content-Type", "application/octet-stream")
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
		return nil, fmt.Errorf("mix nodes file not found: %s\nRun 'Info' first to download configuration", config.MixnodesFile)
	}
	
	return config, nil
}

func downloadConfigurations() string {
	config, err := loadConfig()
	if err != nil {
		return fmt.Sprintf("Error loading config: %v", err)
	}

	if strings.Contains(config.PubKeysURL, "example.com") || strings.Contains(config.MixnodesURL, "example.com") {
		return "WARNING: Configuration uses example URLs. Please edit the config file first:\n" +
			fmt.Sprintf("  %s\n", config.ConfigFile) +
			"\nUpdate the pub keys URL and mix nodes URL with actual URLs."
	}

	result := "Downloading config files via Tor...\n"
	result += fmt.Sprintf("Config directory: %s\n", filepath.Dir(config.ConfigFile))

	if err := os.MkdirAll(filepath.Dir(config.ConfigFile), 0700); err != nil {
		return fmt.Sprintf("Error creating config directory: %v", err)
	}

	if err := downloadFileViaTor(config.PubKeysURL, config.PubKeysFile); err != nil {
		return fmt.Sprintf("Error downloading pub keys: %v", err)
	}
	if err := downloadFileViaTor(config.MixnodesURL, config.MixnodesFile); err != nil {
		return fmt.Sprintf("Error downloading mix nodes: %v", err)
	}
	
	if _, err := os.Stat(config.MixnodesFile); err == nil {
		result += fmt.Sprintf("✓ mix nodes file created: %s\n", config.MixnodesFile)
	}
	if _, err := os.Stat(config.PubKeysFile); err == nil {
		result += fmt.Sprintf("✓ pub keys file created: %s\n", config.PubKeysFile)
	}
	
	result += "Configuration updated successfully!"
	return result
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

func encryptAndUploadRandom() string {
	plaintext := textArea.Text
	if len(plaintext) == 0 {
		return "Error: No message text provided"
	}

	plaintextBuf := memguard.NewBufferFromBytes([]byte(plaintext))
	defer plaintextBuf.Destroy()

	config, err := loadConfig()
	if err != nil {
		return fmt.Sprintf("Error loading configuration: %v", err)
	}

	mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
	if err != nil {
		return fmt.Sprintf("Error loading mix node addresses: %v", err)
	}

	numHops := 2 + randInt(4)

	if len(mixnodes) < numHops {
		return fmt.Sprintf("Not enough mix nodes available. Need %d, have %d", numHops, len(mixnodes))
	}

	selectedNodes := selectRandomNodes(mixnodes, numHops)
	var nodeNames []string
	for _, node := range selectedNodes {
		nodeNames = append(nodeNames, node.Name)
	}

	return encryptAndUpload(nodeNames, plaintextBuf.Bytes(), config)
}

func sendDummyTraffic() string {
    config, err := loadConfig()
    if err != nil {
        return fmt.Sprintf("Error loading configuration: %v", err)
    }

    mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
    if err != nil {
        return fmt.Sprintf("Error loading mix node addresses: %v", err)
    }

    if len(mixnodes) < 1 {
        return "No mix nodes available for cover traffic"
    }

    err = sendSingleDummyMessage(config, mixnodes, 1)
    if err != nil {
        return fmt.Sprintf("Error sending cover message: %v", err)
    }
    
    return "Cover message sent successfully!"
}

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
	
	sizeRange := maxSize - minSize + 1
	if sizeRange <= 0 {
		sizeRange = 1
	}
	payloadSize := randInt(sizeRange) + minSize
	
	if payloadSize > MaxUserPayload {
		payloadSize = MaxUserPayload
	}
	if payloadSize < minSize {
		payloadSize = minSize
	}

	dummyPayload := generateRandomPayload(payloadSize)
	dummyRecipient := fmt.Sprintf("%s.dummy", nodeNames[len(nodeNames)-1])
	dummyMessageContent := fmt.Sprintf("To: %s\n\n%s", dummyRecipient, string(dummyPayload))

	dummyMessage, err := createDummyMessage(nodeNames, dummyMessageContent, mixnodes, config)
	if err != nil {
		return err
	}

	firstNode := selectedNodes[0]
	return uploadFile(firstNode.Address, strings.NewReader(dummyMessage))
}

func createDummyMessage(nodeNames []string, payload string, mixnodes []MixnodeEntry, config *Config) (string, error) {
	pubKeys, err := loadPublicKeys(config.PubKeysFile)
	if err != nil {
		return "", err
	}

	const encryptionOverhead = 56
	currentMessage := []byte(payload)
	
	for i := len(nodeNames) - 1; i >= 0; i-- {
		name := strings.TrimSpace(nodeNames[i])
		pubKey, found := findPublicKey(pubKeys, name)
		if !found {
			return "", fmt.Errorf("public key not found for: %s", name)
		}

		maxPayloadSize := MaxTotalSize - encryptionOverhead
		
		var routingHeader []byte
		if i > 0 {
			currentNodeName := strings.TrimSpace(nodeNames[i])
			currentMixnode, found := findMixnode(mixnodes, currentNodeName)
			if !found {
				return "", fmt.Errorf("mixnode not found: %s", currentNodeName)
			}
			routingHeader = []byte("To: " + currentMixnode.Address + "\n\n")
			maxPayloadSize -= len(routingHeader)
		}

		var payloadToEncrypt []byte
		if i == len(nodeNames)-1 {
			paddedPayload, err := adaptivePadding(currentMessage, maxPayloadSize)
			if err != nil {
				paddedPayload = currentMessage
			}
			if len(paddedPayload) > maxPayloadSize {
				paddedPayload = paddedPayload[:maxPayloadSize]
			}
			payloadToEncrypt = paddedPayload
		} else {
			payloadToEncrypt = append(routingHeader, currentMessage...)
		}

		encryptedData, err := encryptMessageRaw(payloadToEncrypt, pubKey)
		if err != nil {
			return "", err
		}

		if i == 0 {
			currentMessage = append(routingHeader, encryptedData...)
		} else {
			currentMessage = encryptedData
		}
	}

	return string(currentMessage), nil
}

func encryptAndUploadManual() string {
	namesArg := chainEntry.Text
	plaintext := textArea.Text
	
	if len(plaintext) == 0 {
		return "Error: No message text provided"
	}
	if len(namesArg) == 0 {
		return "Error: No node chain provided"
	}

	plaintextBuf := memguard.NewBufferFromBytes([]byte(plaintext))
	defer plaintextBuf.Destroy()

	config, err := loadConfig()
	if err != nil {
		return fmt.Sprintf("Error loading config: %v", err)
	}

	names := strings.Split(namesArg, ",")
	if len(names) == 0 {
		return "Error: No node names provided"
	}

	if hasDuplicates(names) {
		return "Error: Duplicate node names not allowed"
	}

	return encryptAndUpload(names, plaintextBuf.Bytes(), config)
}

func selectRandomNodes(mixnodes []MixnodeEntry, count int) []MixnodeEntry {
	nodes := make([]MixnodeEntry, len(mixnodes))
	copy(nodes, mixnodes)
	
	for i := len(nodes) - 1; i > 0; i-- {
		j := randInt(i + 1)
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
	return nodes[:count]
}

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

func findMixnode(mixnodes []MixnodeEntry, name string) (MixnodeEntry, bool) {
	cleanName := strings.TrimSpace(name)
	for _, m := range mixnodes {
		if strings.TrimSpace(m.Name) == cleanName {
			return m, true
		}
	}
	return MixnodeEntry{}, false
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := d / time.Minute
	s := (d - m*time.Minute) / time.Second
	if m > 0 {
		return fmt.Sprintf("%d min %d sec", m, s)
	}
	return fmt.Sprintf("%d sec", s)
}

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

    body := bytes.NewReader(messageData)

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
    req.Header.Set("Content-Type", "application/octet-stream")
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

    return nil
}

func encryptAndUpload(names []string, plaintext []byte, config *Config) string {
    startTime = time.Now()

    if len(plaintext) > MaxUserPayload {
        return fmt.Sprintf("ERROR: Payload too large: %d bytes (maximum: %d bytes)", len(plaintext), MaxUserPayload)
    }

    pubKeys, err := loadPublicKeys(config.PubKeysFile)
    if err != nil {
        return fmt.Sprintf("Error loading public keys: %v", err)
    }

    mixnodes, err := loadMixnodeAddresses(config.MixnodesFile)
    if err != nil {
        return fmt.Sprintf("Error loading mix nodes: %v", err)
    }

    for _, name := range names {
        if _, found := findMixnode(mixnodes, name); !found {
            return fmt.Sprintf("ERROR: mix node '%s' not found", name)
        }
        if _, found := findPublicKey(pubKeys, name); !found {
            return fmt.Sprintf("ERROR: Public key for '%s' not found", name)
        }
    }

    finalRecipient := extractRecipient(plaintext)
    if finalRecipient == "" {
        return "Invalid message format: missing 'To:' header"
    }

    const encryptionOverhead = 56
    currentMessage := plaintext

    for i := len(names) - 1; i >= 0; i-- {
        currentNodeName := strings.TrimSpace(names[i])
        pubKey, found := findPublicKey(pubKeys, currentNodeName)
        if !found {
            return fmt.Sprintf("FATAL: Public key not found for: %s", currentNodeName)
        }

        var nextHop string
        var routingHeader []byte
        
        if i == len(names)-1 {
            nextHop = finalRecipient
            routingHeader = []byte("To: " + nextHop + "\n\n")
        } else {
            nextNodeName := strings.TrimSpace(names[i+1])
            nextMixnode, found := findMixnode(mixnodes, nextNodeName)
            if !found {
                return fmt.Sprintf("FATAL: Next mix node not found: %s", nextNodeName)
            }
            nextHop = nextMixnode.Address
            routingHeader = []byte("To: " + nextHop + "\n\n")
        }

        maxPlaintextSize := MaxTotalSize - encryptionOverhead
        
        if i > 0 {
            maxPlaintextSize -= len(routingHeader)
        }

        var payloadToEncrypt []byte
        
        if i == len(names)-1 {
            paddedMsg, err := adaptivePadding(currentMessage, maxPlaintextSize)
            if err != nil {
                paddedMsg = currentMessage
            }
            if len(paddedMsg) > maxPlaintextSize {
                paddedMsg = paddedMsg[:maxPlaintextSize]
            }
            payloadToEncrypt = paddedMsg
        } else {
            payloadToEncrypt = append(routingHeader, currentMessage...)
        }

        encryptedLayer, err := encryptMessageRaw(payloadToEncrypt, pubKey)
        if err != nil {
            return fmt.Sprintf("Encryption error for node %s: %v", currentNodeName, err)
        }

        if i == 0 {
            currentMessage = append(routingHeader, encryptedLayer...)
        } else {
            currentMessage = encryptedLayer
        }
    }

    firstNodeName := strings.TrimSpace(names[0])
    firstMixnode, found := findMixnode(mixnodes, firstNodeName)
    if !found {
        return fmt.Sprintf("ERROR: First mix node not found: %s", firstNodeName)
    }

    if err := uploadFile(firstMixnode.Address, bytes.NewReader(currentMessage)); err != nil {
        return fmt.Sprintf("Upload failed: %v", err)
    }

    elapsed := time.Since(startTime)
    return fmt.Sprintf("Message sent successfully. Time: %s", formatDuration(elapsed))
}

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

func secureClear() {
	if textArea.Text != "" {
		textBuf := memguard.NewBufferFromBytes([]byte(textArea.Text))
		defer textBuf.Destroy()
		textBuf.Melt()
		textBuf.Wipe()
		
		fyne.Do(func() {
			textArea.SetText("")
		})
	}

	if chainEntry.Text != "" {
		chainBuf := memguard.NewBufferFromBytes([]byte(chainEntry.Text))
		defer chainBuf.Destroy()
		chainBuf.Melt()
		chainBuf.Wipe()
		
		fyne.Do(func() {
			chainEntry.SetText("")
		})
	}

	updateStatus("Text fields securely cleared. All sensitive data wiped from memory.")
}

func toggleTheme() {
	if currentTheme == "dark" {
		myApp.Settings().SetTheme(theme.LightTheme())
		currentTheme = "light"
	} else {
		myApp.Settings().SetTheme(theme.DarkTheme())
		currentTheme = "dark"
	}
}

func showInfo() {
	go func() {
		result := downloadConfigurations()
		updateStatus(result)
	}()
}

func showPing() {
	go func() {
		pingMixnodes()
	}()
}

func sendRandom() {
	go func() {
		result := encryptAndUploadRandom()
		updateStatus(result)
	}()
}

func sendManual() {
	go func() {
		result := encryptAndUploadManual()
		updateStatus(result)
	}()
}

func sendCover() {
	go func() {
		result := sendDummyTraffic()
		updateStatus(result)
	}()
}

func createGUI() fyne.CanvasObject {
	themeButton := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), toggleTheme)
	themeButton.Importance = widget.LowImportance

	infoButton := widget.NewButton("Info", showInfo)
	pingButton := widget.NewButton("Ping", showPing)
	coverButton := widget.NewButton("Cover", sendCover)
	
	topButtons := container.NewHBox(
		layout.NewSpacer(),
		infoButton,
		pingButton,
		coverButton,
		layout.NewSpacer(),
		themeButton,
	)

	textArea = widget.NewMultiLineEntry()
	textArea.SetPlaceHolder("Enter your message here...")
	textArea.Wrapping = fyne.TextWrapWord
	textArea.SetMinRowsVisible(15)
	textArea.TextStyle = fyne.TextStyle{Monospace: true}

	chainLabel := widget.NewLabel("Chain:")
	chainEntry = widget.NewEntry()
	chainEntry.SetPlaceHolder("Enter mix node chain (comma-separated, e.g., node1,node2,node3)")
	chainEntry.Wrapping = fyne.TextTruncate
	chainContainer := container.NewBorder(nil, nil, chainLabel, nil, chainEntry)

	randomButton := widget.NewButton("Random", sendRandom)
	sendButton := widget.NewButton("Send", sendManual)
	clearButton := widget.NewButton("Clear", secureClear)
	
	bottomButtons := container.NewHBox(
		layout.NewSpacer(),
		randomButton,
		sendButton,
		clearButton,
		layout.NewSpacer(),
	)

	statusLabel = widget.NewLabel("Ready to send secure messages...")
	statusLabel.Wrapping = fyne.TextWrapWord
	statusScroll = container.NewScroll(statusLabel)
	statusScroll.SetMinSize(fyne.NewSize(0, 60))

	content := container.NewBorder(
		topButtons,
		container.NewVBox(
			chainContainer,
			bottomButtons,
			statusScroll,
		),
		nil,
		nil,
		textArea,
	)

	return content
}

func main() {
	startTime = time.Now()
	
	myApp = app.NewWithID("ocmix.client")
	myWindow = myApp.NewWindow("Onion Courie Mixnet Client")
	myWindow.Resize(fyne.NewSize(800, 600))

	currentTheme = "dark"
	myApp.Settings().SetTheme(theme.DarkTheme())

	content := createGUI()
	myWindow.SetContent(content)

	myWindow.ShowAndRun()
	memguard.Purge()
}
