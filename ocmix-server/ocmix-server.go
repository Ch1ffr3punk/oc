// RAM Mix Server with enhanced security. Memory-optimized
// with constant-time operations and anti-forensics.

package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/proxy"
)

const (
	poolMessageSize   = 131072  // 128KB per message
	maxUploadSize     = 138240  // 135KB max upload
	poolCheckInterval = 60 * time.Second
	maxPoolSize       = 100     // Maximum messages in pool
	timestampInterval = 5 * time.Minute
	paddingMarker     = "PAD||"
	endMarker         = "||END"
	minProcessingTime = 300 * time.Millisecond // Constant-time processing
)

var (
	ownOnionAddress   string
	privateKeyPath    string
	privateKeyLocked  *memguard.LockedBuffer
	poolPassword      *memguard.LockedBuffer
	generateKeyPair   bool
	poolMessages      = make(map[string]*PoolMessage)
	poolMutex         sync.RWMutex
	timingObfuscator  = NewTimingObfuscator(minProcessingTime, 200*time.Millisecond)
)

// PoolMessage with encrypted fields (memory efficient)
type PoolMessage struct {
	OnionAddress []byte // encrypted onion address
	Message      []byte // encrypted message content  
	CreatedAt    []byte // encrypted timestamp
}

// TimingObfuscator ensures constant-time execution
type TimingObfuscator struct {
	minProcessingTime time.Duration
	maxJitter         time.Duration
}

func NewTimingObfuscator(minTime, maxJitter time.Duration) *TimingObfuscator {
	return &TimingObfuscator{
		minProcessingTime: minTime,
		maxJitter:         maxJitter,
	}
}

// Process executes function with timing obfuscation
func (to *TimingObfuscator) Process(fn func()) {
	start := time.Now()
	fn()
	to.obfuscateTiming(start)
}

func (to *TimingObfuscator) obfuscateTiming(start time.Time) {
	elapsed := time.Since(start)
	
	if elapsed < to.minProcessingTime {
		time.Sleep(to.minProcessingTime - elapsed)
	}
	
	jitter := time.Duration(rand.Int63n(int64(to.maxJitter)))
	time.Sleep(jitter)
}

// encryptField encrypts data with random nonce (constant-time operations)
func encryptField(data string, key []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, err
	}
	
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	
	ciphertext := aead.Seal(nil, nonce, []byte(data), nil)
	return append(nonce, ciphertext...), nil
}

// decryptField decrypts data (constant-time operations)
func decryptField(encryptedData []byte, key []byte) (string, error) {
	if len(encryptedData) < 12 {
		return "", errors.New("invalid encrypted data")
	}
	
	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]
	
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	
	return string(plaintext), nil
}

// encryptTime encrypts timestamp efficiently
func encryptTime(t time.Time, key []byte) ([]byte, error) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, uint64(t.UnixNano()))
	return encryptField(string(data), key)
}

// decryptTime decrypts timestamp
func decryptTime(encryptedData []byte, key []byte) (time.Time, error) {
	timeStr, err := decryptField(encryptedData, key)
	if err != nil {
		return time.Time{}, err
	}
	
	if len(timeStr) != 8 {
		return time.Time{}, errors.New("invalid time data length")
	}
	
	nanos := int64(binary.LittleEndian.Uint64([]byte(timeStr)))
	return time.Unix(0, nanos), nil
}

// processMessageConstantTime processes message in constant time regardless of content
func processMessageConstantTime(content []byte) {
	paddedContent := padToConstantSize(content, maxUploadSize)
	simulateCryptoOperations(paddedContent)
}

// padToConstantSize pads data to fixed size for constant-time processing
func padToConstantSize(data []byte, size int) []byte {
	if len(data) >= size {
		return data[:size]
	}
	
	padded := make([]byte, size)
	copy(padded, data)
	return padded
}

// simulateCryptoOperations simulates constant-time cryptographic work
func simulateCryptoOperations(data []byte) {
	workBuffer := make([]byte, 32)
	for i := 0; i < 1000; i++ {
		hash := sha256.Sum256(data)
		copy(workBuffer, hash[:])
	}
}

// addToPoolSecurely adds message with timing protection
func addToPoolSecurely(message []byte, onionAddress string) error {
	var err error
	timingObfuscator.Process(func() {
		err = addToPool(message, onionAddress)
	})
	return err
}

// addToPool adds message to pool (original logic with dummy protection)
func addToPool(message []byte, onionAddress string) error {
	poolMutex.Lock()
	defer poolMutex.Unlock()

	if strings.HasSuffix(strings.ToLower(onionAddress), ".dummy") {
		return nil
	}

	if len(poolMessages) >= maxPoolSize {
		return fmt.Errorf("pool full")
	}

	paddedMessage, err := validateAndPadMessageWithMarker(message)
	if err != nil {
		return fmt.Errorf("message size validation failed: %v", err)
	}

	randomBytes := make([]byte, 8)
	if _, err := cryptorand.Read(randomBytes); err != nil {
		return err
	}
	id := fmt.Sprintf("%x", randomBytes)

	encryptedOnion, err := encryptField(onionAddress, poolPassword.Bytes())
	if err != nil {
		return err
	}

	encryptedMessage, err := encryptField(string(paddedMessage), poolPassword.Bytes())
	if err != nil {
		return err
	}

	createdAt := time.Now()
	encryptedTime, err := encryptTime(createdAt, poolPassword.Bytes())
	if err != nil {
		return err
	}

	poolMsg := &PoolMessage{
		OnionAddress: encryptedOnion,
		Message:      encryptedMessage,
		CreatedAt:    encryptedTime,
	}

	poolMessages[id] = poolMsg
	go scheduleMessageSend(poolMsg, id)
	return nil
}

// validateAndPadMessageWithMarker pads message to fixed size
func validateAndPadMessageWithMarker(data []byte) ([]byte, error) {
	if len(data) > poolMessageSize {
		return nil, fmt.Errorf("message size %d bytes exceeds pool size %d bytes", len(data), poolMessageSize)
	}

	markerOverhead := len(paddingMarker) + len(endMarker)
	availableSpace := poolMessageSize - len(data)

	if availableSpace < markerOverhead {
		return data, nil
	}

	paddingNeeded := availableSpace - markerOverhead
	randomPadding := make([]byte, paddingNeeded)
	if _, err := cryptorand.Read(randomPadding); err != nil {
		return nil, fmt.Errorf("error generating padding: %v", err)
	}

	padded := make([]byte, poolMessageSize)
	copy(padded, data)

	currentPos := len(data)
	copy(padded[currentPos:], []byte(paddingMarker))
	currentPos += len(paddingMarker)
	copy(padded[currentPos:], randomPadding)
	currentPos += len(randomPadding)
	copy(padded[currentPos:], []byte(endMarker))

	return padded, nil
}

// removePaddingWithMarker removes padding from message
func removePaddingWithMarker(data []byte) []byte {
	content := string(data)
	markerIndex := strings.Index(content, paddingMarker)
	if markerIndex == -1 {
		return tryFindMessageBoundary(data)
	}
	return data[:markerIndex]
}

// tryFindMessageBoundary finds message boundary if markers are missing
func tryFindMessageBoundary(data []byte) []byte {
	content := string(data)
	patterns := []string{"\n\n", "\r\n\r\n", "-----END", "====", "\x00\x00"}
	for _, pattern := range patterns {
		if idx := strings.LastIndex(content, pattern); idx != -1 {
			if idx+len(pattern) < len(data) {
				potentialEnd := idx + len(pattern)
				if potentialEnd <= len(data) {
					return data[:potentialEnd]
				}
			}
		}
	}
	if len(data) == poolMessageSize {
		return data
	}
	return data
}

// deleteFromPool removes message from pool
func deleteFromPool(id string) {
	poolMutex.Lock()
	defer poolMutex.Unlock()
	delete(poolMessages, id)
}

// getAllMessages returns all messages from pool
func getAllMessages() (ids []string, msgs []*PoolMessage) {
	poolMutex.RLock()
	defer poolMutex.RUnlock()

	ids = make([]string, 0, len(poolMessages))
	msgs = make([]*PoolMessage, 0, len(poolMessages))

	for id, msg := range poolMessages {
		ids = append(ids, id)
		msgs = append(msgs, msg)
	}
	return
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	timingObfuscator.Process(func() {
		handleUploadInternal(w, r)
	})
}

func handleUploadInternal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAnonymizedResponse(w, "invalid_method")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	err := r.ParseMultipartForm(maxUploadSize)
	if err != nil {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}
	defer file.Close()

	content, err := ioutil.ReadAll(file)
	if err != nil {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	processMessageConstantTime(content)

	if len(content) > maxUploadSize {
		sendAnonymizedResponse(w, "upload_success")
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	if len(decoded) > maxUploadSize {
		sendAnonymizedResponse(w, "upload_success")
		return
	}

	decryptedContent, err := decryptContent(decoded)
	if err != nil {
		sendAnonymizedResponse(w, "decryption_error")
		return
	}
	defer decryptedContent.Destroy()

	decryptedString := string(decryptedContent.Bytes())

	if len(decryptedString) > poolMessageSize {
		sendAnonymizedResponse(w, "upload_success")
		return
	}

	lines := strings.Split(decryptedString, "\n")
	var headers []string
	var messageBody string
	var toHeader string

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			messageBody = strings.Join(lines[i+1:], "\n")
			break
		}
		
		if strings.HasPrefix(strings.ToLower(line), "to:") {
			toHeader = strings.TrimSpace(line[3:])
			if idx := strings.Index(toHeader, " "); idx != -1 {
				toHeader = toHeader[:idx]
			}
		}
		headers = append(headers, line)
	}

	if toHeader == "" {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	newMessage := strings.Join(headers, "\n") + "\n\n" + messageBody

	if len([]byte(newMessage)) > poolMessageSize {
		sendAnonymizedResponse(w, "upload_success")
		return
	}

	err = addToPoolSecurely([]byte(newMessage), toHeader)
	if err != nil {
		sendAnonymizedResponse(w, "upload_success")
		return
	}

	sendAnonymizedResponse(w, "upload_success")
}

// sendAnonymizedResponse sends standardized delayed response
func sendAnonymizedResponse(w http.ResponseWriter, responseType string) {
	delay := time.Duration(rand.Intn(5000)+1000) * time.Millisecond
	time.Sleep(delay)

	response := "OK"

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, response)
}

func scheduleMessageSend(msg *PoolMessage, id string) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	minDelay := 5 * time.Minute
	maxDelay := 20 * time.Minute
	randomDelay := minDelay + time.Duration(rand.Int63n(int64(maxDelay-minDelay)))

	time.Sleep(randomDelay)

	poolMutex.Lock()
	existing, exists := poolMessages[id]
	poolMutex.Unlock()

	if !exists {
		return
	}

	onionAddress, err := decryptField(existing.OnionAddress, poolPassword.Bytes())
	if err != nil {
		deleteFromPool(id)
		return
	}

	cleanOnionAddress := strings.ToLower(onionAddress)
	if strings.HasSuffix(cleanOnionAddress, ".dummy:8080") || 
	   strings.HasSuffix(cleanOnionAddress, ".dummy") {
		deleteFromPool(id)
		return
	}

	if isLoopMessage(existing) {
		deleteFromPool(id)
		return
	}

	if err := sendPoolMessage(existing); err != nil {
		deleteFromPool(id)
		return
	}

	deleteFromPool(id)
}

// isLoopMessage checks if message is addressed back to this server
func isLoopMessage(msg *PoolMessage) bool {
	onionAddress, err := decryptField(msg.OnionAddress, poolPassword.Bytes())
	if err != nil {
		return false
	}
	return strings.Contains(onionAddress, ownOnionAddress) ||
		strings.Contains(onionAddress, "localhost") ||
		strings.Contains(onionAddress, "127.0.0.1")
}

func managePool() {
	ticker := time.NewTicker(poolCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		processPool()
	}
}

func processPool() {
	ids, msgs := getAllMessages()

	if len(msgs) >= maxPoolSize {
		sendEmergencyBatch(ids, msgs)
		return
	}

	if len(msgs) == 0 {
		return
	}

	now := time.Now()
	maxAge := 20 * time.Minute

	for i, msg := range msgs {
		id := ids[i]
		onionAddress, err := decryptField(msg.OnionAddress, poolPassword.Bytes())
		if err != nil {
			deleteFromPool(id)
			continue
		}

		createdAt, err := decryptTime(msg.CreatedAt, poolPassword.Bytes())
		if err != nil {
			continue
		}

		if now.Sub(createdAt) >= maxAge {
			cleanOnionAddress := strings.ToLower(onionAddress)
			if strings.HasSuffix(cleanOnionAddress, ".dummy:8080") || 
			   strings.HasSuffix(cleanOnionAddress, ".dummy") {
				deleteFromPool(id)
			} else if isLoopMessage(msg) {
				deleteFromPool(id)
			} else {
				if err := sendPoolMessage(msg); err != nil {
					deleteFromPool(id)
				} else {
					deleteFromPool(id)
				}
			}
		}
	}
}

func sendEmergencyBatch(ids []string, msgs []*PoolMessage) {
	if len(msgs) == 0 {
		return
	}

	for i := range msgs {
		j := rand.Intn(i + 1)
		msgs[i], msgs[j] = msgs[j], msgs[i]
		ids[i], ids[j] = ids[j], ids[i]
	}

	batchSize := int(float64(len(msgs)) * 0.33)
	if batchSize == 0 {
		batchSize = 1
	}

	sentCount := 0
	for i := 0; i < len(msgs) && sentCount < batchSize; i++ {
		msg := msgs[i]
		id := ids[i]
		onionAddress, err := decryptField(msg.OnionAddress, poolPassword.Bytes())
		if err != nil {
			deleteFromPool(id)
			continue
		}
		
		cleanOnionAddress := strings.ToLower(onionAddress)
		if strings.HasSuffix(cleanOnionAddress, ".dummy:8080") || 
		   strings.HasSuffix(cleanOnionAddress, ".dummy") {
			deleteFromPool(id)
			continue
		}
		
		if err := sendPoolMessage(msg); err != nil {
			deleteFromPool(id)
		} else {
			deleteFromPool(id)
			sentCount++
		}
	}
}

func sendPoolMessage(msg *PoolMessage) error {
	onionAddress, err := decryptField(msg.OnionAddress, poolPassword.Bytes())
	if err != nil {
		return err
	}

	encryptedMessage, err := decryptField(msg.Message, poolPassword.Bytes())
	if err != nil {
		return err
	}

	originalMessage := removePaddingWithMarker([]byte(encryptedMessage))
	_, err = sendToOnionAddress(originalMessage, onionAddress)
	return err
}

func sendToOnionAddress(message []byte, onionAddress string) (string, error) {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return "", err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   60 * time.Second,
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "message.txt")
	if err != nil {
		return "", err
	}
	if _, err := part.Write(message); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	url := fmt.Sprintf("http://%s/upload", onionAddress)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned non-OK status: %d", resp.StatusCode)
	}

	return string(respBody), nil
}

func startCoverTrafficSimulator() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			if shouldSimulateCoverTraffic() {
				go simulateLightCoverTraffic()
			}
		}
	}()
}

func shouldSimulateCoverTraffic() bool {
	poolMutex.RLock()
	currentLoad := len(poolMessages)
	poolMutex.RUnlock()
	
	probability := 0.3
	if currentLoad > maxPoolSize/2 {
		probability = 0.1
	}
	
	return rand.Float64() < probability
}

func simulateLightCoverTraffic() {
	defer func() {
		if r := recover(); r != nil {
		}
	}()
	
	poolMutex.Lock()
	defer poolMutex.Unlock()
	
	_ = len(poolMessages)
}

func decryptContent(content []byte) (*memguard.LockedBuffer, error) {
	if len(content) > maxUploadSize {
		return nil, errors.New("encrypted message too large")
	}
	if len(content) < 32+24 {
		return nil, errors.New("invalid encrypted data length")
	}

	clientPubKey := content[:32]
	nonce := content[32:56]
	ciphertext := content[56:]

	var clientPubKeyArr [32]byte
	var nonceArr [24]byte
	copy(clientPubKeyArr[:], clientPubKey)
	copy(nonceArr[:], nonce)

	serverPrivKey := privateKeyLocked.Bytes()
	var serverPrivKeyArr [32]byte
	copy(serverPrivKeyArr[:], serverPrivKey)

	plaintext, ok := box.Open(nil, ciphertext, &nonceArr, &clientPubKeyArr, &serverPrivKeyArr)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	cleanPlaintext := removeAdaptivePadding(plaintext)
	decryptedLocked := memguard.NewBufferFromBytes(cleanPlaintext)
	return decryptedLocked, nil
}

func removeAdaptivePadding(data []byte) []byte {
	content := string(data)
	const beginMarker = "-----BEGIN PADDING-----"
	const endMarker = "-----END PADDING-----"

	startIdx := strings.Index(content, beginMarker)
	if startIdx == -1 {
		return data
	}

	relativeEndIdx := strings.Index(content[startIdx+len(beginMarker):], endMarker)
	if relativeEndIdx == -1 {
		return data
	}

	endIdx := startIdx + len(beginMarker) + relativeEndIdx
	endOfMarker := endIdx + len(endMarker)

	for endOfMarker < len(content) && strings.ContainsRune(" \t\n\r", rune(content[endOfMarker])) {
		endOfMarker++
	}

	if endOfMarker >= len(content) {
		return []byte{}
	}

	return []byte(content[endOfMarker:])
}

func generateKeyPairFiles() error {
	publicKey, privateKey, err := box.GenerateKey(cryptorand.Reader)
	if err != nil {
		return fmt.Errorf("error generating key pair: %v", err)
	}

	privateKeyFile, err := os.OpenFile("private.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error creating private key file: %v", err)
	}
	defer privateKeyFile.Close()

	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKey[:],
	}
	if err := pem.Encode(privateKeyFile, privateKeyBlock); err != nil {
		return fmt.Errorf("error encoding private key: %v", err)
	}

	publicKeyFile, err := os.OpenFile("public.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("error creating public key file: %v", err)
	}
	defer publicKeyFile.Close()

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey[:],
	}
	if err := pem.Encode(publicKeyFile, publicKeyBlock); err != nil {
		return fmt.Errorf("error encoding public key: %v", err)
	}

	epochTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes("private.pem", epochTime, epochTime)
	os.Chtimes("public.pem", epochTime, epochTime)

	return nil
}

func loadX25519PEM(filename string) (*memguard.LockedBuffer, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pemData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("PEM decoding failed: no PEM block found")
	}
	if len(block.Bytes) != 32 {
		return nil, errors.New("invalid key length")
	}

	lockedBuffer := memguard.NewBufferFromBytes(block.Bytes)
	return lockedBuffer, nil
}

func main() {
	rand.Seed(time.Now().UnixNano())

	flag.StringVar(&privateKeyPath, "s", "", "Path to the private key file")
	flag.BoolVar(&generateKeyPair, "g", false, "Generate key pair")
	flag.Parse()

	if generateKeyPair {
		if err := generateKeyPairFiles(); err != nil {
			log.Fatalf("Error generating key pair: %v", err)
		}
		fmt.Println("Key pair generated: public.pem and private.pem")
		os.Exit(0)
	}

	if privateKeyPath == "" {
		log.Fatal("Please provide private key path with -s")
	}

	var err error
	privateKeyLocked, err = loadX25519PEM(privateKeyPath)
	if err != nil {
		log.Fatalf("Error loading private key: %v", err)
	}
	defer privateKeyLocked.Destroy()
	
	//⚠️ Insert your own Tor Hidden Service Onion address
	ownOnionAddress = "rayvmrv645fln4cmkglfdio4pjwebqotqib7ajpx4mbobbpkdkwgfzad.onion:8080"

	password := make([]byte, 32)
	if _, err := cryptorand.Read(password); err != nil {
		log.Fatalf("Failed to generate pool password: %v", err)
	}
	poolPassword = memguard.NewBufferFromBytes(password)
	defer poolPassword.Destroy()

	startCoverTrafficSimulator()
	go managePool()

	http.HandleFunc("/upload", handleUpload)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
