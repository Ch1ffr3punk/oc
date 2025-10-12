// Onion Courier Tor Hidden Service Mixnet Server
package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

// Constants
const (
	PoolMessageSize   = 32768   // 32 KB - Unified size for all pool messages
	maxUploadSize     = 28672   // 28 KB (fixed size)
	poolCheckInterval = 60 * time.Second
	maxPoolSize       = 400
	minProcessingTime = 300 * time.Millisecond
	PaddingHeader     = "-----BEGIN PADDING-----"
	PaddingFooter     = "-----END PADDING-----"
	MixnodePort       = "8080"
	FinalRecipientPort = "8088"
	// Batch processing constants
	batchMinSize       = 5
	batchMaxSize       = 15
	batchTimeout       = 3 * time.Minute
	batchFlushInterval = 30 * time.Second
)

// Global variables
var (
	ownOnionAddress   string
	privateKeyPath    string
	privateKeyLocked  *memguard.LockedBuffer
	generateKeyPair   bool
	poolMessages      = make([]*EncryptedMessage, 0)
	poolMutex         sync.RWMutex
	timingObfuscator  = NewTimingObfuscator(minProcessingTime, 200*time.Millisecond)
	// Security features
	replayCache   *cache.Cache
	globalLimiter = rate.NewLimiter(rate.Every(100*time.Millisecond), 5)
	ipLimiters    = cache.New(30*time.Minute, 5*time.Minute)
	keyManager    *KeyManager
	// Pool statistics
	poolStats struct {
		maxMessagesSeen int
		lastShrinkTime  time.Time
		shrinkCount     int
	}
	poolStatsMutex sync.RWMutex
	// Batch processing system
	batchProcessor *BatchProcessor
)

// EncryptedMessage - Contains encrypted message data
type EncryptedMessage struct {
	data []byte // Always exactly PoolMessageSize after encryption and padding
}

// BatchProcessor handles batch processing for better anonymity
type BatchProcessor struct {
	batchMutex     sync.RWMutex
	currentBatch   []*EncryptedMessage
	batchTimer     *time.Timer
	batchCreated   time.Time
	flushTicker    *time.Ticker
	shuffleEnabled bool
}

// KeyManager handles forward secrecy with key rotation
type KeyManager struct {
	currentKey    *memguard.LockedBuffer
	nextKey       *memguard.LockedBuffer
	keyMutex      sync.RWMutex
	rotationTimer *time.Timer
}

// TimingObfuscator ensures constant-time execution
type TimingObfuscator struct {
	minProcessingTime time.Duration
	maxJitter         time.Duration
}

// RoutingInfo contains parsed routing information from message headers
type RoutingInfo struct {
	nextHop   string
	isMixnode bool
}

// NewTimingObfuscator creates a new timing obfuscator
func NewTimingObfuscator(minTime, maxJitter time.Duration) *TimingObfuscator {
	return &TimingObfuscator{
		minProcessingTime: minTime,
		maxJitter:         maxJitter,
	}
}

// Process executes a function with timing obfuscation
func (to *TimingObfuscator) Process(fn func()) {
	start := time.Now()
	fn()
	to.obfuscateTiming(start)
}

// obfuscateTiming ensures constant execution time with jitter
func (to *TimingObfuscator) obfuscateTiming(start time.Time) {
	elapsed := time.Since(start)
	if elapsed < to.minProcessingTime {
		time.Sleep(to.minProcessingTime - elapsed)
	}
	jitterNanos, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(to.maxJitter)))
	if err != nil {
		jitterNanos = big.NewInt(int64(to.maxJitter / 2))
	}
	jitter := time.Duration(jitterNanos.Int64())
	time.Sleep(jitter)
}

// Initialize security features
func initSecurity() {
	replayCache = cache.New(30*time.Minute, 5*time.Minute)
}

// Initialize batch processor
func initBatchProcessor() {
	batchProcessor = &BatchProcessor{
		currentBatch:   make([]*EncryptedMessage, 0),
		shuffleEnabled: true,
	}
	batchProcessor.flushTicker = time.NewTicker(batchFlushInterval)
	go batchProcessor.regularBatchFlusher()
}

// initKeyManager initializes forward secrecy key management
func initKeyManager() {
	keyManager = &KeyManager{}
	keyManager.rotateKeys()
	keyManager.rotationTimer = time.AfterFunc(12*time.Hour, func() {
		keyManager.rotateKeys()
		keyManager.rotationTimer.Reset(12 * time.Hour)
	})
}

// rotateKeys rotates encryption keys for forward secrecy
func (km *KeyManager) rotateKeys() {
	km.keyMutex.Lock()
	defer km.keyMutex.Unlock()

	newKey := make([]byte, 32)
	if _, err := cryptorand.Read(newKey); err != nil {
		return
	}

	if km.currentKey != nil {
		if km.nextKey != nil {
			km.nextKey.Destroy()
		}
		km.nextKey = km.currentKey
	}

	km.currentKey = memguard.NewBufferFromBytes(newKey)
}

// encryptMessage symmetrically encrypts data using the current key
func (km *KeyManager) encryptMessage(data []byte) ([]byte, error) {
	km.keyMutex.RLock()
	defer km.keyMutex.RUnlock()
	if km.currentKey == nil {
		return nil, errors.New("no encryption key available")
	}
	nonce := make([]byte, 12)
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(km.currentKey.Bytes())
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

// decryptMessage decrypts data with current or next key (forward secrecy)
func (km *KeyManager) decryptMessage(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 12 {
		return nil, errors.New("invalid encrypted data")
	}
	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]
	km.keyMutex.RLock()
	currentKey := km.currentKey
	nextKey := km.nextKey
	km.keyMutex.RUnlock()
	if currentKey != nil {
		aead, err := chacha20poly1305.New(currentKey.Bytes())
		if err == nil {
			if plaintext, err := aead.Open(nil, nonce, ciphertext, nil); err == nil {
				return plaintext, nil
			}
		}
	}
	if nextKey != nil {
		aead, err := chacha20poly1305.New(nextKey.Bytes())
		if err == nil {
			if plaintext, err := aead.Open(nil, nonce, ciphertext, nil); err == nil {
				return plaintext, nil
			}
		}
	}
	return nil, errors.New("decryption failed with all keys")
}

// generateMessageID generates a message ID for replay protection
func generateMessageID() []byte {
	id := make([]byte, 16)
	if _, err := cryptorand.Read(id); err != nil {
		timestamp := make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))
		hash := sha256.Sum256(timestamp)
		id = hash[:16]
	}
	return id
}

// generateMessageIDFromEncrypted creates an ID from the encrypted content for replay protection
func generateMessageIDFromEncrypted(encryptedContent []byte) []byte {
	hash := sha256.Sum256(encryptedContent)
	return hash[:16]
}

// isReplay checks if message has been seen before
func isReplay(encryptedContent []byte) bool {
	id := generateMessageIDFromEncrypted(encryptedContent)
	_, found := replayCache.Get(string(id))
	return found
}

// markAsSeen marks message as processed
func markAsSeen(encryptedContent []byte) {
	id := generateMessageIDFromEncrypted(encryptedContent)
	replayCache.Set(string(id), true, cache.DefaultExpiration)
}

// getIPLimiter gets or creates a rate limiter for an IP address
func getIPLimiter(ip string) *rate.Limiter {
	limiter, found := ipLimiters.Get(ip)
	if found {
		return limiter.(*rate.Limiter)
	}
	newLimiter := rate.NewLimiter(rate.Every(30*time.Second), 30)
	ipLimiters.Set(ip, newLimiter, cache.DefaultExpiration)
	return newLimiter
}

// ensureExactSize ensures data is exactly targetSize bytes
func ensureExactSize(data []byte, targetSize int) ([]byte, error) {
	if len(data) == targetSize {
		return data, nil
	}

	result := make([]byte, targetSize)

	if len(data) > targetSize {
		// Data too large - use first targetSize bytes
		copy(result, data[:targetSize])
	} else {
		// Data too small - pad with random data
		copy(result, data)
		remaining := targetSize - len(data)
		if remaining > 0 {
			randomPadding := make([]byte, remaining)
			if _, err := cryptorand.Read(randomPadding); err != nil {
				hash := sha256.Sum256(data)
				for i := 0; i < remaining; i++ {
					randomPadding[i] = hash[i%32]
				}
			}
			copy(result[len(data):], randomPadding)
		}
	}
	return result, nil
}

// serializeMessageForPool serializes message for the pool with exact size
func serializeMessageForPool(onionAddress string, message []byte, sendTime time.Time) ([]byte, error) {
	// Calculate total available size after encryption
	encryptionOverhead := 28 // 12 nonce + 16 auth tag
	targetSerializedSize := PoolMessageSize - encryptionOverhead

	// Serialize message
	data := make([]byte, 0)
	originalData := make([]byte, 0)

	// Add message ID (16 bytes)
	messageID := generateMessageID()
	originalData = append(originalData, messageID...)

	// Add timestamp (8 bytes)
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(sendTime.UnixNano()))
	originalData = append(originalData, timestampBytes...)

	// Add onion address
	addrBytes := []byte(onionAddress)
	addrLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(addrLen, uint32(len(addrBytes)))
	originalData = append(originalData, addrLen...)
	originalData = append(originalData, addrBytes...)

	// Add message
	msgLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgLen, uint32(len(message)))
	originalData = append(originalData, msgLen...)
	originalData = append(originalData, message...)

	// Add length prefix
	lengthPrefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthPrefix, uint32(len(originalData)))
	data = append(data, lengthPrefix...)
	data = append(data, originalData...)

	// Pad to exact target size (before encryption)
	return ensureExactSize(data, targetSerializedSize)
}

// deserializeMessageFromPool deserializes message from pool data
func deserializeMessageFromPool(paddedData []byte) (string, []byte, time.Time, []byte, error) {
	// Remove strict size check - encrypted data size can vary due to encryption
	// Just ensure we have enough data to work with
	if len(paddedData) < 50 { // Minimum size for basic headers
		return "", nil, time.Time{}, nil, errors.New("data too short for deserialization")
	}

	// Find actual message end by looking for length prefix
	if len(paddedData) < 4 {
		return "", nil, time.Time{}, nil, errors.New("data too short")
	}

	originalLen := int(binary.LittleEndian.Uint32(paddedData[:4]))
	if originalLen > 0 && originalLen <= len(paddedData)-4 {
		// Valid length prefix found - use it
		paddedData = paddedData[4 : 4+originalLen]
	} else {
		// Length prefix invalid, try to find message end by scanning for zeros
		for i := 0; i < len(paddedData)-32; i++ {
			if paddedData[i] == 0 && i > 64 {
				zeroCount := 0
				for j := i; j < len(paddedData); j++ {
					if paddedData[j] == 0 {
						zeroCount++
					}
				}
				if zeroCount > len(paddedData)-i-10 {
					paddedData = paddedData[:i]
					break
				}
			}
		}
	}

	// Parse deserialized data
	if len(paddedData) < 16+8 {
		return "", nil, time.Time{}, nil, errors.New("data too short for parsing")
	}

	messageID := make([]byte, 16)
	copy(messageID, paddedData[:16])
	pos := 16

	timestamp := int64(binary.LittleEndian.Uint64(paddedData[pos : pos+8]))
	sendTime := time.Unix(0, timestamp)
	pos += 8

	if pos+4 > len(paddedData) {
		return "", nil, time.Time{}, nil, errors.New("invalid address length")
	}
	addrLen := int(binary.LittleEndian.Uint32(paddedData[pos : pos+4]))
	pos += 4

	if pos+addrLen > len(paddedData) {
		return "", nil, time.Time{}, nil, errors.New("invalid address data")
	}
	onionAddress := string(paddedData[pos : pos+addrLen])
	pos += addrLen

	if pos+4 > len(paddedData) {
		return "", nil, time.Time{}, nil, errors.New("invalid message length")
	}
	msgLen := int(binary.LittleEndian.Uint32(paddedData[pos : pos+4]))
	pos += 4

	if pos+msgLen > len(paddedData) {
		return "", nil, time.Time{}, nil, errors.New("invalid message data")
	}
	message := make([]byte, msgLen)
	copy(message, paddedData[pos:pos+msgLen])

	return onionAddress, message, sendTime, messageID, nil
}

// parseBinaryRoutingInfo parses routing information from message headers
func parseBinaryRoutingInfo(message []byte) (*RoutingInfo, []byte, error) {
	// Try Unix LF separator first
	if idx := bytes.Index(message, []byte{0x0A, 0x0A}); idx != -1 {
		headerSection := message[:idx]
		if !bytes.HasPrefix(headerSection, []byte("To:")) {
			return nil, nil, errors.New("missing To: header")
		}

		toLineEnd := bytes.IndexByte(headerSection, 0x0A)
		if toLineEnd == -1 {
			toLineEnd = len(headerSection)
		}

		nextHop := string(bytes.TrimSpace(headerSection[3:toLineEnd]))
		bodyStart := idx + 2

		if bodyStart >= len(message) {
			return nil, nil, errors.New("empty message body")
		}

		return &RoutingInfo{
			nextHop:   nextHop,
			isMixnode: isMixnodeDestination(nextHop),
		}, message[bodyStart:], nil
	}

	// Try Windows CRLF separator
	if idx := bytes.Index(message, []byte{0x0D, 0x0A, 0x0D, 0x0A}); idx != -1 {
		headerSection := message[:idx]
		if !bytes.HasPrefix(headerSection, []byte("To:")) {
			return nil, nil, errors.New("missing To: header")
		}

		toLineEnd := bytes.IndexByte(headerSection, 0x0A)
		if toLineEnd == -1 {
			toLineEnd = len(headerSection)
		}

		nextHop := string(bytes.TrimSpace(headerSection[3:toLineEnd]))
		bodyStart := idx + 4

		if bodyStart >= len(message) {
			return nil, nil, errors.New("empty message body")
		}

		return &RoutingInfo{
			nextHop:   nextHop,
			isMixnode: isMixnodeDestination(nextHop),
		}, message[bodyStart:], nil
	}

	return nil, nil, errors.New("no header-body separator found")
}

// isMixnodeDestination checks if destination is a mixnode
func isMixnodeDestination(toHeader string) bool {
	return strings.Contains(toHeader, ":"+MixnodePort)
}

// Remove padding markers from decrypted messages
func removePaddingMarkers(paddedMessage []byte) []byte {
	footer := []byte(PaddingFooter)
	footerIdx := bytes.Index(paddedMessage, footer)
	if footerIdx == -1 {
		return paddedMessage
	}
	start := footerIdx + len(footer)
	for start < len(paddedMessage) && isWhitespace(paddedMessage[start]) {
		start++
	}
	if start >= len(paddedMessage) {
		return paddedMessage
	}
	return paddedMessage[start:]
}

// isWhitespace checks if byte is whitespace
func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// processMessageConstantTime processes message with constant timing
func processMessageConstantTime(content []byte) {
	paddedContent := padToConstantSize(content, maxUploadSize)
	simulateCryptoOperations(paddedContent)
}

// padToConstantSize pads data to constant size for timing protection
func padToConstantSize(data []byte, size int) []byte {
	if len(data) >= size {
		return data[:size]
	}
	padded := make([]byte, size)
	copy(padded, data)
	return padded
}

// simulateCryptoOperations simulates cryptographic operations for timing consistency
func simulateCryptoOperations(data []byte) {
	workBuffer := make([]byte, 32)
	for i := 0; i < 1000; i++ {
		hash := sha256.Sum256(data)
		copy(workBuffer, hash[:])
	}
}

// simulateDecryptionTime ensures constant-time responses
func simulateDecryptionTime() {
	time.Sleep(2 * time.Millisecond)
}

// secureRandomDuration generates cryptographically secure random duration
func secureRandomDuration(min, max time.Duration) time.Duration {
	minNanos := min.Nanoseconds()
	maxNanos := max.Nanoseconds()
	if minNanos >= maxNanos {
		return min
	}
	rangeNanos := maxNanos - minNanos
	randomNanos, err := cryptorand.Int(cryptorand.Reader, big.NewInt(rangeNanos))
	if err != nil {
		return time.Duration((minNanos + maxNanos) / 2)
	}
	return time.Duration(minNanos + randomNanos.Int64())
}

// updatePoolStatsOnAdd updates pool statistics when adding messages
func updatePoolStatsOnAdd() {
	poolStatsMutex.Lock()
	defer poolStatsMutex.Unlock()
	currentLen := len(poolMessages)
	if currentLen > poolStats.maxMessagesSeen {
		poolStats.maxMessagesSeen = currentLen
	}
}

// shrinkPoolIfNeeded shrinks pool capacity if it's too large
func shrinkPoolIfNeeded() {
	poolMutex.Lock()
	defer poolMutex.Unlock()
	currentLen := len(poolMessages)
	currentCap := cap(poolMessages)
	shouldShrink := currentCap > currentLen*2 &&
		time.Since(poolStats.lastShrinkTime) > 10*time.Minute &&
		currentLen < maxPoolSize/2
	if shouldShrink {
		newCap := currentLen + currentLen/2
		if newCap < 10 {
			newCap = 10
		}
		newPool := make([]*EncryptedMessage, currentLen, newCap)
		copy(newPool, poolMessages)
		poolMessages = newPool
		poolStatsMutex.Lock()
		poolStats.lastShrinkTime = time.Now()
		poolStats.shrinkCount++
		poolStatsMutex.Unlock()
	}
}

// fisherYatesShuffle securely shuffles messages using crypto/rand
func fisherYatesShuffle(messages []*EncryptedMessage) error {
	for i := len(messages) - 1; i > 0; i-- {
		jBig, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(jBig.Int64())
		messages[i], messages[j] = messages[j], messages[i]
	}
	return nil
}

// shuffleMessages reorders messages in the pool for traffic analysis resistance
func shuffleMessages() error {
	poolMutex.Lock()
	defer poolMutex.Unlock()
	if len(poolMessages) < 2 {
		return nil
	}
	return fisherYatesShuffle(poolMessages)
}

// AddToBatch adds a message to the current batch and processes if batch is full
func (bp *BatchProcessor) AddToBatch(message *EncryptedMessage) error {
	bp.batchMutex.Lock()
	defer bp.batchMutex.Unlock()
	bp.currentBatch = append(bp.currentBatch, message)
	if len(bp.currentBatch) == 1 {
		bp.batchCreated = time.Now()
		if bp.batchTimer != nil {
			bp.batchTimer.Stop()
		}
		bp.batchTimer = time.AfterFunc(batchTimeout, bp.flushBatch)
	}
	if len(bp.currentBatch) >= batchMinSize {
		return bp.processBatch()
	}
	return nil
}

// processBatch processes the current batch of messages
func (bp *BatchProcessor) processBatch() error {
	if len(bp.currentBatch) < batchMinSize {
		return errors.New("batch too small for processing")
	}
	if bp.shuffleEnabled {
		if err := fisherYatesShuffle(bp.currentBatch); err != nil {
			// Log error but continue processing
		}
	}
	for _, msg := range bp.currentBatch {
		poolMutex.Lock()
		if len(poolMessages) < maxPoolSize {
			poolMessages = append(poolMessages, msg)
			updatePoolStatsOnAdd()
		}
		poolMutex.Unlock()
		minDelay := 5 * time.Minute
		maxDelay := 20 * time.Minute
		randomDelay := secureRandomDuration(minDelay, maxDelay)
		go scheduleIndividualMessage(msg.data, randomDelay)
	}
	bp.currentBatch = make([]*EncryptedMessage, 0)
	if bp.batchTimer != nil {
		bp.batchTimer.Stop()
		bp.batchTimer = nil
	}
	return nil
}

// flushBatch processes the current batch regardless of size (timeout or manual flush)
func (bp *BatchProcessor) flushBatch() {
	bp.batchMutex.Lock()
	defer bp.batchMutex.Unlock()
	if len(bp.currentBatch) > 0 {
		if bp.shuffleEnabled {
			fisherYatesShuffle(bp.currentBatch)
		}
		for _, msg := range bp.currentBatch {
			poolMutex.Lock()
			if len(poolMessages) < maxPoolSize {
				poolMessages = append(poolMessages, msg)
				updatePoolStatsOnAdd()
			}
			poolMutex.Unlock()
			minDelay := 5 * time.Minute
			maxDelay := 20 * time.Minute
			randomDelay := secureRandomDuration(minDelay, maxDelay)
			go scheduleIndividualMessage(msg.data, randomDelay)
		}
		bp.currentBatch = make([]*EncryptedMessage, 0)
		bp.batchTimer = nil
	}
}

// regularBatchFlusher periodically flushes batches to prevent long delays
func (bp *BatchProcessor) regularBatchFlusher() {
	for range bp.flushTicker.C {
		bp.flushBatch()
	}
}

// addToPoolSecurely adds message to pool with timing obfuscation
func addToPoolSecurely(message []byte, onionAddress string) error {
	var err error
	timingObfuscator.Process(func() {
		err = addToPool(message, onionAddress)
	})
	return err
}

// addToPool adds message to the processing pool
func addToPool(message []byte, onionAddress string) error {
	if len(message) > PoolMessageSize {
		return fmt.Errorf("message size exceeds pool size: %d > %d", len(message), PoolMessageSize)
	}

	minDelay := 5 * time.Minute
	maxDelay := 20 * time.Minute
	randomDelay := secureRandomDuration(minDelay, maxDelay)
	sendTime := time.Now().Add(randomDelay)

	// Serialize message to exact PoolMessageSize
	serializedData, err := serializeMessageForPool(onionAddress, message, sendTime)
	if err != nil {
		return err
	}

	// Encrypt the serialized data
	encryptedData, err := keyManager.encryptMessage(serializedData)
	if err != nil {
		return err
	}

	// Ensure encrypted data is exactly PoolMessageSize
	finalData, err := ensureExactSize(encryptedData, PoolMessageSize)
	if err != nil {
		return err
	}

	msg := &EncryptedMessage{
		data: finalData,
	}

	if batchProcessor != nil {
		if err := batchProcessor.AddToBatch(msg); err != nil {
			poolMutex.Lock()
			defer poolMutex.Unlock()
			if len(poolMessages) >= maxPoolSize {
				return fmt.Errorf("pool full")
			}
			poolMessages = append(poolMessages, msg)
			updatePoolStatsOnAdd()
			go scheduleIndividualMessage(finalData, randomDelay)
		} else {
		}
	} else {
		poolMutex.Lock()
		defer poolMutex.Unlock()
		if len(poolMessages) >= maxPoolSize {
			return fmt.Errorf("pool full")
		}
		poolMessages = append(poolMessages, msg)
		updatePoolStatsOnAdd()
		go scheduleIndividualMessage(finalData, randomDelay)
	}

	return nil
}

// scheduleIndividualMessage schedules individual message for sending after delay
func scheduleIndividualMessage(encryptedData []byte, delay time.Duration) {
	time.Sleep(delay)
	poolMutex.Lock()
	defer poolMutex.Unlock()
	for i, msg := range poolMessages {
		if bytes.Equal(msg.data, encryptedData) {
			poolMessages = append(poolMessages[:i], poolMessages[i+1:]...)
			currentLen := len(poolMessages)
			currentCap := cap(poolMessages)
			if currentCap > currentLen*4 && currentLen > 0 {
				newCap := currentLen * 2
				newPool := make([]*EncryptedMessage, currentLen, newCap)
				copy(newPool, poolMessages)
				poolMessages = newPool
			}
			go func() {
				if err := sendEncryptedMessageDirect(encryptedData); err != nil {
				}
			}()
			return
		}
	}
}

// safeCopy copies bytes with bounds checking to prevent panics
func safeCopy(dst, src []byte) int {
	if len(dst) == 0 || len(src) == 0 {
		return 0
	}
	n := len(src)
	if len(dst) < n {
		n = len(dst)
	}
	copy(dst[:n], src[:n])
	return n
}

// handleUpload handles incoming upload requests
func handleUpload(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			sendAnonymizedResponse(w, "upload_success")
		}
	}()
	timingObfuscator.Process(func() {
		handleUploadInternal(w, r)
	})
}

// handleDecryptedMessage processes decrypted messages and adds them to pool
func handleDecryptedMessage(w http.ResponseWriter, decryptedContent *memguard.LockedBuffer) {
	defer decryptedContent.Destroy()
	decryptedBytes := decryptedContent.Bytes()

	if len(decryptedBytes) == 0 {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	processedMessage := removePaddingMarkers(decryptedBytes)

	if len(processedMessage) == 0 {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	routingInfo, messageBody, err := parseBinaryRoutingInfo(processedMessage)
	if err != nil {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	// Prepare payload for next hop
	var nextHopPayload []byte
	if routingInfo.isMixnode {
		routingHeader := fmt.Sprintf("To: %s\n\n", routingInfo.nextHop)
		nextHopPayload = append([]byte(routingHeader), messageBody...)
	} else {
		routingHeader := fmt.Sprintf("To: %s\n\n", routingInfo.nextHop)
		nextHopPayload = append([]byte(routingHeader), messageBody...)
	}

	// Add to pool for further routing
	err = addToPoolSecurely(nextHopPayload, routingInfo.nextHop)
	if err != nil {
		sendAnonymizedResponse(w, "upload_success")
		return
	}

	sendAnonymizedResponse(w, "upload_success")
}

// handleUploadInternal handles the main upload logic
func handleUploadInternal(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]

	if !getIPLimiter(ip).Allow() && !globalLimiter.Allow() {
		sendAnonymizedResponse(w, "upload_success")
		return
	}

	// Always read raw binary data from request body (no multipart processing)
	bodyContent, err := ioutil.ReadAll(io.LimitReader(r.Body, maxUploadSize))
	if err != nil {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	if len(bodyContent) == 0 {
		sendAnonymizedResponse(w, "invalid_message")
		return
	}

	if isReplay(bodyContent) {
		sendAnonymizedResponse(w, "upload_success")
		return
	}
	markAsSeen(bodyContent)

	processMessageConstantTime(bodyContent)

	// Try all possible interpretation paths
	decrypted1, _ := decryptContentConstantTime(bodyContent)
	routingInfo2, encryptedPayload2, err2 := parseBinaryRoutingInfo(bodyContent)

	var decrypted3 *memguard.LockedBuffer
	if err2 == nil {
		decrypted3, _ = decryptContentConstantTime(encryptedPayload2)
	}

	// Path 1: Message is directly for us (fully decryptable)
	if decrypted1 != nil {
		handleDecryptedMessage(w, decrypted1)
		return
	}

	// Path 2: Message has routing header + inner payload that is decryptable (e.g., final hop)
	if decrypted3 != nil {
		handleDecryptedMessage(w, decrypted3)
		return
	}

	// Path 3: Message has routing header but payload is NOT decryptable → forward
	if err2 == nil {
		if routingInfo2.isMixnode {
			_ = addToPoolSecurely(encryptedPayload2, routingInfo2.nextHop)
		} else {
			go func() {
				_ = sendRawMessage(encryptedPayload2, routingInfo2.nextHop)
			}()
		}

		sendAnonymizedResponse(w, "upload_success")
		return
	}

	// Path 4: Nothing worked – drop silently
	sendAnonymizedResponse(w, "upload_success")
}

// Helper functions

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// decryptContentConstantTime decrypts content with constant timing
func decryptContentConstantTime(content []byte) (*memguard.LockedBuffer, error) {
	if len(content) < 32+24 {
		simulateDecryptionTime()
		return nil, errors.New("invalid encrypted data length")
	}
	var clientPubKeyArr [32]byte
	var nonceArr [24]byte
	safeCopy(clientPubKeyArr[:], content[:32])
	safeCopy(nonceArr[:], content[32:56])
	ciphertext := content[56:]
	serverPrivKey := privateKeyLocked.Bytes()
	var serverPrivKeyArr [32]byte
	safeCopy(serverPrivKeyArr[:], serverPrivKey)
	plaintext, ok := box.Open(nil, ciphertext, &nonceArr, &clientPubKeyArr, &serverPrivKeyArr)
	if !ok {
		simulateDecryptionTime()
		return nil, errors.New("decryption failed")
	}
	decryptedLocked := memguard.NewBufferFromBytes(plaintext)
	return decryptedLocked, nil
}

// secureRandomDelay generates a secure random delay
func secureRandomDelay() time.Duration {
	minDelay := 1000 * time.Millisecond
	maxDelay := 6000 * time.Millisecond
	return secureRandomDuration(minDelay, maxDelay)
}

// sendAnonymizedResponse sends an anonymized response with random delay
func sendAnonymizedResponse(w http.ResponseWriter, responseType string) {
	delay := secureRandomDelay()
	time.Sleep(delay)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, "OK")
}

// sendEncryptedMessageDirect sends encrypted message directly to destination
func sendEncryptedMessageDirect(encryptedData []byte) error {
	decryptedData, err := keyManager.decryptMessage(encryptedData)
	if err != nil {
		return err
	}
	onionAddress, message, _, messageID, err := deserializeMessageFromPool(decryptedData)
	if err != nil {
		return err
	}
	_ = messageID
	if isLoopMessageOnion(onionAddress) {
		return nil
	}
	routingInfo, messageBody, err := parseBinaryRoutingInfo(message)
	if err != nil {
		return err
	}
	var url string
	var payload []byte
	if routingInfo.isMixnode {
		if strings.HasPrefix(routingInfo.nextHop, "http://") || strings.HasPrefix(routingInfo.nextHop, "https://") {
			url = routingInfo.nextHop + "/upload"
		} else {
			url = fmt.Sprintf("http://%s/upload", routingInfo.nextHop)
		}
		payload = message
	} else {
		if strings.HasPrefix(routingInfo.nextHop, "http://") || strings.HasPrefix(routingInfo.nextHop, "https://") {
			url = routingInfo.nextHop + "/upload"
		} else {
			url = fmt.Sprintf("http://%s/upload", routingInfo.nextHop)
		}
		payload = messageBody
	}
	return sendRawMessage(payload, url)
}

// isLoopMessageOnion checks if message is looped back to self
func isLoopMessageOnion(onionAddress string) bool {
	return strings.Contains(onionAddress, ownOnionAddress) ||
		strings.Contains(onionAddress, "localhost") ||
		strings.Contains(onionAddress, "127.0.0.1") ||
		strings.Contains(onionAddress, "0.0.0.0") ||
		strings.Contains(onionAddress, ".dummy")
}

// managePool manages pool operations (shrinking, shuffling, etc.)
func managePool() {
	poolTicker := time.NewTicker(poolCheckInterval)
	shrinkTicker := time.NewTicker(5 * time.Minute)
	shuffleTicker := time.NewTicker(10 * time.Minute)
	defer poolTicker.Stop()
	defer shrinkTicker.Stop()
	defer shuffleTicker.Stop()
	for {
		select {
		case <-poolTicker.C:
			// Pool maintenance
		case <-shrinkTicker.C:
			shrinkPoolIfNeeded()
		case <-shuffleTicker.C:
			shuffleMessages()
		}
	}
}

// sendRawMessage sends raw message via Tor proxy
func sendRawMessage(message []byte, url string) error {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("tor proxy failed")
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
			ResponseHeaderTimeout: 120 * time.Second,
			ExpectContinueTimeout: 60 * time.Second,
		},
		Timeout: 240 * time.Second,
	}
	
	// Send raw binary data instead of multipart form
	body := bytes.NewReader(message)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("create request failed")
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "OnionCourier/1.0")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed")
	}
	defer resp.Body.Close()
	
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response failed")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-OK status: %d", resp.StatusCode)
	}
	return nil
}

// generateKeyPairFiles generates new key pair files
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

// loadPrivateKeySafe safely loads private key into locked buffer
func loadPrivateKeySafe(filename string) (*memguard.LockedBuffer, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open key file failed: %v", err)
	}
	defer file.Close()
	pemData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read key file failed: %v", err)
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
	privateKeyLocked, err = loadPrivateKeySafe(privateKeyPath)
	if err != nil {
		log.Fatalf("Error loading private key: %v", err)
	}
	defer privateKeyLocked.Destroy()

	ownOnionAddress = "5s6chpom2x77gl5pehdea3jrone46r5vqs5p4u2rhhneutzsp4fvzsqd.onion:8080"
	initSecurity()
	initKeyManager()
	initBatchProcessor()

	log.Printf("🧅 Onion Courier mix node running 🚀")
	go managePool()
	http.HandleFunc("/upload", handleUpload)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
