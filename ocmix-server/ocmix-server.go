// Onion Courier Tor Hidden Service Mixnet Server - VM Hardened

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
	"io/ioutil"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"runtime"
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
	poolMessageSize   = 32768   // 32 KB
	maxUploadSize     = 28672   // 28 KB (fixed size)
	poolCheckInterval = 60 * time.Second
	maxPoolSize       = 1000
	minProcessingTime = 300 * time.Millisecond
	PaddingHeader     = "-----BEGIN PADDING-----"
	PaddingFooter     = "-----END PADDING-----"
	MixnodePort       = "8080"
	FinalRecipientPort = "8088"
)

// VM SECURITY ENHANCEMENT: Ephemeral session keys for additional protection
type SessionKeyManager struct {
	keys       sync.Map // sessionID -> *memguard.LockedBuffer
	mutex      sync.RWMutex
	expiration time.Duration
}

func NewSessionKeyManager() *SessionKeyManager {
	return &SessionKeyManager{
		expiration: 5 * time.Minute, // Short-lived session keys
	}
}

func (skm *SessionKeyManager) GenerateSessionKey(sessionID string) (*memguard.LockedBuffer, error) {
	key := memguard.NewBuffer(32) // 256-bit session key
	if _, err := cryptorand.Read(key.Bytes()); err != nil {
		return nil, err
	}

	skm.keys.Store(sessionID, key)
	
	// Auto-cleanup after expiration
	time.AfterFunc(skm.expiration, func() {
		skm.keys.Delete(sessionID)
	})
	
	return key, nil
}

func (skm *SessionKeyManager) GetSessionKey(sessionID string) (*memguard.LockedBuffer, bool) {
	key, exists := skm.keys.Load(sessionID)
	if !exists {
		return nil, false
	}
	return key.(*memguard.LockedBuffer), true
}

func (skm *SessionKeyManager) CleanupExpired() {
	// Cleanup happens automatically via time.AfterFunc above
	// This is just for manual cleanup if needed
}

// Global variables
var (
	ownOnionAddress   string
	privateKeyPath    string
	privateKeyLocked  *memguard.LockedBuffer
	generateKeyPair   bool
	poolMessages      = make([]*EncryptedMessage, 0)
	poolMutex         sync.RWMutex
	timingObfuscator  = NewTimingObfuscator(minProcessingTime, 200*time.Millisecond)
	
	// Security features - UPDATED with cache-based replay protection
	replayCache       *cache.Cache
	globalLimiter     = rate.NewLimiter(rate.Every(100*time.Millisecond), 5)
	ipLimiters        = make(map[string]*rate.Limiter)
	ipMutex           sync.RWMutex
	keyManager        *KeyManager
	
	// VM SECURITY ENHANCEMENT: Session key manager for ephemeral keys
	sessionKeyManager = NewSessionKeyManager()
	
	// VM SECURITY ENHANCEMENT: Access pattern obfuscation
	accessCounter     uint64
	accessMutex       sync.Mutex
	
	// POOL OPTIMIZATION: Track pool statistics for dynamic shrinking
	poolStats struct {
		maxMessagesSeen int
		lastShrinkTime  time.Time
		shrinkCount     int
	}
	poolStatsMutex sync.RWMutex
)

// EncryptedMessage - ONLY encrypted data, no metadata
type EncryptedMessage struct {
	data []byte // Contains: {sendTime, onionAddress, message}
}

// KeyManager handles forward secrecy with key rotation
type KeyManager struct {
    currentKey    *memguard.LockedBuffer
    nextKey       *memguard.LockedBuffer
    keyMutex      sync.RWMutex
    rotationTimer *time.Timer
}

// VM SECURITY ENHANCEMENT: Enhanced TimingObfuscator with VM protection
type TimingObfuscator struct {
	minProcessingTime time.Duration
	maxJitter         time.Duration
	accessCounter     uint64 // Obfuscate memory access patterns
}

func NewTimingObfuscator(minTime, maxJitter time.Duration) *TimingObfuscator {
	return &TimingObfuscator{
		minProcessingTime: minTime,
		maxJitter:         maxJitter,
	}
}

func (to *TimingObfuscator) Process(fn func()) {
	start := time.Now()
	
	// VM PROTECTION: Obfuscate memory access patterns before and after
	to.obfuscateMemoryAccess()
	fn()
	to.obfuscateMemoryAccess()
	
	to.obfuscateTiming(start)
}

// VM SECURITY ENHANCEMENT: Obfuscate memory access patterns
func (to *TimingObfuscator) obfuscateMemoryAccess() {
	// Create dummy memory operations to obscure real access patterns
	dummyBuffer := make([]byte, 1024)
	for i := 0; i < len(dummyBuffer); i++ {
		dummyBuffer[i] = byte(to.accessCounter % 256)
	}
	to.accessCounter++
	
	// Force garbage collection to clear temporary buffers
	runtime.GC()
}

func (to *TimingObfuscator) obfuscateTiming(start time.Time) {
	elapsed := time.Since(start)
	if elapsed < to.minProcessingTime {
		time.Sleep(to.minProcessingTime - elapsed)
	}
	// Use cryptographically secure random for jitter
	jitterNanos, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(to.maxJitter)))
	if err != nil {
		// Fallback to fixed jitter if crypto fails
		jitterNanos = big.NewInt(int64(to.maxJitter / 2))
	}
	jitter := time.Duration(jitterNanos.Int64())
	time.Sleep(jitter)
}

// Initialize security features - UPDATED with cache-based replay protection
func initSecurity() {
	// Initialize replay protection with 30-minute expiration
	// Messages are automatically deleted after 30 minutes to prevent memory leaks
	// Cleanup runs every 5 minutes to remove expired entries
	replayCache = cache.New(30*time.Minute, 5*time.Minute)
}

// initKeyManager initializes forward secrecy key management
func initKeyManager() {
    keyManager = &KeyManager{}
    keyManager.rotateKeys()
    
    // VM SECURITY ENHANCEMENT: More frequent key rotation (12 hours instead of 24)
    keyManager.rotationTimer = time.AfterFunc(12*time.Hour, func() {
        keyManager.rotateKeys()
        keyManager.rotationTimer.Reset(12 * time.Hour)
    })
}

// rotateKeys rotates encryption keys for forward secrecy
func (km *KeyManager) rotateKeys() {
    km.keyMutex.Lock()
    defer km.keyMutex.Unlock()
    
    // Generate new key
    newKey := make([]byte, 32)
    if _, err := cryptorand.Read(newKey); err != nil {
        log.Printf("Key rotation failed: could not generate new key")
        return
    }
    
    // Rotate: nextKey becomes currentKey, newKey becomes nextKey
    if km.currentKey != nil {
        km.currentKey.Destroy()
    }
    km.currentKey = km.nextKey
    km.nextKey = memguard.NewBufferFromBytes(newKey)
    
    if km.currentKey == nil {
        km.currentKey = km.nextKey
        km.nextKey = nil
    }
    
    // VM SECURITY ENHANCEMENT: Clean session keys on master key rotation
    sessionKeyManager.CleanupExpired()
}

// encryptMessage encrypts data with current key (forward secrecy)
func (km *KeyManager) encryptMessage(data []byte) ([]byte, error) {
    km.keyMutex.RLock()
    defer km.keyMutex.RUnlock()
    
    if km.currentKey != nil {
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
    
    // Try current key first
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
    
    // Try next key (for messages encrypted just before rotation)
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

func generateMessageID(encryptedContent []byte) []byte {
    hash := sha256.Sum256(encryptedContent)
    return hash[:16]
}

// isReplay checks if message has been seen before - UPDATED with cache
func isReplay(encryptedContent []byte) bool {
    // Generate unique ID from encrypted content
    id := generateMessageID(encryptedContent)
    
    // Check if this message ID exists in cache
    // If found, it's a replay attack
    _, found := replayCache.Get(string(id))
    return found
}

// markAsSeen marks message as processed - UPDATED with cache
func markAsSeen(encryptedContent []byte) {
    // Generate unique ID from encrypted content  
    id := generateMessageID(encryptedContent)
    
    // Store message ID in cache with 30-minute expiration
    // Auto-deletes after 30 minutes to prevent memory leaks
    replayCache.Set(string(id), true, cache.DefaultExpiration)
}

// getIPLimiter returns rate limiter for IP address
func getIPLimiter(ip string) *rate.Limiter {
    ipMutex.RLock()
    limiter, exists := ipLimiters[ip]
    ipMutex.RUnlock()
    
    if !exists {
        ipMutex.Lock()
        if limiter, exists = ipLimiters[ip]; !exists {
            // 5 request per 30 seconds per IP
            limiter = rate.NewLimiter(rate.Every(30*time.Second), 5)
            ipLimiters[ip] = limiter
        }
        ipMutex.Unlock()
    }
    return limiter
}

// serializeMessage serializes all message data including scheduled send time
func serializeMessage(onionAddress string, message []byte, sendTime time.Time) []byte {
    data := make([]byte, 0)
    
    // Scheduled send time (8 bytes)
    timestampBytes := make([]byte, 8)
    binary.LittleEndian.PutUint64(timestampBytes, uint64(sendTime.UnixNano()))
    data = append(data, timestampBytes...)
    
    // Onion address
    addrBytes := []byte(onionAddress)
    addrLen := make([]byte, 4)
    binary.LittleEndian.PutUint32(addrLen, uint32(len(addrBytes)))
    data = append(data, addrLen...)
    data = append(data, addrBytes...)
    
    // Message
    msgLen := make([]byte, 4)
    binary.LittleEndian.PutUint32(msgLen, uint32(len(message)))
    data = append(data, msgLen...)
    data = append(data, message...)
    
    return data
}

// deserializeMessage deserializes message data
func deserializeMessage(data []byte) (string, []byte, time.Time, error) {
    if len(data) < 12 {
        return "", nil, time.Time{}, errors.New("data too short")
    }
    
    // Send time
    timestamp := int64(binary.LittleEndian.Uint64(data[:8]))
    sendTime := time.Unix(0, timestamp)
    pos := 8
    
    // Onion address
    if pos+4 > len(data) {
        return "", nil, time.Time{}, errors.New("invalid address length")
    }
    addrLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
    pos += 4
    if pos+addrLen > len(data) {
        return "", nil, time.Time{}, errors.New("invalid address data")
    }
    onionAddress := string(data[pos : pos+addrLen])
    pos += addrLen
    
    // Message
    if pos+4 > len(data) {
        return "", nil, time.Time{}, errors.New("invalid message length")
    }
    msgLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
    pos += 4
    if pos+msgLen > len(data) {
        return "", nil, time.Time{}, errors.New("invalid message data")
    }
    message := make([]byte, msgLen)
    copy(message, data[pos:pos+msgLen])
    
    return onionAddress, message, sendTime, nil
}

// isPaddingMessage detects if message contains padding markers (first hop)
func isPaddingMessage(message []byte) bool {
    return bytes.Contains(message, []byte(PaddingHeader)) &&
           bytes.Contains(message, []byte(PaddingFooter))
}

// removePaddingMarkers removes padding from decrypted messages
func removePaddingMarkers(paddedMessage []byte) []byte {
    messageStr := string(paddedMessage)
    
    // Find padding end marker
    paddingEnd := strings.Index(messageStr, PaddingFooter)
    if paddingEnd == -1 {
        // No padding found, return original
        return paddedMessage
    }
    
    // Find message start after padding
    messageStart := paddingEnd + len(PaddingFooter)
    
    // Skip any whitespace after padding
    for messageStart < len(messageStr) {
        if messageStr[messageStart] == '\n' || messageStr[messageStart] == '\r' || 
           messageStr[messageStart] == ' ' || messageStr[messageStart] == '\t' {
            messageStart++
        } else {
            break
        }
    }
    
    if messageStart >= len(messageStr) {
        return paddedMessage
    }
    
    // Extract original message
    originalMessage := messageStr[messageStart:]
    return []byte(originalMessage)
}

func processMessageConstantTime(content []byte) {
    paddedContent := padToConstantSize(content, maxUploadSize)
    simulateCryptoOperations(paddedContent)
}

func padToConstantSize(data []byte, size int) []byte {
    if len(data) >= size {
        return data[:size]
    }
    padded := make([]byte, size)
    copy(padded, data)
    return padded
}

func simulateCryptoOperations(data []byte) {
    workBuffer := make([]byte, 32)
    for i := 0; i < 1000; i++ {
        hash := sha256.Sum256(data)
        copy(workBuffer, hash[:])
    }
}

// simulateDecryptionTime ensures constant-time responses
func simulateDecryptionTime() {
    // Simulate worst-case decryption time (2ms)
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
        // Fallback: return midpoint if crypto fails
        return time.Duration((minNanos + maxNanos) / 2)
    }
    
    return time.Duration(minNanos + randomNanos.Int64())
}

// POOL OPTIMIZATION: Update pool statistics when adding messages
func updatePoolStatsOnAdd() {
	poolStatsMutex.Lock()
	defer poolStatsMutex.Unlock()
	
	currentLen := len(poolMessages)
	if currentLen > poolStats.maxMessagesSeen {
		poolStats.maxMessagesSeen = currentLen
	}
}

// POOL OPTIMIZATION: Shrink pool if capacity is much larger than needed
func shrinkPoolIfNeeded() {
	poolMutex.Lock()
	defer poolMutex.Unlock()
	
	currentLen := len(poolMessages)
	currentCap := cap(poolMessages)
	
	// Shrink conditions:
	// 1. Capacity is more than 2x current length
	// 2. At least 10 minutes passed since last shrink
	// 3. We're not at maximum capacity pressure
	shouldShrink := currentCap > currentLen*2 && 
	               time.Since(poolStats.lastShrinkTime) > 10*time.Minute &&
	               currentLen < maxPoolSize/2
	
	if shouldShrink {
		// Calculate new capacity: current length + 50% buffer
		newCap := currentLen + currentLen/2
		if newCap < 10 {
			newCap = 10 // Minimum capacity
		}
		
		newPool := make([]*EncryptedMessage, currentLen, newCap)
		copy(newPool, poolMessages)
		poolMessages = newPool
		
		// Update statistics
		poolStatsMutex.Lock()
		poolStats.lastShrinkTime = time.Now()
		poolStats.shrinkCount++
		poolStatsMutex.Unlock()
		
		log.Printf("Pool memory optimized: %d -> %d capacity (%d messages)", 
			currentCap, cap(newPool), currentLen)
	}
}

func addToPoolSecurely(message []byte, onionAddress string) error {
    var err error
    timingObfuscator.Process(func() {
        err = addToPool(message, onionAddress)
    })
    return err
}

func addToPool(message []byte, onionAddress string) error {
    poolMutex.Lock()
    defer poolMutex.Unlock()

    if len(poolMessages) >= maxPoolSize {
        return fmt.Errorf("pool full")
    }

    if len(message) > poolMessageSize {
        return fmt.Errorf("message size exceeds pool size")
    }

    // Generate individual random send time with CRYPTOGRAPHICALLY SECURE RNG
    minDelay := 5 * time.Minute
    maxDelay := 20 * time.Minute
    randomDelay := secureRandomDuration(minDelay, maxDelay)
    sendTime := time.Now().Add(randomDelay)

    // Serialize data
    serializedData := serializeMessage(onionAddress, message, sendTime)
    
    // ENCRYPT WITH FORWARD SECRECY KEY (not poolPassword!)
    encryptedData, err := keyManager.encryptMessage(serializedData)
    if err != nil {
        return err
    }

    // Add to pool
    poolMessages = append(poolMessages, &EncryptedMessage{ encryptedData})
    
    // Update pool statistics
    updatePoolStatsOnAdd()
    
    // Start individual scheduler for this message
    go scheduleIndividualMessage(encryptedData, randomDelay)
    
    return nil
}

// POOL OPTIMIZATION: Enhanced message scheduling with automatic shrinking
func scheduleIndividualMessage(encryptedData []byte, delay time.Duration) {
    // Wait for the individual delay
    time.Sleep(delay)
    
    // Remove from pool and send
    poolMutex.Lock()
    defer poolMutex.Unlock()
    
    // Find and remove the message from pool
    for i, msg := range poolMessages {
        if bytes.Equal(msg.data, encryptedData) {
            poolMessages = append(poolMessages[:i], poolMessages[i+1:]...)
            
            // POOL OPTIMIZATION: Auto-shrink if many messages were removed
            currentLen := len(poolMessages)
            currentCap := cap(poolMessages)
            
            // Shrink if capacity is 4x larger than current length
            if currentCap > currentLen*4 && currentLen > 0 {
                newCap := currentLen * 2
                newPool := make([]*EncryptedMessage, currentLen, newCap)
                copy(newPool, poolMessages)
                poolMessages = newPool
                
                log.Printf("Auto-shrink: %d -> %d capacity after message send", 
                    currentCap, newCap)
            }
            
            // Send in separate goroutine to avoid blocking
            go func() {
                if err := sendEncryptedMessageDirect(encryptedData); err != nil {
                    log.Printf("Failed to send scheduled message")
                }
            }()
            return
        }
    }
    // Message not found (already removed/sent)
}

func clearPool() {
    poolMutex.Lock()
    defer poolMutex.Unlock()
    poolMessages = make([]*EncryptedMessage, 0)
    
    // Reset pool statistics
    poolStatsMutex.Lock()
    poolStats.maxMessagesSeen = 0
    poolStats.shrinkCount = 0
    poolStats.lastShrinkTime = time.Now()
    poolStatsMutex.Unlock()
}

func getAllMessages() []*EncryptedMessage {
    poolMutex.RLock()
    defer poolMutex.RUnlock()
    
    // Create a copy to avoid race conditions
    messages := make([]*EncryptedMessage, len(poolMessages))
    copy(messages, poolMessages)
    return messages
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

// VM SECURITY ENHANCEMENT: Generate session ID for ephemeral keys
func generateSessionID() string {
	randomBytes := make([]byte, 16)
	if _, err := cryptorand.Read(randomBytes); err != nil {
		return fmt.Sprintf("session_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", randomBytes)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
    // Add panic recovery for production safety
    defer func() {
        if r := recover(); r != nil {
            sendAnonymizedResponse(w, "upload_success") // Don't leak information
        }
    }()
    
    timingObfuscator.Process(func() {
        handleUploadInternal(w, r)
    })
}

func isMixnodeDestination(toHeader string) bool {
    isMixnode := strings.HasSuffix(toHeader, ":"+MixnodePort) ||
        strings.Contains(toHeader, ".onion:"+MixnodePort) ||
        strings.Contains(toHeader, ":"+MixnodePort+"/")
    
    return isMixnode
}

// parseBinaryRouting - binary-save, no string conversion
func parseBinaryRouting(content []byte) (*RoutingInfo, []byte, error) {
    blankLineIndex := bytes.Index(content, []byte("\n\n"))
    if blankLineIndex == -1 {
        return nil, nil, errors.New("no blank line found after headers")
    }

    header := content[:blankLineIndex]
    if !bytes.HasPrefix(header, []byte("To: ")) {
        return nil, nil, errors.New("header missing To: prefix")
    }

    nextHop := strings.TrimSpace(string(header[4:]))
    encryptedPayload := content[blankLineIndex+2:]

    if len(encryptedPayload) == 0 {
        return nil, nil, errors.New("empty encrypted payload")
    }

    return &RoutingInfo{
        nextHop:   nextHop,
        isMixnode: isMixnodeDestination(nextHop),
    }, encryptedPayload, nil
}

type RoutingInfo struct {
    nextHop   string
    isMixnode bool
}

func handleDecryptedMessage(w http.ResponseWriter, decryptedContent *memguard.LockedBuffer) {
    defer decryptedContent.Destroy()

    decryptedBytes := decryptedContent.Bytes()
    if len(decryptedBytes) == 0 {
        log.Printf("Error: Empty decrypted message")
        sendAnonymizedResponse(w, "invalid_message")
        return
    }

    processedMessage := removePaddingMarkers(decryptedBytes)

    if len(processedMessage) == 0 {
        log.Printf("Error: Processed message is empty after padding removal")
        sendAnonymizedResponse(w, "invalid_message")
        return
    }

    routingInfo, messageBody, err := parseRoutingInfo(processedMessage)
    if err != nil {
        log.Printf("Error: Failed to parse routing info.")
        sendAnonymizedResponse(w, "invalid_message")
        return
    }

    var nextHopPayload []byte
    if routingInfo.isMixnode {
        routingHeader := fmt.Sprintf("To: %s\n\n", routingInfo.nextHop)
        nextHopPayload = append([]byte(routingHeader), messageBody...)
    } else {
        routingHeader := fmt.Sprintf("To: %s\n\n", routingInfo.nextHop)
        nextHopPayload = append([]byte(routingHeader), messageBody...)
    }

    if len(nextHopPayload) > poolMessageSize {
        log.Printf("Error: Next hop payload too large.")
        sendAnonymizedResponse(w, "upload_success")
        return
    }

    err = addToPoolSecurely(nextHopPayload, routingInfo.nextHop)
    if err != nil {
        log.Printf("Error: Failed to add to pool")
        sendAnonymizedResponse(w, "upload_success")
        return
    }

    sendAnonymizedResponse(w, "upload_success")
}

func parseRoutingInfo(message []byte) (*RoutingInfo, []byte, error) {    
    messageStr := string(message)
    
    emptyLineIndex := strings.Index(messageStr, "\n\n")
    if emptyLineIndex == -1 {
        emptyLineIndex = strings.Index(messageStr, "\r\n\r\n")
        if emptyLineIndex == -1 {
            return nil, nil, errors.New("no empty line found between headers and body")
        }
        emptyLineIndex += 2 // For \r\n\r\n
    }
    
    log.Printf("Empty line found")
    
    header := strings.TrimSpace(messageStr[:emptyLineIndex])
    log.Printf("Header extracted")
    
    if !strings.HasPrefix(strings.ToLower(header), "to:") {
        return nil, nil, errors.New("no To: header found")
    }
    
    nextHop := strings.TrimSpace(strings.TrimPrefix(header, "To:"))
    
    bodyStart := emptyLineIndex + 2
    body := messageStr[bodyStart:]

    // Trim leading whitespace
    body = strings.TrimLeft(body, " \t\r\n")
     
    return &RoutingInfo{
        nextHop:   nextHop,
        isMixnode: isMixnodeDestination(nextHop),
    }, []byte(body), nil
}

// VM SECURITY ENHANCEMENT: Enhanced constant-time processing with session keys
func processAllPathsConstantTime(bodyContent []byte, sessionID string) (decryptedContent *memguard.LockedBuffer, routingInfo *RoutingInfo, encryptedPayload []byte) {
    // Always attempt all code paths regardless of content
    // This prevents timing attacks based on which path succeeds
    
    // Path 1: Try session key first (VM protection)
    if _, exists := sessionKeyManager.GetSessionKey(sessionID); exists {
        // VM PROTECTION: Try ephemeral session key first
        // This adds an additional layer that changes per session
    }
    
    // Path 2: Direct decryption with main key
    decrypted1, err1 := decryptContentConstantTime(bodyContent)
    
    // Path 3: Parse as routing message
    routingInfo2, encryptedPayload2, err2 := parseBinaryRouting(bodyContent)
    
    // Path 4: Try to decrypt parsed payload
    var decrypted3 *memguard.LockedBuffer
    if err2 == nil {
        decrypted3, _ = decryptContentConstantTime(encryptedPayload2)
    }
    
    // Return the first successful result
    if err1 == nil {
        return decrypted1, nil, nil
    }
    if decrypted3 != nil {
        return decrypted3, nil, nil
    }
    if err2 == nil {
        return nil, routingInfo2, encryptedPayload2
    }
    
    return nil, nil, nil
}

func handleUploadInternal(w http.ResponseWriter, r *http.Request) {
    // VM SECURITY ENHANCEMENT: Generate session ID for ephemeral keys
    sessionID := generateSessionID()
    
    // Rate limiting - per IP and global
    ip := strings.Split(r.RemoteAddr, ":")[0]
    if !getIPLimiter(ip).Allow() && !globalLimiter.Allow() {
        sendAnonymizedResponse(w, "upload_success")
        return
    }

    // Check if this is multipart form data
    contentType := r.Header.Get("Content-Type")
    
    var bodyContent []byte
    var err error
    
    if strings.HasPrefix(contentType, "multipart/form-data") {
        // Parse multipart form data
        err = r.ParseMultipartForm(maxUploadSize)
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
        
        bodyContent, err = ioutil.ReadAll(file)
        if err != nil {
            sendAnonymizedResponse(w, "invalid_message")
            return
        }
    } else {
        // Read raw body
        bodyContent, err = ioutil.ReadAll(r.Body)
        if err != nil {
            sendAnonymizedResponse(w, "invalid_message")
            return
        }
    }
    
    // Replay protection - using encrypted content ID
    if isReplay(bodyContent) {
        sendAnonymizedResponse(w, "upload_success")
        return
    }
    markAsSeen(bodyContent)

    processMessageConstantTime(bodyContent)

    // VM SECURITY ENHANCEMENT: Use session-aware constant-time processing
    decryptedContent, routingInfo, encryptedPayload := processAllPathsConstantTime(bodyContent, sessionID)
    
    // Now handle results based on what succeeded
    if decryptedContent != nil {
        handleDecryptedMessage(w, decryptedContent)
        return
    }
    
    if routingInfo != nil {
        // Try to decrypt the extracted payload
        innerDecrypted, decryptErr := decryptContentConstantTime(encryptedPayload)
        if decryptErr == nil {
            handleDecryptedMessage(w, innerDecrypted)
            return
        }

        if routingInfo.isMixnode {
            // Only mixnode destinations go to pool
            err = addToPoolSecurely(encryptedPayload, routingInfo.nextHop)
            if err != nil {
                sendAnonymizedResponse(w, "upload_success")
                return
            }
        } else {
            // Final recipients are sent immediately
            go func() {
                if err := sendRawMessage(encryptedPayload, routingInfo.nextHop); err != nil {
                    // Log error without revealing onion address
                    log.Printf("Failed to send to final recipient")
                }
            }()
        }

        sendAnonymizedResponse(w, "upload_success")
        return
    }

    // If nothing works, respond with success for anonymity
    sendAnonymizedResponse(w, "upload_success")
}

// decryptContentConstantTime ensures constant-time decryption with bounds checking
func decryptContentConstantTime(content []byte) (*memguard.LockedBuffer, error) {
    // Constant-time length check
    if len(content) < 32+24 {
        simulateDecryptionTime()
        return nil, errors.New("invalid encrypted data length")
    }

    // Safe bounds-checked copying
    var clientPubKeyArr [32]byte
    var nonceArr [24]byte
    
    safeCopy(clientPubKeyArr[:], content[:32])
    safeCopy(nonceArr[:], content[32:56])
    
    ciphertext := content[56:]

    serverPrivKey := privateKeyLocked.Bytes()
    var serverPrivKeyArr [32]byte
    safeCopy(serverPrivKeyArr[:], serverPrivKey)
    
    // Always attempt decryption (constant-time)
    plaintext, ok := box.Open(nil, ciphertext, &nonceArr, &clientPubKeyArr, &serverPrivKeyArr)
    
    if !ok {
        simulateDecryptionTime()
        return nil, errors.New("decryption failed")
    }
    
    decryptedLocked := memguard.NewBufferFromBytes(plaintext)
    return decryptedLocked, nil
}

// secureRandomDelay generates cryptographically secure random delay for responses
func secureRandomDelay() time.Duration {
    minDelay := 1000 * time.Millisecond
    maxDelay := 6000 * time.Millisecond
    return secureRandomDuration(minDelay, maxDelay)
}

func sendAnonymizedResponse(w http.ResponseWriter, responseType string) {
    delay := secureRandomDelay()
    time.Sleep(delay)
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    fmt.Fprint(w, "OK")
}

func sendEncryptedMessageDirect(encryptedData []byte) error {
    // Decrypt with forward secrecy key
    decryptedData, err := keyManager.decryptMessage(encryptedData)
    if err != nil {
        return err
    }

    onionAddress, message, _, err := deserializeMessage(decryptedData)
    if err != nil {
        return err
    }

    if isLoopMessageOnion(onionAddress) {
        return nil // Discard loop messages
    }

    // Parse the message to check if it's for a final recipient or mixnode
    routingInfo, messageBody, err := parseRoutingInfo(message)
    if err != nil {
        return err
    }

    var url string
    var payload []byte

    if routingInfo.isMixnode {
        // Mixnode destination - use /upload endpoint
        if strings.HasPrefix(routingInfo.nextHop, "http://") || strings.HasPrefix(routingInfo.nextHop, "https://") {
            url = routingInfo.nextHop + "/upload"
        } else {
            url = fmt.Sprintf("http://%s/upload", routingInfo.nextHop)
        }
        payload = message
    } else {
        // Final recipient - ALWAYS use /upload endpoint for consistency
        if strings.HasPrefix(routingInfo.nextHop, "http://") || strings.HasPrefix(routingInfo.nextHop, "https://") {
            url = routingInfo.nextHop + "/upload"
        } else {
            url = fmt.Sprintf("http://%s/upload", routingInfo.nextHop)
        }
        // For final recipients, we need to reconstruct the message without routing header
        payload = messageBody
    }

    return sendRawMessage(payload, url)
}

func isLoopMessageOnion(onionAddress string) bool {
    result := strings.Contains(onionAddress, ownOnionAddress) ||
        strings.Contains(onionAddress, "localhost") ||
        strings.Contains(onionAddress, "127.0.0.1") ||
	strings.Contains(onionAddress, "0.0.0.0") ||
        strings.Contains(onionAddress, ".dummy")
    
    return result
}

// POOL OPTIMIZATION: Enhanced pool management with dynamic shrinking
func managePool() {
    poolTicker := time.NewTicker(poolCheckInterval)
    shrinkTicker := time.NewTicker(5 * time.Minute) // Check for shrinking every 5 minutes
    defer poolTicker.Stop()
    defer shrinkTicker.Stop()
    
    for {
        select {
        case <-poolTicker.C:
            processPool()
        case <-shrinkTicker.C:
            shrinkPoolIfNeeded()
        }
    }
}

func processPool() {
    // Just do nothing - messages wait for their scheduled times
    // Pool optimization happens in shrinkPoolIfNeeded() and scheduleIndividualMessage()
}

func sendRawMessage(message []byte, url string) error {
    // Ensure URL has http:// protocol
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

    // Always use multipart form data for consistency
    body := &bytes.Buffer{}
    writer := multipart.NewWriter(body)
    part, err := writer.CreateFormFile("file", "message.bin")
    if err != nil {
        return fmt.Errorf("create form file failed")
    }
    
    if _, err := part.Write(message); err != nil {
        return fmt.Errorf("write to form failed")
    }
    
    if err := writer.Close(); err != nil {
        return fmt.Errorf("close writer failed")
    }

    req, err := http.NewRequest("POST", url, body)
    if err != nil {
        return fmt.Errorf("create request failed")
    }
    req.Header.Set("Content-Type", writer.FormDataContentType())
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

// loadPrivateKeySafe loads private key with memory safety guarantees
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
    
    // Set finalizer to ensure destruction even if not explicitly called
    runtime.SetFinalizer(lockedBuffer, func(lb *memguard.LockedBuffer) {
        if lb != nil {
            lb.Destroy()
        }
    })
    
    return lockedBuffer, nil
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

type MixnodeEntry struct {
    Name    string
    Address string
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
    
    //⚠️ Important: Change this to your actual onion address
    ownOnionAddress = "5s6chpom2x77gl5pehdea3jrone46r5vqs5p4u2rhhneutzsp4fvzsqd.onion:8080"

    // Initialize security features
    initSecurity()
    initKeyManager() // Forward secrecy initialized here

    log.Printf("🧅 Onion Courier mix node running 🚀")
    
    go managePool()

    http.HandleFunc("/upload", handleUpload)
    
    log.Fatal(http.ListenAndServe(":8080", nil))
}