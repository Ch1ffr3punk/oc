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
	"io/ioutil"
	"log"
	"math/big"
	"mime/multipart"
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
	replayCache       *cache.Cache
	globalLimiter     = rate.NewLimiter(rate.Every(100*time.Millisecond), 5)
	
	ipLimiters        = cache.New(30*time.Minute, 5*time.Minute)
	keyManager        *KeyManager
	
	// Pool statistics for dynamic shrinking
	poolStats struct {
		maxMessagesSeen int
		lastShrinkTime  time.Time
		shrinkCount     int
	}
	poolStatsMutex sync.RWMutex
)

// EncryptedMessage - Contains serialized and encrypted message data
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
	// Use cryptographically secure random for jitter
	jitterNanos, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(to.maxJitter)))
	if err != nil {
		// Fallback to fixed jitter if crypto fails
		jitterNanos = big.NewInt(int64(to.maxJitter / 2))
	}
	jitter := time.Duration(jitterNanos.Int64())
	time.Sleep(jitter)
}

// Initialize security features
func initSecurity() {
	// Initialize replay protection with 30-minute expiration
	replayCache = cache.New(30*time.Minute, 5*time.Minute)
}

// initKeyManager initializes forward secrecy key management
func initKeyManager() {
    keyManager = &KeyManager{}
    keyManager.rotateKeys()
    
    // Rotate keys every 12 hours for forward secrecy
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
}

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

// isReplay checks if message has been seen before
func isReplay(encryptedContent []byte) bool {
    id := generateMessageID(encryptedContent)
    _, found := replayCache.Get(string(id))
    return found
}

// markAsSeen marks message as processed
func markAsSeen(encryptedContent []byte) {
    id := generateMessageID(encryptedContent)
    replayCache.Set(string(id), true, cache.DefaultExpiration)
}

func getIPLimiter(ip string) *rate.Limiter {
    limiter, found := ipLimiters.Get(ip)
    if found {
        return limiter.(*rate.Limiter)
    }
    
    // 5 requests per 30 seconds per IP
    newLimiter := rate.NewLimiter(rate.Every(30*time.Second), 5)
    ipLimiters.Set(ip, newLimiter, cache.DefaultExpiration)
    return newLimiter
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

func parseBinaryRoutingInfo(message []byte) (*RoutingInfo, []byte, error) {
    // Find the header-body separator
    separator := []byte("\n\n")
    separatorIndex := bytes.Index(message, separator)
    if separatorIndex == -1 {
        separator = []byte("\r\n\r\n")
        separatorIndex = bytes.Index(message, separator)
        if separatorIndex == -1 {
            return nil, nil, errors.New("no header-body separator found")
        }
    }

    // Extract headers (binary-safe)
    headerSection := message[:separatorIndex]
    if !bytes.HasPrefix(headerSection, []byte("To:")) {
        return nil, nil, errors.New("missing To: header")
    }

    // Extract next hop address (binary-safe)
    toLineEnd := bytes.IndexByte(headerSection, '\n')
    if toLineEnd == -1 {
        toLineEnd = len(headerSection)
    }
    
    nextHop := string(bytes.TrimSpace(headerSection[3:toLineEnd]))
    bodyStart := separatorIndex + len(separator)
    
    if bodyStart >= len(message) {
        return nil, nil, errors.New("empty message body")
    }

    // Extract message body
    messageBody := message[bodyStart:]
    
    return &RoutingInfo{
        nextHop:   nextHop,
        isMixnode: isMixnodeDestination(nextHop),
    }, messageBody, nil
}

type RoutingInfo struct {
    nextHop   string
    isMixnode bool
}

func isMixnodeDestination(toHeader string) bool {
    return strings.Contains(toHeader, ":"+MixnodePort)
}

// Remove padding markers from decrypted messages
func removePaddingMarkers(paddedMessage []byte) []byte {
    messageStr := string(paddedMessage)
    
    paddingEnd := strings.Index(messageStr, PaddingFooter)
    if paddingEnd == -1 {
        return paddedMessage
    }

    messageStart := paddingEnd + len(PaddingFooter)
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
    
    return []byte(messageStr[messageStart:])
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

// Pool optimization functions
func updatePoolStatsOnAdd() {
	poolStatsMutex.Lock()
	defer poolStatsMutex.Unlock()
	
	currentLen := len(poolMessages)
	if currentLen > poolStats.maxMessagesSeen {
		poolStats.maxMessagesSeen = currentLen
	}
}

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

    minDelay := 5 * time.Minute
    maxDelay := 20 * time.Minute
    randomDelay := secureRandomDuration(minDelay, maxDelay)
    sendTime := time.Now().Add(randomDelay)

    serializedData := serializeMessage(onionAddress, message, sendTime)
    
    encryptedData, err := keyManager.encryptMessage(serializedData)
    if err != nil {
        return err
    }

    poolMessages = append(poolMessages, &EncryptedMessage{encryptedData})
    updatePoolStatsOnAdd()
    
    go scheduleIndividualMessage(encryptedData, randomDelay)
    
    return nil
}

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

func clearPool() {
    poolMutex.Lock()
    defer poolMutex.Unlock()
    poolMessages = make([]*EncryptedMessage, 0)
    
    poolStatsMutex.Lock()
    poolStats.maxMessagesSeen = 0
    poolStats.shrinkCount = 0
    poolStats.lastShrinkTime = time.Now()
    poolStatsMutex.Unlock()
}

func getAllMessages() []*EncryptedMessage {
    poolMutex.RLock()
    defer poolMutex.RUnlock()
    
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

    var nextHopPayload []byte
    if routingInfo.isMixnode {
        routingHeader := fmt.Sprintf("To: %s\n\n", routingInfo.nextHop)
        nextHopPayload = append([]byte(routingHeader), messageBody...)
    } else {
        routingHeader := fmt.Sprintf("To: %s\n\n", routingInfo.nextHop)
        nextHopPayload = append([]byte(routingHeader), messageBody...)
    }

    if len(nextHopPayload) > poolMessageSize {
        sendAnonymizedResponse(w, "upload_success")
        return
    }

    err = addToPoolSecurely(nextHopPayload, routingInfo.nextHop)
    if err != nil {
        sendAnonymizedResponse(w, "upload_success")
        return
    }

    sendAnonymizedResponse(w, "upload_success")
}

func processAllPathsConstantTime(bodyContent []byte) (decryptedContent *memguard.LockedBuffer, routingInfo *RoutingInfo, encryptedPayload []byte) {
    decrypted1, err1 := decryptContentConstantTime(bodyContent)
    
    routingInfo2, encryptedPayload2, err2 := parseBinaryRoutingInfo(bodyContent)
    
    var decrypted3 *memguard.LockedBuffer
    if err2 == nil {
        decrypted3, _ = decryptContentConstantTime(encryptedPayload2)
    }
    
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
    ip := strings.Split(r.RemoteAddr, ":")[0]
    if !getIPLimiter(ip).Allow() && !globalLimiter.Allow() {
        sendAnonymizedResponse(w, "upload_success")
        return
    }

    contentType := r.Header.Get("Content-Type")
    
    var bodyContent []byte
    var err error
    
    if strings.HasPrefix(contentType, "multipart/form-data") {
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
        bodyContent, err = ioutil.ReadAll(r.Body)
        if err != nil {
            sendAnonymizedResponse(w, "invalid_message")
            return
        }
    }
    
    if isReplay(bodyContent) {
        sendAnonymizedResponse(w, "upload_success")
        return
    }
    markAsSeen(bodyContent)

    processMessageConstantTime(bodyContent)

    decryptedContent, routingInfo, encryptedPayload := processAllPathsConstantTime(bodyContent)
    
    if decryptedContent != nil {
        handleDecryptedMessage(w, decryptedContent)
        return
    }
    
    if routingInfo != nil {
        innerDecrypted, decryptErr := decryptContentConstantTime(encryptedPayload)
        if decryptErr == nil {
            handleDecryptedMessage(w, innerDecrypted)
            return
        }

        if routingInfo.isMixnode {
            err = addToPoolSecurely(encryptedPayload, routingInfo.nextHop)
            if err != nil {
                sendAnonymizedResponse(w, "upload_success")
                return
            }
        } else {
            go func() {
                if err := sendRawMessage(encryptedPayload, routingInfo.nextHop); err != nil {
                    // FIX: Minimal logging in production
                }
            }()
        }

        sendAnonymizedResponse(w, "upload_success")
        return
    }

    sendAnonymizedResponse(w, "upload_success")
}

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
    decryptedData, err := keyManager.decryptMessage(encryptedData)
    if err != nil {
        return err
    }

    onionAddress, message, _, err := deserializeMessage(decryptedData)
    if err != nil {
        return err
    }

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

func isLoopMessageOnion(onionAddress string) bool {
    return strings.Contains(onionAddress, ownOnionAddress) ||
        strings.Contains(onionAddress, "localhost") ||
        strings.Contains(onionAddress, "127.0.0.1") ||
	    strings.Contains(onionAddress, "0.0.0.0") ||
        strings.Contains(onionAddress, ".dummy")
}

func managePool() {
    poolTicker := time.NewTicker(poolCheckInterval)
    shrinkTicker := time.NewTicker(5 * time.Minute)
    defer poolTicker.Stop()
    defer shrinkTicker.Stop()
    
    for {
        select {
        case <-poolTicker.C:
            // Pool processing logic if needed
        case <-shrinkTicker.C:
            shrinkPoolIfNeeded()
        }
    }
}

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

    log.Printf("🧅 Onion Courier mix node running 🚀")

    go managePool()

    http.HandleFunc("/upload", handleUpload)
    
    log.Fatal(http.ListenAndServe(":8080", nil))
}
