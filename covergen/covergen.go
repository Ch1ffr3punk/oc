// Onion Courier Cover Traffic Generator

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/proxy"
)

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

// Constants for message sizing (must match main client)
const (
	MaxUserPayload = 20480  // 20 KB maximum user message size
	MaxTotalSize   = 28672  // 28 KB maximum total message size after padding (server limit)
	PaddingHeader  = "-----BEGIN PADDING-----"
	PaddingFooter  = "-----END PADDING-----"
)

var quietMode bool

// secureRandInt generates a cryptographically secure random integer
func secureRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// adaptivePadding applies padding that automatically adapts to available space
func adaptivePadding(message []byte, maxTotalSize int) ([]byte, error) {
    // This function should never fail - if no space for padding, return original message
    messageSize := len(message)
    
    // If message already at or over limit, return as-is (no padding possible)
    if messageSize >= maxTotalSize {
        return message, nil
    }

    // Calculate available space for padding
    availableSpace := maxTotalSize - messageSize
    overhead := len(PaddingHeader) + len(PaddingFooter) + 4 // 4 bytes for newlines
    
    // If not enough space for padding structure, return original message
    if availableSpace <= overhead {
        return message, nil
    }

    // Maximum padding based on available space
    maxPaddingSize := availableSpace - overhead
    
    // Choose random padding size within available space
    targetPaddingSize := secureRandInt(maxPaddingSize + 1) // +1 because secureRandInt is exclusive

    // Ensure at least 1 byte padding if possible
    if targetPaddingSize == 0 && maxPaddingSize > 0 {
        targetPaddingSize = 1
    }

    // Generate padding bytes
    padding := make([]byte, targetPaddingSize)
    if _, err := rand.Read(padding); err != nil {
        return message, nil // Fallback to original message on error
    }

    // Construct padded message
    padded := fmt.Sprintf("%s\n%s\n%s\n%s", 
        PaddingHeader,
        string(padding),
        PaddingFooter,
        string(message))

    // Final safety check - should never exceed due to our calculations
    if len(padded) > maxTotalSize {
        // This should never happen, but if it does, return original message
        return message, nil
    }

    return []byte(padded), nil
}

func main() {
	rateMinStr := flag.String("rate-min", "", "Minimum messages per hour (optional)")
	rateMaxStr := flag.String("rate-max", "", "Maximum messages per hour (optional)")
	minSize := flag.Int("min", 32, "Minimum message size")
	maxSize := flag.Int("max", 20480, "Maximum message size")
	chain := flag.String("chain", "", "Comma-separated node chain (optional)")
	flag.BoolVar(&quietMode, "q", false, "Quiet mode - no output at all")

	flag.Parse()

	// Set defaults
	minRate := 0
	maxRate := 0

	// Parse rate-min if supplied
	if *rateMinStr != "" {
		if val, err := strconv.Atoi(*rateMinStr); err == nil {
			minRate = val
		} else {
			log.Fatalf("Invalid value for rate-min: %s", *rateMinStr)
		}
	}

	// Parse rate-max if supplied
	if *rateMaxStr != "" {
		if val, err := strconv.Atoi(*rateMaxStr); err == nil {
			maxRate = val
		} else {
			log.Fatalf("Invalid value for rate-max: %s", *rateMaxStr)
		}
	}

	if !quietMode {
		fmt.Printf("=== Starting Cover Traffic Generator ===\n")
		fmt.Printf("Rate: %d-%d msgs/hour\n", minRate, maxRate)
		fmt.Printf("Message size: %d-%d bytes\n", *minSize, *maxSize)
		if *chain != "" {
			fmt.Printf("Fixed chain: %s\n", *chain)
		}
	}

	pubKeys, err := loadPublicKeys("oc/pubring.txt")
	if err != nil {
		if !quietMode {
			fmt.Fprintf(os.Stderr, "Error loading public keys: %v\n", err)
		}
		os.Exit(1)
	}

	mixnodes, err := loadMixnodeAddresses("oc/mixnodes.txt")
	if err != nil {
		if !quietMode {
			fmt.Fprintf(os.Stderr, "Error loading mixnodes: %v\n", err)
		}
		os.Exit(1)
	}

	if !quietMode {
		fmt.Printf("Loaded %d public keys and %d mixnodes\n", len(pubKeys), len(mixnodes))
		fmt.Printf("=== Starting cover message scheduling ===\n")
	}

	// Start with panic recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				if !quietMode {
					fmt.Printf("PANIC in main: %v - restarting in 30s\n", r)
				}
				time.Sleep(30 * time.Second)
				main()
			}
		}()
		scheduleMessages(minRate, maxRate, *minSize, *maxSize, pubKeys, mixnodes, *chain)
	}()

	// Keep main alive
	select {}
}

// scheduleMessages schedules cover traffic messages at random intervals
func scheduleMessages(rateMin, rateMax, minSize, maxSize int, pubKeys []KeyEntry, mixnodes []MixnodeEntry, chain string) {
	defer func() {
		if r := recover(); r != nil {
			if !quietMode {
				fmt.Printf("PANIC in scheduler: %v\n", r)
			}
		}
	}()

	for {
		// Calculate number of messages for this hour
		totalMsgs := secureRandInt(rateMax-rateMin+1) + rateMin

		if !quietMode {
			fmt.Printf("This hour: %d messages scheduled\n", totalMsgs)
		}

		// Generate random send times
		var times []time.Duration
		for i := 0; i < totalMsgs; i++ {
			offset := secureRandInt(3600)
			times = append(times, time.Duration(offset)*time.Second)
		}
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

		start := time.Now()

		// Schedule each message
		for i, t := range times {
			go func(msgNum int, delay time.Duration) {
				defer func() {
					if r := recover(); r != nil {
						if !quietMode {
							fmt.Printf("PANIC in message %d: %v\n", msgNum, r)
						}
					}
				}()

				sendTime := start.Add(delay)
				time.Sleep(time.Until(sendTime))

				if !quietMode {
					fmt.Printf("Sending cover message %d now\n", msgNum)
				}

				selectedChain := selectRandomChain(chain, mixnodes)
				sendCoverMessage(selectedChain, minSize, maxSize, pubKeys, mixnodes)
			}(i+1, t)
		}

		// Wait for next hour
		nextHour := start.Add(time.Hour)
		time.Sleep(time.Until(nextHour))
	}
}

// selectRandomChain selects a random chain of mixnodes
func selectRandomChain(fixedChain string, mixnodes []MixnodeEntry) string {
	if fixedChain != "" {
		return fixedChain
	}

	length := secureRandInt(4) + 2 // 2-5 hops

	availableNodes := make([]string, len(mixnodes))
	for i, node := range mixnodes {
		availableNodes[i] = node.Name
	}

	var selectedNodes []string
	used := make(map[string]bool)

	for i := 0; i < length && len(selectedNodes) < len(availableNodes); i++ {
		for attempts := 0; attempts < 10; attempts++ {
			nodeIndex := secureRandInt(len(availableNodes))
			nodeName := availableNodes[nodeIndex]
			if !used[nodeName] {
				selectedNodes = append(selectedNodes, nodeName)
				used[nodeName] = true
				break
			}
		}
	}

	if len(selectedNodes) < 2 {
		if len(availableNodes) >= 2 {
			return strings.Join(availableNodes[:2], ",")
		} else if len(availableNodes) == 1 {
			return availableNodes[0]
		}
		return ""
	}

	return strings.Join(selectedNodes, ",")
}

// sendCoverMessage sends a single cover traffic message
func sendCoverMessage(chain string, minSize, maxSize int, pubKeys []KeyEntry, mixnodes []MixnodeEntry) {
    defer func() {
        if r := recover(); r != nil {
            if !quietMode {
                fmt.Printf("PANIC in sendCoverMessage: %v\n", r)
            }
        }
    }()

    if chain == "" {
        return
    }

    // Ensure message size limits match main client
    if minSize < 1 {
        minSize = 1
    }
    if maxSize > MaxUserPayload {
        maxSize = MaxUserPayload
    }
    
    // Ensure maxSize is at least minSize
    if maxSize < minSize {
        maxSize = minSize
    }

    nodes := strings.Split(chain, ",")
    if hasDuplicates(nodes) {
        return
    }

    // Generate random payload with PROPER size calculation
    // Calculate maximum possible payload size accounting for "To: " header
    dummyAddress := generateRandomOnionV3Address() + ".dummy:8080"
    headerOverhead := len("To: " + dummyAddress + "\n\n")
    
    // Adjust maxSize to account for header overhead
    adjustedMaxSize := MaxUserPayload - headerOverhead
    if adjustedMaxSize < minSize {
        adjustedMaxSize = minSize
    }
    if adjustedMaxSize > MaxUserPayload {
        adjustedMaxSize = MaxUserPayload
    }

    // Calculate size range with proper bounds
    sizeRange := adjustedMaxSize - minSize + 1
    if sizeRange <= 0 {
        sizeRange = 1
    }
    size := secureRandInt(sizeRange) + minSize
    
    // Ensure size doesn't exceed adjusted maximum
    if size > adjustedMaxSize {
        size = adjustedMaxSize
    }
    if size < minSize {
        size = minSize
    }

    randomBytes := make([]byte, size)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return
    }

    // Create internal message with dummy recipient
    internalMessage := fmt.Sprintf("To: %s\n\n%s", dummyAddress, string(randomBytes))

    // This check should never fail with proper calculations, but keep as safety
    if len(internalMessage) > MaxUserPayload {
        // If somehow still too large, truncate the random payload
        excess := len(internalMessage) - MaxUserPayload
        if size > excess {
            randomBytes = randomBytes[:size-excess]
            internalMessage = fmt.Sprintf("To: %s\n\n%s", dummyAddress, string(randomBytes))
        }
        // If still too large after truncation, drop this message silently
        if len(internalMessage) > MaxUserPayload {
            return
        }
    }

    firstNode := strings.TrimSpace(nodes[0])
    firstMixnode, found := findMixnode(mixnodes, firstNode)
    if !found {
        return
    }

    if len(nodes) == 1 {
        // Single node chain - CORRECT ORDER: padding then encryption
        pubKey, found := findPublicKey(pubKeys, firstNode)
        if !found {
            return
        }
        
        // Calculate exact available space for encryption
        routingHeader := []byte("To: " + dummyAddress + "\n\n")
        availableForPadding := MaxTotalSize - len(routingHeader) - 56 // 56 bytes for encryption overhead
        
        paddedMessage, err := adaptivePadding([]byte(internalMessage), availableForPadding)
        if err != nil {
            // If padding fails, use original message
            paddedMessage = []byte(internalMessage)
        }
        
        encryptedData, err := encryptMessageRawSecure(paddedMessage, pubKey)
        if err != nil {
            return
        }
        
        // Add routing header after encryption
        finalMessage := append(routingHeader, encryptedData...)
        
        // Final size check - should never exceed with proper calculations
        if len(finalMessage) > MaxTotalSize {
            // If somehow still too large, truncate (should never happen)
            if len(finalMessage) > MaxTotalSize {
                finalMessage = finalMessage[:MaxTotalSize]
            }
        }
        
        err = uploadFileSecure(firstMixnode.Address, bytes.NewReader(finalMessage))
        if err != nil && !quietMode {
            fmt.Printf("Upload failed: %v\n", err)
        } else if !quietMode {
            fmt.Printf("Cover message sent to %s\n", firstNode)
        }
    } else {
        // Multi-node chain - build onion
        encryptedMessage, err := encryptForChainSecure(internalMessage, nodes, pubKeys, mixnodes)
        if err != nil {
            if !quietMode {
                fmt.Printf("Encryption failed: %v\n", err)
            }
            return
        }
        
        // Final size check for multi-node messages
        if len(encryptedMessage) > MaxTotalSize {
            // If somehow too large, truncate (should never happen)
            if len(encryptedMessage) > MaxTotalSize {
                encryptedMessage = encryptedMessage[:MaxTotalSize]
            }
        }
        
        err = uploadFileSecure(firstMixnode.Address, strings.NewReader(encryptedMessage))
        if err != nil && !quietMode {
            fmt.Printf("Upload failed: %v\n", err)
        } else if !quietMode {
            fmt.Printf("Cover message sent through %d mixnodes\n", len(nodes))
        }
    }
}

// encryptForChainSecure builds encrypted onion message for multi-node chain with precise size control
func encryptForChainSecure(plaintext string, nodes []string, pubKeys []KeyEntry, mixnodes []MixnodeEntry) (string, error) {
    currentMessage := []byte(plaintext)

    // Encryption overhead per layer
    const encryptionOverhead = 56 // 32B Public Key + 24B Nonce

    // Build onion from inside out
    for i := len(nodes) - 1; i >= 0; i-- {
        currentNode := strings.TrimSpace(nodes[i])

        pubKey, found := findPublicKey(pubKeys, currentNode)
        if !found {
            return "", fmt.Errorf("public key not found for: %s", currentNode)
        }

        // Determine next hop address
        var nextHop string
        var routingHeader []byte
        
        if i == len(nodes)-1 {
            // Final hop - extract recipient from plaintext
            lines := strings.SplitN(plaintext, "\n", 2)
            if len(lines) > 0 && strings.HasPrefix(lines[0], "To:") {
                nextHop = strings.TrimSpace(strings.TrimPrefix(lines[0], "To:"))
                routingHeader = []byte("To: " + nextHop + "\n\n")
            } else {
                return "", fmt.Errorf("invalid plaintext format")
            }
        } else {
            // Intermediate hop - route to next mixnode
            nextNode := strings.TrimSpace(nodes[i+1])
            nextMixnode, found := findMixnode(mixnodes, nextNode)
            if !found {
                return "", fmt.Errorf("mixnode not found: %s", nextNode)
            }
            nextHop = nextMixnode.Address
            routingHeader = []byte("To: " + nextHop + "\n\n")
        }

        // Calculate maximum payload size for this layer
        maxPayloadSize := MaxTotalSize
        
        // Subtract encryption overhead
        maxPayloadSize -= encryptionOverhead
        
        // For outer layer (i == 0), subtract routing header that will be added later
        if i == 0 {
            maxPayloadSize -= len(routingHeader)
        }

        // Construct payload for this layer
        var payloadToEncrypt []byte
        
        if i == len(nodes)-1 {
            // Innermost layer: plaintext only
            payloadToEncrypt = currentMessage
        } else {
            // Intermediate layers: routing header + encrypted data from inner layer
            payloadToEncrypt = append(routingHeader, currentMessage...)
        }

        // Apply padding only to outermost layer
        if i == 0 {
            paddedPayload, err := adaptivePadding(payloadToEncrypt, maxPayloadSize)
            if err != nil {
                paddedPayload = payloadToEncrypt
            }
            // Ensure padded payload doesn't exceed limits
            if len(paddedPayload) > maxPayloadSize {
                paddedPayload = paddedPayload[:maxPayloadSize]
            }
            payloadToEncrypt = paddedPayload
        } else {
            // For inner layers, ensure payload fits without padding
            if len(payloadToEncrypt) > maxPayloadSize {
                return "", fmt.Errorf("payload too large at layer %d: %d > %d", 
                    i, len(payloadToEncrypt), maxPayloadSize)
            }
        }

        // Encrypt payload for current node
        encryptedPayload, err := encryptMessageRawSecure(payloadToEncrypt, pubKey)
        if err != nil {
            return "", fmt.Errorf("encryption error for %s: %v", currentNode, err)
        }

        // Construct final message for this layer
        if i == 0 {
            // Outermost layer: add routing header after encryption
            currentMessage = append(routingHeader, encryptedPayload...)
        } else {
            currentMessage = encryptedPayload
        }

        // Final verification - should never exceed with proper calculations
        if len(currentMessage) > MaxTotalSize {
            return "", fmt.Errorf("layer %d exceeds size limit: %d > %d", 
                i, len(currentMessage), MaxTotalSize)
        }
    }

    return string(currentMessage), nil
}

// encryptMessageRawSecure encrypts using NaCl Box with raw binary output
func encryptMessageRawSecure(plaintext []byte, serverPubKey [32]byte) ([]byte, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %v", err)
	}

	var clientPubKey, clientPrivKey [32]byte
	copy(clientPubKey[:], publicKey[:])
	copy(clientPrivKey[:], privateKey[:])

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %v", err)
	}

	encrypted := box.Seal(nil, plaintext, &nonce, &serverPubKey, &clientPrivKey)

	output := make([]byte, 32+24+len(encrypted))
	copy(output[0:32], clientPubKey[:])
	copy(output[32:56], nonce[:])
	copy(output[56:], encrypted)
	
	return output, nil
}

// uploadFileSecure uploads file via Tor proxy (RAW binary data)
func uploadFileSecure(serverAddress string, data io.Reader) error {
	defer func() {
		if r := recover(); r != nil {
			if !quietMode {
				fmt.Printf("PANIC in upload: %v\n", r)
			}
		}
	}()

	if !strings.HasPrefix(serverAddress, "http://") && !strings.HasPrefix(serverAddress, "https://") {
		serverAddress = "http://" + serverAddress
	}
	
	// Ensure port is included
	if !strings.Contains(serverAddress, ":") {
		serverAddress = serverAddress + ":8080"
	}
	
	serverURL := serverAddress + "/upload"

	// Read the message data
	content, err := io.ReadAll(data)
	if err != nil {
		return err
	}

	// Send raw binary data instead of multipart form
	body := bytes.NewReader(content)

	dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   30 * time.Second,
	}

	request, err := http.NewRequest("POST", serverURL, body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("User-Agent", "OnionCourier-Cover/1.0")

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	_, err = io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed with status %d", response.StatusCode)
	}

	return nil
}

// generateRandomOnionV3Address generates random onion v3 address
func generateRandomOnionV3Address() string {
	base32Chars := "abcdefghijklmnopqrstuvwxyz234567"
	var result strings.Builder
	for i := 0; i < 56; i++ {
		charIndex := secureRandInt(len(base32Chars))
		result.WriteByte(base32Chars[charIndex])
	}
	return result.String()
}

// loadPublicKeys loads public keys from PEM file
func loadPublicKeys(filename string) ([]KeyEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var keys []KeyEntry
	content := string(data)
	
	lines := strings.Split(content, "\n")
	
	var currentName string
	var currentPEM strings.Builder
	inPEMBlock := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "-----BEGIN") {
			inPEMBlock = true
			currentPEM.Reset()
			currentPEM.WriteString(line)
			currentPEM.WriteString("\n")
		} else if strings.HasPrefix(line, "-----END") {
			currentPEM.WriteString(line)
			currentPEM.WriteString("\n")
			inPEMBlock = false
			
			if currentName != "" {
				block, _ := pem.Decode([]byte(currentPEM.String()))
				if block != nil && len(block.Bytes) == 32 {
					var key [32]byte
					copy(key[:], block.Bytes)
					keys = append(keys, KeyEntry{Name: currentName, Key: key})
				}
			}
			currentName = ""
		} else if inPEMBlock {
			currentPEM.WriteString(line)
			currentPEM.WriteString("\n")
		} else if line != "" && currentName == "" && !strings.HasPrefix(line, "-----") {
			currentName = line
		}
	}
	
	return keys, nil
}

// loadMixnodeAddresses loads mixnode addresses from configuration file
func loadMixnodeAddresses(filename string) ([]MixnodeEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var mixnodes []MixnodeEntry
	content := string(data)
	
	lines := strings.Split(content, "\n")
	var currentName string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		if currentName == "" {
			currentName = line
		} else {
			address := line
			if !strings.Contains(address, ":") {
				address = address + ":8080"
			}
			mixnodes = append(mixnodes, MixnodeEntry{
				Name:    currentName,
				Address: address,
			})
			currentName = ""
		}
	}
	
	return mixnodes, nil
}

// findPublicKey finds public key by name
func findPublicKey(keys []KeyEntry, name string) ([32]byte, bool) {
	for _, key := range keys {
		if key.Name == name {
			return key.Key, true
		}
	}
	return [32]byte{}, false
}

// findMixnode finds mixnode by name
func findMixnode(mixnodes []MixnodeEntry, name string) (MixnodeEntry, bool) {
	for _, mixnode := range mixnodes {
		if mixnode.Name == name {
			return mixnode, true
		}
	}
	return MixnodeEntry{}, false
}

// hasDuplicates checks for duplicate node names in chain
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
