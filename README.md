# Onion Courier Tor Hidden Service Mixnet

Onion Courier is a production-ready anonymous communication system that implements a **mixnet architecture over Tor hidden services**. It provides strong anonymity guarantees against both local and global adversaries through **cryptographic layered encryption**, **traffic analysis protection**, and **systematic cover traffic integration**.

---

## Features

- **Strong Anonymity Guarantees**: Protection against both local and global adversaries
- **Mixnet Architecture**: Decentralized network routing through multiple intermediary nodes  
- **Forward Secrecy**: Automatic key rotation every 12 hours for pool encryption
- **Cover Traffic Integration**: Systematic dummy message generation to obscure communication patterns  
- **Timing Attack Protection**: Randomized delays and constant-time cryptographic operations  
- **Replay Protection**: Cache-based message ID tracking with automatic expiration
- **Tor Integration**: Operates exclusively over Tor hidden services for enhanced privacy
- **Batch Processing**: Message batching with shuffling for traffic analysis resistance
- **Fixed-Size Messages**: All messages 32KB in RAM to prevent size correlation attacks
- **Encrypted Message IDs**: No metadata leakage in message identifiers

---

## Technical Architecture

### System Design

Onion Courier operates as a decentralized mix network where messages are routed through multiple intermediary nodes called **mix nodes** before reaching their final destination. The system follows the classic mixnet paradigm first proposed by [**David Chaum**](https://en.wikipedia.org/wiki/David_Chaum), where each mix node sequentially peels off one layer of encryption, providing **unlinkability** between incoming and outgoing messages.

### Core Components

- **Mixnode Server**: Go-based concurrent server implementation with forward secrecy
- **Command-Line Client**: POSIX-compliant command-line interface  
- **Cover Traffic Daemon**: Automated dummy message generation system    
- **Endpoint Server**: For receiving messages from the Mixnet or directly with ocsend-client  

---

## Cryptographic Implementation

### Asymmetric Encryption

- **NaCl Box**: Curve25519 for key exchange, XSalsa20 for encryption, and Poly1305 for authentication  
- **Key Management**: Persistent X25519 key pairs for mixnodes   
- **Private Key Storage**: 32-byte keys stored in PEM format at `private.pem` with filesystem hardening  
- **Public Key Distribution**: 32-byte public keys distributed through `pubring.txt` public key registry  

### Symmetric Encryption & Forward Secrecy

- **ChaCha20-Poly1305**: For internal message storage within mixnode pools with forward secrecy
- **Automatic Key Rotation**: Pool encryption keys rotated every 12 hours
- **Dual-Key Support**: Support for both current and next keys during transition periods
- **Nonce Generation**: 12-byte cryptographically random nonces for each encryption  
- **Authentication**: 16-byte Poly1305 authentication tags ensuring message integrity  

---

## Message Protocol

### Layered Encryption Structure

Client → [Encryption Layer N] → Mixnode 1 (Batch Processing + Pool + Delay) → [Encryption Layer N-1] → ... → Final Recipient

**Important**: All messages (including final recipients) go through the mixnet pool with randomized delays and batch processing.

Each encryption layer contains:

- **Routing Header**: `To: <next_hop_address>` specification (except outermost layer)  
- **Encrypted Payload**: Next layer's complete encrypted message  
- **Adaptive Client Padding**: Applied to plaintext layer for traffic analysis protection  

### Binary Message Format

The outermost layer transmitted to the first mix node follows this exact binary structure:

[32 bytes - Client ephemeral public key]
[24 bytes - Encryption nonce]
[N bytes - NaCl Box ciphertext with routing header and encrypted payload]

---

## Advanced Security Features

### Batch Processing & Shuffling
- **Batch Size**: 5-15 messages per batch for optimal anonymity
- **Shuffling**: Cryptographically secure Fisher-Yates shuffle of batch messages
- **Anonymity Set**: Up to 1.3 trillion possible message combinations per batch (15! permutations)
- **Timeout**: 3-minute maximum batch formation time

### Fixed-Size Message Protection
- **All Pool Messages**: Exactly 32KB with cryptographically secure random padding
- **RAM Analysis Protection**: Prevents message size correlation in memory
- **Length Prefixing**: Original message length stored for accurate padding removal

### Encrypted Message Identifiers
- **Message IDs**: Generated and encrypted within message payload
- **No Metadata Leakage**: External observers cannot correlate message IDs with content
- **Replay Protection**: Separate external ID for replay cache using encrypted content hash

### Enhanced Timing Protection
- **Per-Message Delays**: 5-20 minute cryptographically secure random delays
- **Batch Timeouts**: 3-minute maximum wait for batch formation
- **Constant-Time Operations**: All cryptographic operations execute in constant time

---

## Technical Specifications

### Message Size Parameters

| Parameter                  | Value                        |
|---------------------------|------------------------------|
| Maximum User Payload      | 20,480 bytes (20 KB)         |
| Maximum Total Message Size| 28,672 bytes (28 KB)         |
| Pool Message Storage Size | 32,768 bytes (32 KB) fixed   |
| Fixed Padding Size In Pool| 32,768 bytes (32 KB)         |
| Encryption Overhead       | 56 bytes per layer           |
| Number Of Hops Per Chain  | 1-5                          |

### Mixnode Operational Parameters

- **Maximum Pool Capacity**: 400 messages  
- **Minimum Delivery Delay**: 5 minutes (300 seconds)  
- **Maximum Delivery Delay**: 20 minutes (1,200 seconds)  
- **Batch Processing**: 5-15 messages with 3-minute timeout
- **Key Rotation Interval**: 12 hours for forward secrecy
- **Replay Cache Expiration**: 30 minutes with 5-minute cleanup
- **Rate Limiting**: 30 requests per 30 seconds per IP

---

## Quick Start

### Prerequisites

- Go programming language (1.16+)  
- Mix Server: Tor Hidden Service running on `localhost:8080`
- Endpoint Server: Tor Hidden Service running on `localhost:8088` 
- Mix Client: Tor running on `localhost:9050`

## Compiling ocmix-server
In line 1154 of the source code replace the .onion address with your own  
and remember that the server must use port 8080, in order to function  
properly, with public or anonymous Onion Courier Mixnets.  
$ go build -ldflags "-s -w"

## Generate key pair
$ ./ocmix-server -g  
Key pair generated: public.pem and private.pem

## Start mix node server
$ ./ocmix-server -s private.pem  
2025/10/04 11:34:55 🧅 Onion Courier mix node running 🚀  
Press CTRL-Z   
Type 'bg'  
Type 'logout'  

## Download configuration (keys and mix nodes)
$ ./ocmix-client -i  
Downloading config files via Tor...  
Config directory: oc  
✓ Mixnodes file created: oc/mixnodes.txt  
✓ Pubkeys file created: oc/pubring.txt  
Configuration updated successfully!   

## Create your message for an endpoint server
To: vztrzrdafvnjegctrltkv6azyrjqawqmrwnhe7kvaqnj5vvnwhoiq7id.onion:8088

Hello World!

Regards  
Bob

Please note: The endpoint server will remove the first  To: header and  
the blank line following. Keep that in mind if you create messages for  
clearnet emails or Usenet, so that they look like this:    

To: ugf7olo27n5nq2jr6yoai2j5jo24ogx6yemjaozsgxg3byfpcpwdg7id.onion:8088  

From: Onion Courier <noreply\@oc2mx.net>  
To: mail2news@dizum.com  
Subject: Test  
Newsgroups: alt.test.test  

Hello World!

Regards  
Bob

When using an email or Usenet gateway and you like to insert UTF-8  
characters in your From: and Subject: header I recommend using [mbe](https://github.com/Ch1ffr3punk/mbe).   

## Send through 2-5 random nodes
$ ./ocmix-client -r < msg.txt

## Send through specific nodes  
$ ./ocmix-client node1,node2,node3 < msg.txt

## Send cover traffic
$ ./ocmix-client -c

## Ping mix nodes to see their status  
$ ./ocmix-client -p  
```
Checking mix node status via Tor...

bob OK
hal OK
len OK
ulf OK
wau OK
```

If you are a respected member of a privacy community and would  
like your public mix node been listed, just mail me the public key  
and mix node address along with the nickname of your mix node to:  
sacenatorATgmailDOTcom.     

## Start endpoint server
$ ./ochome-server -p inbox

If you plan to run ochome-server on a remote server, I suggest using   
[oget](https://github.com/Ch1ffr3punk/oget), to download messages. 

## Send files directly to an endpoint server     
$ ./ocsend-client address:port < file  

## Security Features
**Forward Secrecy**
**Automatic Key Rotation:** Pool encryption keys rotated every 12 hours

**Dual-Key Support:** Support for current + next key during transition periods

**ChaCha20-Poly1305:** For pool message encryption with forward secrecy

**Replay Protection:**
Cache-based: Uses in-memory cache with automatic cleanup

**30-minute Expiration:** Message IDs automatically deleted after 30 minutes

**Automatic Cleanup:** Removes expired entries every 5 minutes

**Timing Attack Protection:**
Randomized Delays: 5-20 minute random delays per hop using cryptographic RNG

**Constant-Time Processing:** All cryptographic operations in constant time

**Timing Obfuscation:** Cryptographically secure random delays for responses

**Batch Processing:** Message batching with shuffling breaks timing correlations

**Advanced Anonymity Features:**
**Batch Processing:** 5-15 messages per batch with secure shuffling

**Fixed-Size Messages:** All pool messages exactly 32KB to prevent RAM analysis

**Encrypted Message IDs:** No metadata leakage in message identifiers

**Traffic Analysis Resistance:** Batch shuffling creates 1.3 trillion possible combinations

**Size Correlation Protection:** Fixed padding prevents message size tracking

## Anonymity Guarantees
**Sender Anonymity:** Hidden among multiple legitimate users and cover traffic sources

**Receiver Anonymity:** Final destination concealed through multiple routing hops

**Relationship Anonymity:** Computational difficulty correlating message senders and receivers

**Temporal Anonymity:** Randomized delays prevent timing-based correlation attacks

**Global Adversary Protection:** Mixnet architecture protects against network-wide surveillance

**Traffic Analysis Resistance:** Batch processing and shuffling break message correlations

## Attack Resistance
**Traffic Analysis Resistance:** Batch processing, shuffling, and adaptive padding

**Timing Attack Mitigation:** Randomized delays and batch timeouts

**Partial Node Compromise:** Forward secrecy protects older messages

**Size Correlation Protection:** Fixed 32KB messages prevent RAM analysis

**Replay Attack Prevention:** Cache-based message ID tracking

**Network Analysis:** Tor hidden services + mixnet provide layered protection

**RAM Analysis Protection:** All messages identical 32KB size in memory

**Metadata Protection:** Encrypted message IDs prevent correlation attacks

## Network Protocol - HTTP API Endpoints
Mixnodes
Port: 8080

Endpoint: POST /upload

Response: Always "OK" with random timing

Final Recipients
Port: 8088 (or other service port)

Format: Accepts raw POST data

Response: Always "OK" for consistent responses

Message Flow
All messages go through enhanced mixnet processing:

Client → Mixnode 1 (Batch Processing + Pool + 5-20min Delay) → Mixnode 2 (Batch Processing + Pool + 5-20min Delay) → Final Recipient

Pool Management
**Batch Processing:** 5-15 messages with 3-minute timeout and secure shuffling

**Individual Scheduling:** Each message has individual random delay after batch processing

**Fixed-Size Storage:** All messages stored as exactly 32KB in pool

**Secure Randomization:** Cryptographically secure random selection and shuffling

## Threat Model
### Protected Against  
**Traffic Analysis:** Through batch processing, shuffling, and adaptive padding  
**Timing Attacks:** Through randomized delays and batch timeouts  
**Replay Attacks:** Through message-ID cache with expiration  
**Node Compromise:** Forward secrecy protects older messages  
**Size Correlation:** Fixed 32KB messages prevent RAM analysis  
**Partial Network Observation:** Mixnet architecture provides unlinkability  
**Global Adversary:** Multi-hop routing breaks end-to-end correlation  
**Metadata Analysis:** Encrypted message IDs prevent correlation  
**RAM Analysis:** Fixed-size messages prevent memory analysis  

### Security Assumptions  
Tor Hidden Services provide sufficient network-level anonymity  
At least one mix node in the path is trustworthy  
Cryptographic primitives (Curve25519, ChaCha20, Poly1305) are secure  
Operating system provides secure random number generation  

## Dependencies  
memguard: Secure memory handling for cryptographic key protection  
golang.org/x/crypto/nacl/box: Standardized NaCl Box implementation  
golang.org/x/crypto/chacha20poly1305: Standardized ChaCha20+Poly1305  
golang.org/x/net/proxy: SOCKS5 proxy support for Tor integration  
patrickmn/go-cache: In-memory cache for replay protection  

## --
If you like the idea of an own privately run Onion Courier Mixnet,    
as much as I do, consider a small donation.  
```
BTC: 129yB8kL8mQVZufNS4huajsdJPa48aHwHz  
Nym: n1yql04xjhmlhfkjsk8x8g7fynm27xzvnk23wfys  
XMR: 45TJx8ZHngM4GuNfYxRw7R7vRyFgfMVp862JqycMrPmyfTfJAYcQGEzT27wL1z5RG1b5XfRPJk97KeZr1svK8qES2z1uZrS  
```

Or, if you prefer, [buy me a coffee.](https://buymeacoffee.com/ch1ffr3punk)     

The Onion Courier Mixnet is dedicated to Alice and Bob.  












