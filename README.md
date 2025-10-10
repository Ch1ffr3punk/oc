# Onion Courier Tor Hidden Service Mixnet

Onion Courier is a production-ready anonymous communication system that implements a **mixnet architecture over Tor hidden services**. It provides strong anonymity guarantees against both local and global adversaries through **cryptographic layered encryption**, **traffic analysis protection**, and **systematic cover traffic integration**.

---

## Features

- **Strong Anonymity Guarantees**: Protection against both local and global adversaries
- **Mixnet Architecture**: Decentralized network routing through multiple intermediary nodes  
- **Forward Secrecy**: Automatic key rotation every 24 hours for pool encryption
- **Cover Traffic Integration**: Systematic dummy message generation to obscure communication patterns  
- **Timing Attack Protection**: Randomized delays and constant-time cryptographic operations  
- **Replay Protection**: Cache-based message ID tracking with automatic expiration
- **Tor Integration**: Operates exclusively over Tor hidden services for enhanced privacy  

---

## Technical Architecture

### System Design

Onion Courier operates as a decentralized mix network where messages are routed through multiple intermediary nodes called **mix nodes** before reaching their final destination. The system follows the classic mixnet paradigm first proposed by [**David Chaum**](https://en.wikipedia.org/wiki/David_Chaum), where each mix node sequentially peels off one layer of encryption, providing **unlinkability** between incoming and outgoing messages.

### Core Components

- **Mixnode Server**: Go-based concurrent server implementation with forward secrecy
- **Command-Line Client**: POSIX-compliant command-line interface  
- **Cover Traffic Daemon**: Automated dummy message generation system (available upon request)  
- **Endpoint Server**: For receiving messages from the Mixnet 

---

## Cryptographic Implementation

### Asymmetric Encryption

- **NaCl Box**: Curve25519 for key exchange, XSalsa20 for encryption, and Poly1305 for authentication  
- **Key Management**: Persistent X25519 key pairs for mixnodes   
- **Private Key Storage**: 32-byte keys stored in PEM format at `private.pem` with filesystem hardening  
- **Public Key Distribution**: 32-byte public keys distributed through `pubring.txt` public key registry  

### Symmetric Encryption & Forward Secrecy

- **ChaCha20-Poly1305**: For internal message storage within mixnode pools with forward secrecy
- **Automatic Key Rotation**: Pool encryption keys rotated every 24 hours
- **Dual-Key Support**: Support for both current and next keys during transition periods
- **Nonce Generation**: 12-byte cryptographically random nonces for each encryption  
- **Authentication**: 16-byte Poly1305 authentication tags ensuring message integrity  

---

## Message Protocol

### Layered Encryption Structure

Client → [Encryption Layer N] → Mixnode 1 (Pool + Delay) → [Encryption Layer N-1] → ... → Final Recipient


**Important**: All messages (including final recipients) go through the mixnet pool with randomized delays.

Each encryption layer contains:

- **Routing Header**: `To: <next_hop_address>` specification (except outermost layer)  
- **Encrypted Payload**: Next layer's complete encrypted message  
- **Structural Padding**: Applied only to plaintext layer for traffic analysis protection  

### Binary Message Format

The outermost layer transmitted to the first mix node follows this exact binary structure:

[32 bytes - Client ephemeral public key]
[24 bytes - Encryption nonce]
[N bytes - NaCl Box ciphertext with routing header and encrypted payload]



---

## Technical Specifications

### Message Size Parameters

| Parameter                  | Value                        |
|---------------------------|------------------------------|
| Maximum User Payload      | 20,480 bytes (20 KB)         |
| Minimum Total Message Size| 1,024 bytes (1 KB)           |
| Maximum Total Message Size| 25,600 bytes (25 KB)         |
| Pool Message Storage Limit| 32,768 bytes (32 KB)         |
| HTTP Upload Limit         | 28,672 bytes (28 KB)         |
| Encryption Overhead       | 56 bytes per layer           |
| Number Of Hops Per Chain  | 1-5                          |

### Mixnode Operational Parameters

- **Maximum Pool Capacity**: 100 messages  
- **Minimum Delivery Delay**: 5 minutes (300 seconds)  
- **Maximum Delivery Delay**: 20 minutes (1,200 seconds)  
- **Pool Maintenance Interval**: 60-second cleanup cycles  
- **Key Rotation Interval**: 24 hours for forward secrecy
- **Replay Cache Expiration**: 30 minutes with 5-minute cleanup

---

## Quick Start

### Prerequisites

- Go programming language (1.16+)  
- Mix Server: Tor Hidden Service running on `localhost:8080`
- Endpoint Server: Tor Hidden Service running on `localhost:8088` 
- Mix Client: Tor running on `localhost:9050`

## Compiling ocmix-server
In line 1058 of the source code replace the .onion address with your own  
and remember that the server must use port 8080, in order to function  
properly, with public or anonymous Onion Courier Mixnets.  
$ go build -ldflags "-s -w"

## Generate key pair
$ ./ocmix-server -g  
Key pair generated: public.pem and private.pem

## Start mix node server
$ ./ocmix-server -s private.pem  
2025/10/04 11:34:55 🧅 Onion Courier mix node running 🚀  
Press CTRL-Z, press Enter   
Type 'bg', press Enter   
Type 'logout', press Enter    

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

bob                     OK  
hal                     OK  
len                     OK  
ulf                     OK  
wau                     OK
```
If you are a respected member of a privacy community and would  
like your public mix node been listed, just mail me the public key  
and mix node address along with the nickname of your mix node to:  
sacenatorATgmailDOTcom.     

## Start endpoint server (handles both multipart and raw POST)
$ ./ochome-server -p inbox

If you plan to run ochome-server on a remote server, I suggest using   
[oget](https://github.com/Ch1ffr3punk/oget), to download messages. 

## Send files directly to an endpoint server (base64 encoded)    
$ ./ocsend-client address:port < file  

## Security Features
**Forward Secrecy**
**Automatic Key Rotation:** Pool encryption keys rotated every 24 hours

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

## Anonymity Guarantees
**Sender Anonymity:** Hidden among multiple legitimate users and cover traffic sources

**Receiver Anonymity:** Final destination concealed through multiple routing hops

**Relationship Anonymity:** Computational difficulty correlating message senders and receivers

**Temporal Anonymity:** Randomized delays prevent timing-based correlation attacks

**Global Adversary Protection:** Mixnet architecture protects against network-wide surveillance

## Attack Resistance
**Traffic Analysis Resistance:** Outer-layer padding and cover traffic

**Timing Attack Mitigation:** Randomized delays and constant-time operations

**Partial Node Compromise:** Forward secrecy protects older messages

**Size Correlation Protection:** Adaptive padding prevents message size tracking

**Replay Attack Prevention:** Cache-based message ID tracking

**Network Analysis:** Tor hidden services + mixnet provide layered protection

## Network Protocol - HTTP API Endpoints
Mixnodes
Port: 8080

Endpoint: POST /upload

Format: multipart/form-data with field file

Response: Always "OK" with random timing

Final Recipients
Port: 8088 (or other service port)

Format: Accepts both multipart/form-data and raw POST data

Response: Always "OK" for consistent responses

Message Flow
All messages (including final recipients) go through the mixnet pool with randomized delays:

Client → Mixnode 1 (Pool + 5-20min Delay) → Mixnode 2 (Pool + 5-20min Delay) → Final Recipient

Pool Management
Individual Scheduling: Each message has individual random delay

Emergency Batch: On pool overflow, 33% of messages sent immediately with secure randomization

Secure Randomization: Cryptographically secure random selection for batches

## Threat Model
### Protected Against  
**Traffic Analysis:** Through padding and cover traffic  
**Timing Attacks:** Through randomized delays and constant-time operations  
**Replay Attacks:** Through message-ID cache with expiration  
**Node Compromise:** Forward secrecy protects older messages  
**Size Correlation:** Adaptive padding prevents size analysis  
**Partial Network Observation:** Mixnet architecture provides unlinkability  
**Global Adversary:** Multi-hop routing breaks end-to-end correlation  
**Metadata Analysis:** No persistent metadata retention  

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
































