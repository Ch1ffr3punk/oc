# Onion Courier Tor Hidden Service Mixnet

Onion Courier is an open-source anonymous communication system that implements a **mixnet architecture over Tor hidden services**. Developed as a research implementation, it provides strong anonymity guarantees through **cryptographic layered encryption**, **traffic analysis protection**, and **systematic cover traffic integration**.

---

## Features

- **Strong Anonymity Guarantees**: Cryptographic layered encryption and traffic analysis protection  
- **Mixnet Architecture**: Decentralized network routing through multiple intermediary nodes  
- **Cover Traffic Integration**: Systematic dummy message generation to obscure communication patterns  
- **Timing Attack Protection**: Randomized delays and constant-time cryptographic operations  
- **Tor Integration**: Operates exclusively over Tor hidden services for enhanced privacy  

---

## Technical Architecture

### System Design

Onion Courier operates as a decentralized mix network where messages are routed through multiple intermediary nodes called **mixnodes** before reaching their final destination. The system follows the classic mixnet paradigm first proposed by [**David Chaum**](https://en.wikipedia.org/wiki/David_Chaum), where each mixnode sequentially peels off one layer of encryption, providing **unlinkability** between incoming and outgoing messages.

### Core Components

- **Mixnode Server**: Go-based concurrent server implementation  
- **Command-Line Client**: POSIX-compliant command-line interface  
- **Cover Traffic Daemon**: Automated dummy message generation system  

---

## Cryptographic Implementation

### Asymmetric Encryption

- **NaCl Box**: Curve25519 for key exchange, XSalsa20 for encryption, and Poly1305 for authentication  
- **Key Management**: Persistent X25519 key pairs for mixnodes, ephemeral key pairs for clients  
- **Private Key Storage**: 32-byte keys stored in PEM format at `private.pem` with filesystem hardening  
- **Public Key Distribution**: 32-byte public keys distributed through `pubring.txt` public key registry  

### Symmetric Encryption

- **ChaCha20-Poly1305**: For internal message storage within mixnode pools  
- **Nonce Generation**: 12-byte cryptographically random nonces for each encryption  
- **Authentication**: 16-byte Poly1305 authentication tags ensuring message integrity  

---

## Message Protocol

### Layered Encryption Structure

Client → [Encryption Layer N] → Mixnode 1 → [Encryption Layer N-1] → ... → Final Destination


Each encryption layer contains:

- **Routing Header**: `To: <next_hop_address>` specification (except outermost layer)  
- **Encrypted Payload**: Next layer's complete encrypted message  
- **Structural Padding**: Applied only to outermost layer for traffic analysis protection  

### Binary Message Format

The outermost layer transmitted to the first mixnode follows this exact binary structure:

[32 bytes - Client ephemeral public key]
[24 bytes - Encryption nonce]
[N bytes - NaCl Box ciphertext with padding]


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
- **Maximum Message Age**: 20 minutes before forced delivery  

---

## Installation & Usage

### Prerequisites

- Go programming language  
- Tor service running on `localhost:9050`  

### Building from Source

git clone https://github.com/Ch1ffr3punk/oc
cd oc
go build

Configuration
Ensure Tor is running with SOCKS5 proxy on localhost:9050
Configure mixnode keys in private.pem and pubring.txt
Set up hidden service endpoints for mixnodes

## Security Features

### Anonymity Guarantees
Sender Anonymity: Hidden among multiple legitimate users and cover traffic sources  
Receiver Anonymity: Final destination concealed through multiple routing hops  
Relationship Anonymity: Computational difficulty correlating message senders and receivers  
Temporal Anonymity: Randomized delays prevent timing-based correlation attacks  

### Attack Resistance  
Traffic Analysis Resistance: Outer-layer padding and cover traffic  
Timing Attack Mitigation: Randomized delays and constant-time operations  
Partial Node Compromise: Single node compromise doesn't reveal complete message paths  
Size Correlation Protection: Selective padding prevents message size tracking  

## Network Protocol - HTTP API Endpoints  
Primary Upload Endpoint: POST /upload with multipart/form-data encoding  
File Field Specification: file field containing complete encrypted message binary  
Response Standardization: Anonymous "OK" responses with timing normalization  
Mixnodes: Port 8080 Endpoints: Port 8088

## Tor Integration  
SOCKS5 Proxy Configuration: localhost:9050 standard Tor proxy  
Hidden Service Operation: .onion address deployment only  
Network Timeouts: 120-second connection and transmission timeouts   

## Dependencies  
memguard : Secure memory handling for cryptographic key protection  
golang.org/x/crypto/nacl/box : Standardized NaCl Box implementation
golang.org/x/crypto/chacha20poly1305 : Standardized ChaCha20+Poly1305  
golang.org/x/net/proxy : SOCKS5 proxy support for Tor integration  
