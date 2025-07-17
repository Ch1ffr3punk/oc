package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/awnumar/memguard"
)

func main() {
	defer memguard.Purge()

	fmt.Println("Generating Ed25519 key pair in current directory...")
	generateKeyPair()
}

func savePEM(filename string, data []byte, pemType string) error {
	block := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

func generateKeyPair() {
	privateKeyPath := "private.pem"
	publicKeyPath := "public.pem"

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Neue API für memguard
	privateKeyLockedBuffer := memguard.NewBufferFromBytes(privateKey)
	defer privateKeyLockedBuffer.Destroy()

	err = savePEM(privateKeyPath, privateKeyLockedBuffer.Bytes(), "PRIVATE KEY")
	if err != nil {
		log.Fatalf("Failed to save private key: %v", err)
	}

	err = savePEM(publicKeyPath, publicKey, "PUBLIC KEY")
	if err != nil {
		log.Fatalf("Failed to save public key: %v", err)
	}

	fmt.Printf("Key pair successfully generated and saved:\n")
	fmt.Printf("Private Key: %s\n", privateKeyPath)
	fmt.Printf("Public Key: %s\n", publicKeyPath)
}