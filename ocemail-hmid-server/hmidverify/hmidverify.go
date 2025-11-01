package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

type hmid struct {
	keyHash string
	hmid    string
}

const base36Chars = "abcdefghijklmnopqrstuvwxyz0123456789"

func fromBase36Fixed(s string) ([]byte, error) {
	if len(s) != 21 {
		return nil, fmt.Errorf("must be exactly 21 characters")
	}
	
	bigInt := big.NewInt(0)
	
	for i := 0; i < len(s); i++ {
		c := s[i]
		var digit int64
		
		if c >= 'a' && c <= 'z' {
			digit = int64(c - 'a')
		} else if c >= '0' && c <= '9' {
			digit = int64(c - '0' + 26)
		} else {
			return nil, fmt.Errorf("invalid character: %c", c)
		}
		
		bigInt.Mul(bigInt, big.NewInt(36))
		bigInt.Add(bigInt, big.NewInt(digit))
	}
	
	result := make([]byte, 13)
	bytes := bigInt.Bytes()
	
	if len(bytes) < 13 {
		copy(result[13-len(bytes):], bytes)
	} else if len(bytes) == 13 {
		copy(result, bytes)
	} else {
		copy(result, bytes[len(bytes)-13:])
	}
	
	return result, nil
}

func (h *hmid) hmidtest() bool {
	if len(h.hmid) != 21 {
		return false
	}

	hmidBytes, err := fromBase36Fixed(h.hmid)
	if err != nil {
		return false
	}

	iv := hmidBytes[:10]
	receivedHash := hmidBytes[10:]

	keyHashBytes, err := hex.DecodeString(h.keyHash)
	if err != nil {
		return false
	}
	
	digest := sha256.New()
	digest.Write(iv)
	digest.Write(keyHashBytes)
	expectedHash := digest.Sum(nil)[:3]

	for i := 0; i < 3; i++ {
		if expectedHash[i] != receivedHash[i] {
			return false
		}
	}
	return true
}

func main() {
	cmdargs := os.Args[1:]
	switch len(cmdargs) {
	case 2:
		h := new(hmid)
		h.keyHash = cmdargs[0]
		h.hmid = cmdargs[1]
		if !h.hmidtest() {
			fmt.Println("⚠️ M-ID not generated with this hashed password")
			os.Exit(1)
		}
		fmt.Println("✅ M-ID is valid for this hashed password")
	case 1:
		if cmdargs[0] == "--help" || cmdargs[0] == "-h" {
			fmt.Printf("Usage:\n")
			fmt.Printf("  hmidverify <password-hash> <hmid>     - validate hmid\n")
			fmt.Printf("\nNote: Provide the SHA-256 hash of the password as first argument\n")
		} else {
			fmt.Printf("Invalid number of arguments\n")
			fmt.Printf("Use hmidverify --help for usage information\n")
			os.Exit(1)
		}
	default:
		fmt.Printf("Usage:\n")
		fmt.Printf("  hmidverify <password-hash> <hmid>     - validate hmid\n")
		fmt.Printf("  hmidverify --help                     - show this help\n")
		fmt.Printf("\nNote: Provide the SHA-256 hash of the password as first argument\n")
		os.Exit(2)
	}
}
