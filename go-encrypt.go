package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Println("Usage:")
		fmt.Println("  Encrypt: go run go-encrypt.go encrypt <keyfile> <input.json> <output.enc>")
		fmt.Println("  Decrypt: go run go-encrypt.go decrypt <keyfile> <input.enc> <output.json>")
		fmt.Println("  Key file must contain exactly 32 bytes for AES-256")
		os.Exit(1)
	}
	op, keyFile, in, out := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	key, err := loadKeyFromFile(keyFile)
	if err != nil { fmt.Println("Key error:", err); os.Exit(1) }

	switch op {
	case "encrypt":
		pt, err := os.ReadFile(in); if err != nil { fatal(err) }
		ct, err := encryptCFB(pt, key); if err != nil { fatal(err) }
		// store IV|ciphertext, all base64
		if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(ct)), 0644); err != nil { fatal(err) }
		fmt.Printf("Successfully encrypted %s to %s using AES-256 CFB with key from %s\n", in, out, keyFile)
	case "decrypt":
		dataB64, err := os.ReadFile(in); if err != nil { fatal(err) }
		ct, err := base64.StdEncoding.DecodeString(string(dataB64)); if err != nil { fatal(err) }
		pt, err := decryptCFB(ct, key); if err != nil { fatal(err) }
		if err := os.WriteFile(out, pt, 0644); err != nil { fatal(err) }
		fmt.Printf("Successfully decrypted %s to %s using AES-256 CFB with key from %s\n", in, out, keyFile)
	default:
		fmt.Println("op must be encrypt|decrypt")
	}
}

func loadKeyFromFile(keyFile string) ([]byte, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %v", keyFile, err)
	}
	
	if len(key) != 32 {
		return nil, fmt.Errorf("key file must contain exactly 32 bytes, got %d bytes", len(key))
	}
	
	return key, nil
}

func encryptCFB(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Generate a random IV (Initialization Vector) for CFB mode
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	
	// Create CFB stream
	stream := cipher.NewCFBEncrypter(block, iv)
	
	// Encrypt the data
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	
	// Combine IV and ciphertext for storage
	// Format: IV (16 bytes) + Ciphertext
	return append(iv, ciphertext...), nil
}

func decryptCFB(in, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Check minimum length (IV + at least 1 byte of data)
	if len(in) < aes.BlockSize+1 {
		return nil, errors.New("encrypted data too short")
	}
	
	// Extract IV and ciphertext
	iv := in[:aes.BlockSize]
	ciphertext := in[aes.BlockSize:]
	
	// Create CFB stream
	stream := cipher.NewCFBDecrypter(block, iv)
	
	// Decrypt the data
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	
	return plaintext, nil
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
