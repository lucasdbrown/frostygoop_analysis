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

	"golang.org/x/crypto/scrypt"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage:")
		fmt.Println("  Encrypt: go run go-encrypt.go encrypt <input.json> <output.enc>")
		fmt.Println("  Decrypt: go run go-encrypt.go decrypt <input.enc> <output.json>")
		fmt.Println("  Set GO_ENCRYPT_PASSPHRASE (recommended) or GO_ENCRYPT_KEY (32-byte raw, base64)")
		os.Exit(1)
	}
	op, in, out := os.Args[1], os.Args[2], os.Args[3]

	key, salt, err := loadKey()
	if err != nil { fmt.Println("Key error:", err); os.Exit(1) }

	switch op {
	case "encrypt":
		pt, err := os.ReadFile(in); if err != nil { fatal(err) }
		ct, err := encryptGCM(pt, key) ; if err != nil { fatal(err) }
		// store salt|nonce|ciphertext, all base64
		payload := append(salt, ct...) // ct already includes nonce|ciphertext
		if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(payload)), 0644); err != nil { fatal(err) }
		fmt.Println("Encrypted:", out)
	case "decrypt":
		dataB64, err := os.ReadFile(in); if err != nil { fatal(err) }
		payload, err := base64.StdEncoding.DecodeString(string(dataB64)); if err != nil { fatal(err) }
		if len(payload) < 16 { fatal(errors.New("payload too short")) }
		salt := payload[:16]
		key, err = deriveFromPassOrEnv(salt) // re-derive with same salt
		if err != nil { fatal(err) }
		pt, err := decryptGCM(payload[16:], key); if err != nil { fatal(err) }
		if err := os.WriteFile(out, pt, 0644); err != nil { fatal(err) }
		fmt.Println("Decrypted:", out)
	default:
		fmt.Println("op must be encrypt|decrypt")
	}
}

func loadKey() (key, salt []byte, err error) {
	// Preferred: passphrase + scrypt (automatic, integrity-safe with GCM)
	if os.Getenv("GO_ENCRYPT_PASSPHRASE") != "" {
		salt = make([]byte, 16)
		if _, err = io.ReadFull(rand.Reader, salt); err != nil { return nil, nil, err }
		key, err = deriveFromPassOrEnv(salt)
		return key, salt, err
	}
	// Fallback: raw 32-byte key via base64 env
	if v := os.Getenv("GO_ENCRYPT_KEY"); v != "" {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(raw) != 32 {
			return nil, nil, errors.New("GO_ENCRYPT_KEY must be base64-encoded 32 bytes")
		}
		return raw, make([]byte, 16), nil // dummy salt for layout
	}
	return nil, nil, errors.New("set GO_ENCRYPT_PASSPHRASE or GO_ENCRYPT_KEY")
}

func deriveFromPassOrEnv(salt []byte) ([]byte, error) {
	pass := os.Getenv("GO_ENCRYPT_PASSPHRASE")
	if pass == "" { return nil, errors.New("missing GO_ENCRYPT_PASSPHRASE") }
	// N,r,p tuned for CLI use; adjust upward for more security
	return scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
}

func encryptGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key); if err != nil { return nil, err }
	gcm, err := cipher.NewGCM(block); if err != nil { return nil, err }
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil { return nil, err }
	// output: nonce | ciphertext|tag
	out := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, out...), nil
}

func decryptGCM(in, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key); if err != nil { return nil, err }
	gcm, err := cipher.NewGCM(block); if err != nil { return nil, err }
	if len(in) < gcm.NonceSize() { return nil, errors.New("ciphertext too short") }
	nonce, ct := in[:gcm.NonceSize()], in[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
