package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"

	"golang.org/x/crypto/nacl/secretbox"
)

// TODO, make this into a struct that implements crypto.Symmetric.

const (
	nonceLen  = 24
	secretLen = 32
)

// secret must be 32 bytes long. Use something like Sha256(Bcrypt(passphrase))
// The ciphertext is (secretbox.Overhead + 24) bytes longer than the plaintext.
func EncryptSymmetric(plaintext []byte, secret []byte) (ciphertext []byte) {
	if len(secret) != secretLen {
		panic(fmt.Sprintf("Secret must be 32 bytes long, got len %v", len(secret)))
	}
	nonce := randBytes(nonceLen)
	nonceArr := [nonceLen]byte{}
	copy(nonceArr[:], nonce)
	secretArr := [secretLen]byte{}
	copy(secretArr[:], secret)
	ciphertext = make([]byte, nonceLen+secretbox.Overhead+len(plaintext))
	copy(ciphertext, nonce)
	secretbox.Seal(ciphertext[nonceLen:nonceLen], plaintext, &nonceArr, &secretArr)
	return ciphertext
}

// secret must be 32 bytes long. Use something like Sha256(Bcrypt(passphrase))
// The ciphertext is (secretbox.Overhead + 24) bytes longer than the plaintext.
func DecryptSymmetric(ciphertext []byte, secret []byte) (plaintext []byte, err error) {
	if len(secret) != secretLen {
		panic(fmt.Sprintf("Secret must be 32 bytes long, got len %v", len(secret)))
	}
	if len(ciphertext) <= secretbox.Overhead+nonceLen {
		return nil, errors.New("ciphertext is too short")
	}
	nonce := ciphertext[:nonceLen]
	nonceArr := [nonceLen]byte{}
	copy(nonceArr[:], nonce)
	secretArr := [secretLen]byte{}
	copy(secretArr[:], secret)
	plaintext = make([]byte, len(ciphertext)-nonceLen-secretbox.Overhead)
	_, ok := secretbox.Open(plaintext[:0], ciphertext[nonceLen:], &nonceArr, &secretArr)
	if !ok {
		return nil, errors.New("ciphertext decryption failed")
	}
	return plaintext, nil
}

// This only uses the OS's randomness
func randBytes(numBytes int) []byte {
	b := make([]byte, numBytes)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func encrypt(c *gin.Context) {
	// get data from url
	data := c.Param("data")

	// convert data to byte array
	dataByte := []byte(data)

	secret := randBytes(secretLen)
	ciphertext := EncryptSymmetric(dataByte, secret)

	c.JSON(200, gin.H{"%x\n": ciphertext, "key": secret})

}

func decrypt(c *gin.Context) {
	// get data from url
	data := c.Param("data")
	key := c.Param("key")

	// convert data to byte array
	dataByte := []byte(data)
	keyByte := []byte(key)

	plaintext2, err := DecryptSymmetric(dataByte, keyByte)
	if err != nil {
		panic(err)
	}
	c.JSON(200, gin.H{"%s": plaintext2})
}

// main routing function
func main() {
	router := gin.Default()
	router.GET("/encode/:data", encrypt)
	router.GET("/decode/:data/:key", decrypt)

	router.Run("localhost:8080")
}
