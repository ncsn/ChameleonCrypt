package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
)

func main() {
    key := []byte("thisisa32bytekeyforaesencryption!") // 32 byte = AES-256
    plaintext := []byte("Titkos üzenet")

    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        panic(err)
    }

    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        panic(err)
    }

    ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
    fmt.Printf("Titkosított: %x\n", ciphertext)

    decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Visszafejtve: %s\n", decrypted)
}
