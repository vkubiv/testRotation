package main

import (
	"fmt"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	_ "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
)

func main() {
	msg := []byte("Hello cryto and Rotation")

	keyTemplate := aead.AES256GCMKeyTemplate()
	keyHandle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		print(fmt.Errorf("create: failed to create new keyset handle: %w", err).Error())
		return
	}

	crypto, err := tinkcrypto.New()

	cipherText, nonce, err := crypto.Encrypt(msg, []byte{}, keyHandle)

	km := keyset.NewManagerFromHandle(keyHandle)
	err = km.Rotate(keyTemplate)

	if err != nil {
		print(fmt.Errorf("rotate failed: %w", err).Error())
		return
	}

	updatedKeyHandle, err := km.Handle()

	if testkeyset.KeysetMaterial(updatedKeyHandle) != testkeyset.KeysetMaterial(keyHandle) {
		print("testkeyset.KeysetMaterial(updatedKH) != testkeyset.KeysetMaterial(keyHandle)")
		return
	}

	dec2, err := crypto.Decrypt(cipherText, []byte{}, nonce, updatedKeyHandle)
	if err != nil {
		print(fmt.Errorf("decrypt after rotate failed: %w", err).Error())
		return
	}

	fmt.Printf("Decrypted after rotate: %s\n", string(dec2))
}

/*
func Encrypt(msg []byte, keyHandle *keyset.Handle) []byte {
	aad := make([]byte, 0)

	a, err := aead.New(keyHandle)
	if err != nil {
		panic(fmt.Errorf("create new aead: %w", err))
	}

	cipherText, err := a.Encrypt(msg, aad)

	if err != nil {
		panic(fmt.Errorf("encrypt failed %w", err))
	}
	return cipherText
}

func Decrypt(cipherText []byte, keyHandle *keyset.Handle) []byte {
	aad := make([]byte, 0)

	a, err := aead.New(keyHandle)
	if err != nil {
		panic(fmt.Errorf("create new aead: %w", err))
	}

	msg, err := a.Decrypt(cipherText, aad)

	if err != nil {
		panic(fmt.Errorf("decrypt failed %w", err))
	}
	return msg
}*/
