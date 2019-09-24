package conceal_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/alinz/conceal"
)

type SimpleCipher struct{}

func (sc *SimpleCipher) hash(key string) []byte {
	data := sha256.Sum256([]byte(key))
	return data[0:]
}

func (sc *SimpleCipher) lookupKey(id string) string {
	return "12345"
}

func (sc *SimpleCipher) Encrypt(value []byte, id string) ([]byte, error) {
	key := sc.lookupKey(id)
	block, _ := aes.NewCipher(sc.hash(key))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, value, nil)
	return ciphertext, nil
}

func (sc *SimpleCipher) Decrypt(value []byte, id string) ([]byte, error) {
	key := sc.lookupKey(id)
	block, err := aes.NewCipher(sc.hash(key))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := value[:nonceSize], value[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func TestConceal(t *testing.T) {
	type Class struct {
		Name string `conceal:"data"`
	}

	type User struct {
		ID      string   `conceal:"id"`
		Name    string   `conceal:"data"`
		Classes []*Class `conceal:"data"`
		Top     *Class   `conceal:"data"`
		Bytes   []byte   `conceal:"data"`
	}

	user := &User{
		ID:   "1",
		Name: "John",
		Classes: []*Class{
			{Name: "Cool"},
		},
		Top: &Class{
			Name: "Cool 2",
		},
		Bytes: []byte("hello world"),
	}

	cipher := &SimpleCipher{}

	err := conceal.Encrypt(user, cipher)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(user)
	fmt.Println(user.Classes[0])
	fmt.Println(user.Top)
	fmt.Println(user.Bytes)

	if user.Name == "John" {
		t.Fatal("expect Name to be encrypted")
	}

	err = conceal.Decrypt(user, cipher)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(user)
	fmt.Println(user.Classes[0])
	fmt.Println(user.Top)
	fmt.Println(string(user.Bytes))
}
