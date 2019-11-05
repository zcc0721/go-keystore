package keystore

import (
	"fmt"
	"os"
	"testing"
)

func TestStoreKey(t *testing.T) {
	keyPath := "mykeystore"
	key := &Key{
		ID:      "testkeyID",
		PrivKey: "1234abcd",
	}
	password := "12345"

	if err := StoreKey(keyPath, key, password); err != nil {
		fmt.Println(err)
	}

	os.Remove(keyPath)
}
