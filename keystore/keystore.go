package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/bytom/crypto"
	"github.com/bytom/crypto/randentropy"
	"github.com/bytom/errors"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	version = 1

	LightScryptN = 1 << 12
	LightScryptP = 6
	ScryptR      = 8
	ScryptDKLen  = 32
)

var (
	ErrDecrypt = errors.New("could not decrypt key with given passphrase")
)

// Key struct type for keystore file
type Key struct {
	ID      string
	PrivKey string
}

type encryptedKeyJSON struct {
	Crypto  cryptoJSON `json:"crypto"`
	ID      string     `json:"id"`
	Version int        `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

type scryptParamsJSON struct {
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DkLen int    `json:"dklen"`
	Salt  string `json:"salt"`
}

func GetKey(keyPath, password string) (*Key, error) {
	// Load the key from the keystore and decrypt its contents
	keyjson, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	key, err := DecryptKey(keyjson, password)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func StoreKey(keyPath string, key *Key, password string) error {
	keyjson, err := EncryptKey(key, password)
	if err != nil {
		return err
	}

	return writeKeyFile(keyPath, keyjson)
}

func writeKeyFile(file string, content []byte) error {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return err
	}

	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return err
	}

	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}

	f.Close()
	return os.Rename(f.Name(), file)
}

// EncryptKey encrypts a key using the specified scrypt parameters into a json
// blob that can be decrypted later on.
func EncryptKey(key *Key, password string) ([]byte, error) {
	passwordArray := []byte(password)
	salt := randentropy.GetEntropyCSPRNG(32)
	derivedKey, err := scrypt.Key(passwordArray, salt, LightScryptN, ScryptR, LightScryptP, ScryptDKLen)
	if err != nil {
		return nil, err
	}

	encryptKey := derivedKey[:16]
	iv := randentropy.GetEntropyCSPRNG(aes.BlockSize) // 16
	privKeyBytes, err := hex.DecodeString(key.PrivKey)
	if err != nil {
		return nil, err
	}

	cipherText, err := aesCTRXOR(encryptKey, privKeyBytes, iv)
	if err != nil {
		return nil, err
	}

	mac := crypto.Sha256(derivedKey[16:32], cipherText)
	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = LightScryptN
	scryptParamsJSON["r"] = ScryptR
	scryptParamsJSON["p"] = LightScryptP
	scryptParamsJSON["dklen"] = ScryptDKLen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)

	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}
	cryptoStruct := cryptoJSON{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          "scrypt",
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	encryptedKeyJSON := encryptedKeyJSON{
		Crypto:  cryptoStruct,
		ID:      key.ID,
		Version: version,
	}
	return json.MarshalIndent(encryptedKeyJSON, "", "\t")
}

// DecryptKey decrypts a key from a json blob, returning the private key itself.
func DecryptKey(keyjson []byte, password string) (*Key, error) {
	// Parse the json into a simple map to fetch the key version
	m := make(map[string]interface{})
	if err := json.Unmarshal(keyjson, &m); err != nil {
		return nil, err
	}

	k := new(encryptedKeyJSON)
	if err := json.Unmarshal(keyjson, k); err != nil {
		return nil, err
	}

	privkeyBytes, keyID, err := decryptKey(k, password)
	// Handle any decryption errors and return the key
	if err != nil {
		return nil, err
	}

	return &Key{
		ID:      keyID,
		PrivKey: hex.EncodeToString(privkeyBytes),
	}, nil
}

func decryptKey(keyProtected *encryptedKeyJSON, password string) ([]byte, string, error) {
	if keyProtected.Version != version {
		return nil, "", fmt.Errorf("Version not supported: %v", keyProtected.Version)
	}

	if keyProtected.Crypto.Cipher != "aes-128-ctr" {
		return nil, "", fmt.Errorf("Cipher not supported: %v", keyProtected.Crypto.Cipher)
	}

	keyID := keyProtected.ID
	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		return nil, "", err
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, "", err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, "", err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, password)
	if err != nil {
		return nil, "", err
	}

	calculatedMAC := crypto.Sha256(derivedKey[16:32], cipherText)

	if !bytes.Equal(calculatedMAC, mac) {
		return nil, "", ErrDecrypt
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, "", err
	}

	return plainText, keyID, err
}

func getKDFKey(cryptoJSON cryptoJSON, password string) ([]byte, error) {
	authArray := []byte(password)
	salt, err := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}

	dkLen := ensureInt(cryptoJSON.KDFParams["dklen"])

	if cryptoJSON.KDF == "scrypt" {
		n := ensureInt(cryptoJSON.KDFParams["n"])
		r := ensureInt(cryptoJSON.KDFParams["r"])
		p := ensureInt(cryptoJSON.KDFParams["p"])
		return scrypt.Key(authArray, salt, n, r, p, dkLen)

	} else if cryptoJSON.KDF == "pbkdf2" {
		c := ensureInt(cryptoJSON.KDFParams["c"])
		prf := cryptoJSON.KDFParams["prf"].(string)
		if prf != "hmac-sha256" {
			return nil, fmt.Errorf("Unsupported PBKDF2 PRF: %s", prf)
		}

		key := pbkdf2.Key(authArray, salt, c, dkLen, sha256.New)
		return key, nil
	}

	return nil, fmt.Errorf("Unsupported KDF: %s", cryptoJSON.KDF)
}

func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}
