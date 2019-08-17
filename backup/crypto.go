package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"math"
	"os"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/xerrors"
)

const SaltFile = "salt.bin"

func encryptFile(source, dest string, key []byte) error {
	fileContent, err := ioutil.ReadFile(source)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	encryptedContent := aesgcm.Seal(nonce, nonce, fileContent, nil)

	if err = ioutil.WriteFile(dest, encryptedContent, os.ModePerm); err != nil {
		return err
	}

	return nil
}

func decryptFiles(pin string, files []string) error {
	decKey := deriveEncryptionKey(pin)

	for i, p := range files {
		if p == SaltFile {
			continue
		}

		destPath := p + ".decrypted"
		err := decryptFile(p, destPath, decKey)
		if err != nil {
			return xerrors.New("Failed to restore backup due to incorrect PIN")
		}
		if err = os.Remove(files[i]); err != nil {
			return err
		}
		if err = os.Rename(destPath, files[i]); err != nil {
			return err
		}
	}

	return nil
}

func decryptFile(source, dest string, key []byte) error {
	fileContent, err := ioutil.ReadFile(source)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := aesgcm.NonceSize()
	nonce, cipherContent := fileContent[:nonceSize], fileContent[nonceSize:]

	decryptedContent, err := aesgcm.Open(nil, nonce, cipherContent, nil)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(dest, decryptedContent, os.ModePerm); err != nil {
		return err
	}

	return nil
}

func generateSalt() ([]byte, error) {
	const saltLength = 32

	var salt = make([]byte, saltLength)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	if n != saltLength {
		return nil, xerrors.New("unexpected salt length")
	}

	return salt, nil
}

func initSalt() error {
	salt, err := generateSalt()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(SaltFile, salt, os.ModePerm)
}

func deriveScryptKey(pin string, salt []byte) []byte {
	// NOTE: N, r, and p params used as per doc recommendation:
	//      https://godoc.org/golang.org/x/crypto/scrypt

	// N has to be a power of 2
	var N = int(math.Pow(2, 15))

	sum, err := scrypt.Key([]byte(pin), []byte(salt), N, 8, 1, 32)
	if err != nil {
		panic("Scrypt constant params are configured incorrectly.  Can.  Not.  Continue.")
	}
	return sum[:]
}

func deriveSha256Key(pin string) []byte {
	sum := sha256.Sum256([]byte(pin))
	return sum[:]
}

func deriveEncryptionKey(pin string) []byte {
	if pin == "" {
		return nil
	}

	salt, err := ioutil.ReadFile(SaltFile)
	if err != nil {
		if os.IsNotExist(err) {
			return deriveSha256Key(pin)
		}

		// TODO: on unknown error while reading salt ??? 🤔
	}

	return deriveScryptKey(pin, salt)
}
