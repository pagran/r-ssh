package host_key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
	"r-ssh/common"

	"golang.org/x/crypto/ssh"
)

func generateHostKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, common.HostKeySize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func writeHostKey(writer io.Writer, privateKey *rsa.PrivateKey) error {
	pkcs1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   pkcs1PrivateKey,
	}
	return pem.Encode(writer, &block)
}

func readHostKey(reader io.Reader) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func createHostKey(hostKey string) (ssh.Signer, error) {
	f, err := os.OpenFile(hostKey, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, common.HostKeyFilePerm)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	privateKey, err := generateHostKey()
	if err != nil {
		return nil, err
	}

	err = writeHostKey(f, privateKey)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privateKey)
}

func LoadOrGenerateHostKey(hostKey string) (ssh.Signer, error) {
	info, err := os.Stat(hostKey)
	if os.IsNotExist(err) {
		return createHostKey(hostKey)
	}

	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, common.ErrHostKeyIsDirectory
	}

	f, err := os.Open(hostKey)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return readHostKey(f)
}
