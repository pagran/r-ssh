package common

import (
	"crypto/md5"
	"encoding/hex"

	"golang.org/x/crypto/ssh"
)

func GetFingerprint(pubKey ssh.PublicKey) string {
	fingerprint := md5.Sum(pubKey.Marshal())
	return hex.EncodeToString(fingerprint[:])
}
