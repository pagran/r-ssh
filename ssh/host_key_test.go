package ssh

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"io"
	"testing"
)

func Test_generateHostKey(t *testing.T) {
	hostKey, err := generateHostKey()
	if err != nil {
		t.Errorf("generateHostKey() return error: %s", err)
		return
	}

	err = hostKey.Validate()
	if err != nil {
		t.Errorf("hostKey.Validate() return error: %s", err)
		return
	}

	keyBitLen := hostKey.Size() * 8
	if keyBitLen != HostKeySize {
		t.Errorf("hostKey.Size() got %d, want %d", keyBitLen, HostKeySize)
	}
}

var rsaKeyRaw = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAiw2R1i2NNRYsYUYya2cM8lLO+JY/x1Lp28AB3fAqohragHbp
biPUceyupd2ISOGZeCVvDQdvPdkL8iL3mTnx419aFK+6hfFTgwLgpS4Ivx29r4QQ
0kzuGhD5nL0Sw3H6KRgcaw8YmFjzwLM92dlsQQNEqLDJLgbUqvC8thAVtZo9Jd9v
+UaA7epkSEeJCVUFisRvFhnlpVZr0lFxcJ4ZIT/T1HT4yma8lLEQN6ckRQbpAwJ1
PW9JwlUptCFXH7e6ISkiX53DtWDNqlvOeqmSQNLWNiqVYt86GOMVrDOxkYfquzz7
rme4E+rgwY9Ol84ArsUPk+UXR78QOcV+F3F7VwIDAQABAoIBACBfG1lqJ1p5fAF1
Tx2T0v7C6m4SxGxJ0CmZbJXXaIVujPmlNTiv3LBc8leo2CZnZswCovS8i1gxpEdN
fqjMRZSySQ1Rz7GI+fEhBV1O9zhO2y72Jtheknu9Ae9MUQbxDNTuSQdfb1FgO/bb
g4WoyTvlX+GJrnwpmO7mtngIDJXHJvbuBwNvNoOq37WnqO3+Udycn6WwD8UsI1zY
sT2Hgw8ObIbZo3RaaUKV1ebk8SmxGNl3M9mAR2BIJzcpr0dUCce7BeY8TK9hnyKM
yIla32N9wj6r0IpVYKwIyuSQyiDVVlfMVriVbY0qpe0aJIUb/Uz7SjSC8k6zNchS
ykE0YWkCgYEA1b4FuZ/Tf2HCHySBPUrFwtxxEEmJiI0m97UxqgwCI6nqwX0Hi51g
Nd768O4quysOIFpwbV17xfTJHX7xMCcVS62bYckGZtqZ8Ndq+kKaemRnSGx4Q49p
3sV5ajO2LRvrqdtTRmpd6V4dcUa0GKd5e44XPRka5VM54o5Oa/GsloUCgYEApota
9psegcao6OVMq6j16v59C6LfXn//7QqmOqDziUxJHXYluVHojF1M4AAhSCc9YoOf
Lit9LF+8Nl5ZXwwK7i2r9gaOL5Kr6BR2/m7eo6Rs7yZ3uSIJZj3+p0UVjwlgd1q5
oILftMsKpPWYSO24iKslzpcYANTmSchiANkpVysCgYA5HD/dXEYfqBg9R/y8SslS
iqIvLubvtH9v+lsdy32a1+Dg+C5W8KLvYff8/jYuso9gt6mIn0zeFMzT88IwEpFP
GkEFPLhYLRqqznRIEBnEkCVEpa7wplYsbulFJjIMFYS/atnyW6NiIoKNbM3cNIty
JwIwkg+srLMvxMRRdU6fHQKBgDB760xVlkkDk5LRhkOHGaiC09Z6YPq62r+gVQpG
Zv+2dKaeCZdsz/1lAAdKImZF/ina1ZF0Wal8aWeOiggQknIKW8Bw4h3ZXjBfHNEv
Z6NOL+RjV4FO9luMesEpbIBKo4m7oMSotQWGAqBJWz8H7avj30rIU9WSJUSfkGBc
2BsnAoGBAIv0+YLg7k3fu7s+6ERQZtQSruwi38D+8imTb9vOfLxMKyID2etzCy6u
otK6Otp/1UFjANj8hM/7VPpsSMd15ror0st58YkvjeC9VgIItUkYQLNDOHfWqEe+
Q3TGhkcrMZB5qR2kGMypMl5ek/qjH1Ej2I3EFR73gSMIVptFSLh1
-----END RSA PRIVATE KEY-----
`)

func parsePrivateKey(key []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(key)

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return privateKey
}

var privateKey = parsePrivateKey(rsaKeyRaw)

func Test_writeHostKey(t *testing.T) {
	var buffer bytes.Buffer
	writer := io.Writer(&buffer)

	err := writeHostKey(writer, privateKey)
	if err != nil {
		t.Errorf("writeHostKey() - %s", err)
	}

	if bytes.Compare(rsaKeyRaw, buffer.Bytes()) != 0 {
		t.Errorf("writeHostKey() want %s, got %s", rsaKeyRaw, buffer.String())
	}
}

func Test_readHostKey(t *testing.T) {
	reader := bytes.NewReader(rsaKeyRaw)

	signer, err := readHostKey(reader)
	if err != nil {
		t.Errorf("writeHostKey() - %s", err)
	}

	exceptedPublicKey, _ := ssh.NewPublicKey(privateKey.Public())

	if bytes.Compare(signer.PublicKey().Marshal(), exceptedPublicKey.Marshal()) != 0 {
		t.Errorf("writeHostKey() want %v, got %v", exceptedPublicKey, signer.PublicKey())
	}
}
