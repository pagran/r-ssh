package ssh

import (
	"r-ssh/common"
	"testing"

	"golang.org/x/crypto/ssh"
)

var sshKey1 = parseKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCA7BtvAD+J2MxKNpARDbPdHIBLVdCsaV4uOLLstidiGY1Pc9fodOP+nKJqFor+U4AHODOCj+j6hJ4EEaP0bK2FjCOGmiZez2KSuTe67EB/gnJPHHHAs4roHpBtxjXcBXEQfYmbz9hIZW0bIriyYDK7w4KH7CkUNMboBq99BQD6RCaIFNanWiWtdbof5QKI+sHBunXptbqjwLQ7vZD4/J5WMBIwGp4uaqaDX+z9GO43mNtGx9HNIQHweS3amaRiu9ebqkIF8UaePEPxw+xF33srj/p6VQpQIWjABVEpbmHfk9KCgb3/hZdjRs6WId+mdfCCs/fmfjsOMmiFD1ti2BwR")
var sshKey2 = parseKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCJvBBFMl4s2gCDu7tx8UASYFzt4dnBUpc7+uuL48eSvwaYLD2pIGZRL5egaD9+J4mB0lGEg43ckCVaPWA/0HvymHmUyqFoGou7KKveT51D6+T0+OKC3ffF10sszAztYTwQezKy49PrhpdBnhcc3ZR4ohLJOhCG96ggxd8SZTmzfvWGqBJhCGBUr3QB/GZVNDVphfJ9rnI9RX9BEHwrCfyI3be0AQLrtme6/Ou3y29Ja8tFq8yaVMD0Tjd9hCKx85rJqm8WJHMdjx4OiFUu0/s7q0Rnb8O7wmPOpnjKvgWk+iv2mQMko8S312l4PinSJ1jibaUIRJcQLyB87EjKoBdH")

var sshKeys = []ssh.PublicKey{sshKey1, sshKey2}

func parseKey(key string) ssh.PublicKey {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		panic(err)
	}
	return publicKey
}

func TestDefaultAuthProvider_Auth(t *testing.T) {
	for _, key := range sshKeys {
		if !DefaultAuthProvider.Auth(common.GetFingerprint(key)) {
			t.Error("Auth() must always return true")
		}
	}
}

func TestWhitelistAuthProvider_Auth(t *testing.T) {
	allowedFingerprint := common.GetFingerprint(sshKey1)
	authProvider := NewWhitelistAuthProvider([]string{allowedFingerprint})

	if !authProvider.Auth(common.GetFingerprint(sshKey1)) {
		t.Errorf("Auth() must return true for - %s", allowedFingerprint)
		return
	}

	if authProvider.Auth(common.GetFingerprint(sshKey2)) {
		t.Errorf("Auth() must return false for - %s", ssh.FingerprintSHA256(sshKey2))
		return
	}
}
