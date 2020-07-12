package common

import (
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func TestGetFingerprint(t *testing.T) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCRgSzQfz1CpJYDNIsOMgBqdjcXKdtR4hBMspWvoVLTU7MEgJOxgscPA1bEDd4OiE/nbDm8hg8edUj6dePniI0DtgZ6bu5YZ9QKsJOmpwenW+fv+IsmJAJftsW55Z4DFlS8G4eyIju23RYojDXZ7UYz2RAGdbo1dVDUTRr32JUY76gl0MTi74qupup/OWDShgGrhglvbRRSBMGIGfK681N//0VON3YKDG6GxZyrPFVjbn9dTa2JDzuzpn7D0e9ZoVL4LEApnlQkNf8t7ueOka7azGTdE5AcM9N5bmidpoditEPoq0cdu2iYeuxS0N+v5wNowvF4nHLC/6uTfesSsp8F"))
	if err != nil {
		panic(err)
	}

	want := strings.ReplaceAll(ssh.FingerprintLegacyMD5(publicKey), ":", "")
	got := GetFingerprint(publicKey)
	if want != got {
		t.Errorf("GetFingerprint(), want: %s, got: %s", want, got)
	}
}
