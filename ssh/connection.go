package ssh

import (
	"golang.org/x/crypto/ssh"
	"r-ssh/ssh/terminal"
)

type ConnectionWrapper struct {
	Connection  *ssh.ServerConn
	Fingerprint string
	Terminal    *terminal.BasicTerminal
}
