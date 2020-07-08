package ssh

import (
	"golang.org/x/crypto/ssh"
)

type Controller interface {
	HandleRequest(conn *ConnectionWrapper, req *ssh.Request) (interface{}, error)
	Shutdown(conn *ConnectionWrapper) error
}
