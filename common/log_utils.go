package common

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func NewConnectionLog(conn ssh.ConnMetadata) *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"remote-addr":    conn.RemoteAddr().String(),
		"client-version": string(conn.ClientVersion()),
	})
}
