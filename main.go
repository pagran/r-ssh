package main

import (
	"r-ssh/ssh"
	"r-ssh/ssh/auth"
	"r-ssh/web"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

const applicationName = "rssh"

func main() {
	var cfg Configuration
	err := envconfig.Process(applicationName, &cfg)
	if err != nil {
		logrus.WithError(err).Fatal("process configuration failed")
	}

	logLevel, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.WithError(err).Fatal("parse log level failed")
	}
	logrus.SetLevel(logLevel)
	logrus.SetFormatter(&logrus.TextFormatter{})

	var authProvider auth.AuthProvider
	if len(cfg.PublicKeyWhitelist) == 0 {
		authProvider = auth.DefaultAuthProvider
	} else {
		authProvider = auth.NewWhitelistAuthProvider(cfg.PublicKeyWhitelist)
	}

	sshServer, err := ssh.NewServer(cfg.SSHEndpoint, cfg.Host, cfg.HostKey, authProvider)
	if err != nil {
		logrus.WithError(err).Fatalln("ssh server initialization failed")
	}

	go func() {
		if err = sshServer.Listen(); err != nil {
			logrus.WithError(err).Fatalln("ssh server listen failed")
		}
	}()

	webServer := web.NewServer(sshServer, cfg.WebEndpoint, cfg.Host, cfg.WebHideInfo)
	if err = webServer.Listen(); err != nil {
		logrus.WithError(err).Fatalln("ssh server listen failed")
	}
}
