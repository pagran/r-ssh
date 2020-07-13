package ssh

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"r-ssh/common"
	"r-ssh/ssh/auth"
	"r-ssh/ssh/host_key"
	"r-ssh/ssh/terminal"
)

type Server struct {
	config   *ssh.ServerConfig
	endpoint string
	provider auth.Provider
	host     string

	requestHandlers map[string]Controller

	forwardController *ForwardController
}

func (s *Server) ForwardController() *ForwardController {
	return s.forwardController
}

func (s *Server) publicKeyCallback(_ ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	fingerprint := common.GetFingerprint(pubKey)
	if !s.provider.Auth(fingerprint) {
		return nil, common.ErrAuthNotAllowed
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			common.ExtensionFingerprint: fingerprint,
		},
	}, nil
}

func (s *Server) authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	connectionLog := common.NewConnectionLog(conn).WithField("method", method)
	if err == nil {
		connectionLog.Info("auth successful")
	} else {
		connectionLog.WithError(err).Warnln("auth failed")
	}
}

func (s *Server) bannerCallback(ssh.ConnMetadata) string {
	return common.BannerMessage
}

func (s *Server) handleRequests(connection *ConnectionWrapper, reqs <-chan *ssh.Request) {
	logger := common.NewConnectionLog(connection.Connection)
	for req := range reqs {
		handler, ok := s.requestHandlers[req.Type]
		if !ok {
			err := req.Reply(false, nil)
			if err != nil {
				logger.WithError(err).Warnln("reply failed")
			}
			continue
		}

		reply, err := handler.HandleRequest(connection, req)

		payload := []byte(nil)
		if reply != nil {
			payload = ssh.Marshal(reply)
		}

		if err != nil {
			logger.WithError(err).Warnf("handle %s failed", req.Type)
		}

		err = req.Reply(err == nil, payload)
		if err != nil {
			logger.WithError(err).Warnf("reply %s failed", req.Type)
		}
	}
}

func (s *Server) cleanup(wrapper *ConnectionWrapper) {
	logger := common.NewConnectionLog(wrapper.Connection)

	err := wrapper.Connection.Wait()
	if err != nil && err != io.EOF {
		logger.WithError(err).Warnln("connection closed with error")
	}

	err = s.forwardController.Shutdown(wrapper)
	if err != nil {
		logger.WithError(err).Warnln("shutdown forward failed")
	}
}

func (s *Server) Listen() error {
	listener, err := net.Listen("tcp", s.endpoint)
	if err != nil {
		return err
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.WithError(err).Warnln("accept failed")
			continue
		}

		connection, channels, reqs, err := ssh.NewServerConn(tcpConn, s.config)
		if err != nil {
			log.WithError(err).Warnln("handshake failed")
			continue
		}

		t := terminal.NewBasicTerminal(connection)
		wrapper := &ConnectionWrapper{
			Connection:  connection,
			Fingerprint: connection.Permissions.Extensions[common.ExtensionFingerprint],
			Terminal:    t,
		}

		go t.HandleChannels(channels)
		go s.handleRequests(wrapper, reqs)
		go s.cleanup(wrapper)
	}
}

func NewServer(endpoint, host, hostKey string, provider auth.Provider) (*Server, error) {
	key, err := host_key.LoadOrGenerateHostKey(hostKey)
	if err != nil {
		return nil, err
	}

	forwardController := NewForwardController(host)

	server := Server{
		endpoint:          endpoint,
		provider:          provider,
		host:              host,
		forwardController: forwardController,
		requestHandlers: map[string]Controller{
			"tcpip-forward":        forwardController,
			"cancel-tcpip-forward": forwardController,
		},
	}
	server.config = &ssh.ServerConfig{
		PublicKeyCallback: server.publicKeyCallback,
		AuthLogCallback:   server.authLogCallback,
		BannerCallback:    server.bannerCallback,
	}
	server.config.AddHostKey(key)
	return &server, nil
}
