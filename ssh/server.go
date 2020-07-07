package ssh

import (
	"fmt"
	"io"
	"net"
	"r-ssh/common"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var logger = logrus.WithField("component", "ssh-server")

type ForwardHandler func(origin net.Addr) (io.ReadWriteCloser, string, error)

type Server struct {
	config   *ssh.ServerConfig
	endpoint string
	provider AuthProvider
	host     string

	redirectLock sync.Mutex
	redirects    map[string]ForwardHandler
}

type Connection struct {
	conn         *ssh.ServerConn
	messages     chan string
	shutdownChan chan struct{}
	log          *logrus.Entry
	subdomains   map[string]struct{}
}

func (c *Connection) WriteMessage(str string) {
	select {
	case <-c.shutdownChan:
	case c.messages <- str:
	default:
	}
}

func (c *Connection) WriteFailed(msg portForwardRequest, err error) {
	c.WriteMessage(fmt.Sprintf("failed: %s:%d -> %s\n\r", msg.Address, msg.Port, err))
}

func (c *Connection) WriteSuccess(msg portForwardRequest, host, subdomain string) {
	c.WriteMessage(fmt.Sprintf("success: %s:%d -> %s.%s\n\r", msg.Address, msg.Port, subdomain, host))
}

func (s *Server) GetForwardHandler(subdomain string) (ForwardHandler, error) {
	s.redirectLock.Lock()
	defer s.redirectLock.Unlock()

	handler, ok := s.redirects[subdomain]
	if !ok {
		return nil, ErrForwardNotFound
	}
	return handler, nil
}

func (s *Server) publicKeyCallback(_ ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	fingerprint := common.GetFingerprint(pubKey)
	if !s.provider.Auth(fingerprint) {
		return nil, ErrAuthNotAllowed
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			extensionFingerprint: fingerprint,
		},
	}, nil
}

func connectionLog(conn ssh.ConnMetadata) *logrus.Entry {
	return logger.WithFields(logrus.Fields{
		"remote-addr":    conn.RemoteAddr().String(),
		"client-version": string(conn.ClientVersion()),
	})
}

func (s *Server) authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	connectionLog := connectionLog(conn).WithField("method", method)
	if err == nil {
		connectionLog.Info("auth successful")
	} else {
		connectionLog.WithError(err).Warnln("auth failed")
	}
}

func (s *Server) bannerCallback(ssh.ConnMetadata) string {
	return BannerMessage
}

func (s *Server) createForwardHandler(connection Connection, msg portForwardRequest) ForwardHandler {
	return func(origin net.Addr) (io.ReadWriteCloser, string, error) {
		originAddr, originPortRaw, _ := net.SplitHostPort(origin.String())
		originPort, err := strconv.Atoi(originPortRaw)
		if err != nil {
			return nil, msg.Address, err
		}

		payload := ssh.Marshal(&remoteForwardData{
			DestAddress:   msg.Address,
			DestPort:      msg.Port,
			OriginAddress: originAddr,
			OriginPort:    uint32(originPort),
		})

		channel, reqs, err := connection.conn.OpenChannel(forwardedChannelType, payload)
		if err != nil {
			_ = connection.conn.Close()
			return nil, msg.Address, err
		}
		go ssh.DiscardRequests(reqs)
		return channel, msg.Address, nil
	}
}

func (s *Server) addForwardHandler(conn Connection, subdomain string, handler ForwardHandler) error {
	s.redirectLock.Lock()
	defer s.redirectLock.Unlock()

	_, ok := s.redirects[subdomain]
	if ok {
		return ErrForwardAlreadyBinded
	}

	s.redirects[subdomain] = handler
	conn.subdomains[subdomain] = struct{}{}
	return nil
}

func (s *Server) removeForwardHandler(conn Connection, subdomain string) {
	s.redirectLock.Lock()

	delete(s.redirects, subdomain)
	delete(conn.subdomains, subdomain)

	s.redirectLock.Unlock()
}

func (s *Server) handleForward(conn Connection, payload []byte) ([]byte, error) {
	var msg portForwardRequest

	err := ssh.Unmarshal(payload, &msg)
	if err != nil {
		return nil, err
	}

	fingerprint, ok := conn.conn.Permissions.Extensions[extensionFingerprint]
	if !ok {
		return nil, ErrUnknownFingerprint
	}

	subdomain := common.MakeSubdomain(fingerprint, msg.Address, msg.Port)

	err = s.addForwardHandler(conn, subdomain, s.createForwardHandler(conn, msg))
	if err != nil {
		conn.WriteFailed(msg, err)
		return nil, err
	}

	conn.WriteSuccess(msg, s.host, subdomain)
	return ssh.Marshal(portForwardResponse{Port: msg.Port}), nil
}

func (s *Server) handleForwardCancel(conn Connection, payload []byte) ([]byte, error) {
	var msg portForwardRequest

	err := ssh.Unmarshal(payload, &msg)
	if err != nil {
		return nil, err
	}

	fingerprint, ok := conn.conn.Permissions.Extensions[extensionFingerprint]
	if !ok {
		return nil, ErrUnknownFingerprint
	}

	subdomain := common.MakeSubdomain(fingerprint, msg.Address, msg.Port)
	s.removeForwardHandler(conn, subdomain)
	return nil, nil
}

func (s *Server) handleRequests(connection Connection, reqs <-chan *ssh.Request) {
	log := connection.log
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			response, err := s.handleForward(connection, req.Payload)
			if err != nil {
				log.WithError(err).Warnln("forward failed")
			}

			err = req.Reply(err == nil, response)
			if err != nil {
				log.WithError(err).Warnln("tcpip-forward reply failed")
			}
		case "cancel-tcpip-forward":
			response, err := s.handleForwardCancel(connection, req.Payload)
			if err != nil {
				log.WithError(err).Warnln("cancel forward failed")
			}

			err = req.Reply(err == nil, response)
			if err != nil {
				log.WithError(err).Warnln("cancel-tcpip-forward reply failed")
			}
		default:
			err := req.Reply(false, nil)
			if err != nil {
				log.WithError(err).Warnln("reply failed")
			}
		}
	}
}

func (s *Server) handleChannels(connection Connection, channels <-chan ssh.NewChannel) {
	log := connection.log
	for newChannel := range channels {
		channelType := newChannel.ChannelType()
		if channelType != "session" {
			err := newChannel.Reject(ssh.UnknownChannelType, "not supported")
			if err != nil {
				log.WithError(err).Warnln("reject channel failed")
			}
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.WithError(err).Warnln("accept channel failed")
			continue
		}

		go func() {
			for req := range requests {
				if !req.WantReply {
					continue
				}
				err := req.Reply(req.Type == "shell", nil)
				if err != nil {
					log.WithError(err).Warnln("channel reply failed")
				}
			}
		}()

		go func() {
			for {
				select {
				case str := <-connection.messages:
					_, err = channel.Write([]byte(str))
					if err != nil {
						log.WithError(err).Warnln("write message failed")
						return
					}
				case <-connection.shutdownChan:
					return
				}
			}
		}()
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
			logger.WithError(err).Warnln("accept failed")
			continue
		}

		conn, channels, reqs, err := ssh.NewServerConn(tcpConn, s.config)
		if err != nil {
			logger.WithError(err).Warnln("handshake failed")
			continue
		}

		connectionLog := connectionLog(conn)
		connectionLog.Infoln("accepted ssh connection")

		connection := Connection{
			conn:         conn,
			messages:     make(chan string, MessageBufferSize),
			shutdownChan: make(chan struct{}),
			subdomains:   make(map[string]struct{}),
			log:          connectionLog,
		}

		go s.handleChannels(connection, channels)
		go s.handleRequests(connection, reqs)

		go func() {
			err := conn.Wait()
			if err != nil && err != io.EOF {
				connectionLog.WithError(err).Warnln("connection closed with error")
			}

			close(connection.shutdownChan)
			close(connection.messages)

			for subdomain := range connection.subdomains {
				s.removeForwardHandler(connection, subdomain)
			}
		}()
	}
}

func NewServer(endpoint, host, hostKey string, provider AuthProvider) (*Server, error) {
	key, err := loadOrGenerateHostKey(hostKey)
	if err != nil {
		return nil, err
	}

	server := Server{
		endpoint:  endpoint,
		provider:  provider,
		host:      host,
		redirects: make(map[string]ForwardHandler),
	}
	server.config = &ssh.ServerConfig{
		PublicKeyCallback: server.publicKeyCallback,
		AuthLogCallback:   server.authLogCallback,
		BannerCallback:    server.bannerCallback,
	}
	server.config.AddHostKey(key)
	return &server, nil
}
