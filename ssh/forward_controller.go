package ssh

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"r-ssh/common"
	"strconv"
	"sync"
)

type ForwardHandler func(origin net.Addr) (net.Conn, string, error)

type ForwardController struct {
	redirectLock  sync.Mutex
	redirects     map[string]ForwardHandler
	subdomainsMap map[*ConnectionWrapper]map[string]struct{}
	host          string
}

func (f *ForwardController) HandleRequest(connection *ConnectionWrapper, req *ssh.Request) (interface{}, error) {
	var msg portForwardRequest

	err := ssh.Unmarshal(req.Payload, &msg)
	if err != nil {
		return nil, err
	}

	switch req.Type {
	case "tcpip-forward":
		return f.handleForward(connection, msg.Address, msg.Port)
	case "cancel-tcpip-forward":
		return f.handleForwardCancel(connection, req.Payload)
	default:
		return nil, common.ErrUnknownRequestType
	}
}

func (f *ForwardController) createForwardHandler(connection *ConnectionWrapper, address string, port uint32) ForwardHandler {
	return func(origin net.Addr) (net.Conn, string, error) {
		originAddr, originPortRaw, _ := net.SplitHostPort(origin.String())
		originPort, err := strconv.Atoi(originPortRaw)
		if err != nil {
			return nil, address, err
		}

		payload := ssh.Marshal(&remoteForwardData{
			DestAddress:   address,
			DestPort:      port,
			OriginAddress: originAddr,
			OriginPort:    uint32(originPort),
		})

		channel, reqs, err := connection.Connection.OpenChannel(forwardedChannelType, payload)
		if err != nil {
			_ = connection.Connection.Close()
			return nil, address, err
		}
		go ssh.DiscardRequests(reqs)
		return NewChannelConn(connection.Connection.LocalAddr(), connection.Connection.RemoteAddr(), channel), address, nil
	}
}

func (f *ForwardController) addForwardHandler(conn *ConnectionWrapper, subdomain string, handler ForwardHandler) error {
	f.redirectLock.Lock()
	defer f.redirectLock.Unlock()

	_, ok := f.redirects[subdomain]
	if ok {
		return common.ErrForwardAlreadyBinded
	}

	f.redirects[subdomain] = handler
	subdomains, ok := f.subdomainsMap[conn]
	if !ok {
		subdomains = make(map[string]struct{})
		f.subdomainsMap[conn] = subdomains
	}
	subdomains[subdomain] = struct{}{}
	return nil
}

func (f *ForwardController) removeForwardHandler(conn *ConnectionWrapper, subdomain string) {
	f.redirectLock.Lock()
	defer f.redirectLock.Unlock()
	delete(f.redirects, subdomain)

	subdomains, ok := f.subdomainsMap[conn]
	if ok {
		delete(subdomains, subdomain)
	}
}

func (f *ForwardController) handleForward(conn *ConnectionWrapper, address string, port uint32) (interface{}, error) {
	subdomain := common.MakeSubdomain(conn.Fingerprint, address, port)

	forwardHandler := f.createForwardHandler(conn, address, port)
	err := f.addForwardHandler(conn, subdomain, forwardHandler)
	if err != nil {
		_, _ = conn.Terminal.WriteString(fmt.Sprintf("forward \"%s:%d\" failed: \"%s\"\r\n", address, port, err))
		return nil, err
	}

	_, _ = conn.Terminal.WriteString(fmt.Sprintf("forward \"%s:%d\" to \"%s.%s\"\r\n", address, port, subdomain, f.host))
	return portForwardResponse{Port: port}, nil
}

func (f *ForwardController) handleForwardCancel(conn *ConnectionWrapper, payload []byte) ([]byte, error) {
	var msg portForwardRequest

	err := ssh.Unmarshal(payload, &msg)
	if err != nil {
		return nil, err
	}

	subdomain := common.MakeSubdomain(conn.Fingerprint, msg.Address, msg.Port)
	f.removeForwardHandler(conn, subdomain)
	return nil, nil
}

func (f *ForwardController) GetForwardHandler(subdomain string) (ForwardHandler, error) {
	f.redirectLock.Lock()
	defer f.redirectLock.Unlock()

	handler, ok := f.redirects[subdomain]
	if !ok {
		return nil, common.ErrForwardNotFound
	}
	return handler, nil
}

func (f *ForwardController) Shutdown(conn *ConnectionWrapper) error {
	f.redirectLock.Lock()
	defer f.redirectLock.Unlock()

	subdomains, ok := f.subdomainsMap[conn]
	if !ok {
		return common.ErrForwardNotFound
	}
	delete(f.subdomainsMap, conn)

	for subdomain := range subdomains {
		delete(f.redirects, subdomain)
	}

	return nil
}

func NewForwardController(host string) *ForwardController {
	return &ForwardController{
		host:          host,
		redirects:     make(map[string]ForwardHandler),
		subdomainsMap: make(map[*ConnectionWrapper]map[string]struct{}),
	}
}
