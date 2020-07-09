package web

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"net"
	"net/http"
	"r-ssh/ssh"
	"sync"
)

var logger = logrus.WithField("component", "web")

type Server struct {
	host     string
	endpoint string

	sshServer *ssh.Server

	clientPool sync.Pool
	hideInfo   bool
}

var domainSeparator = []byte(".")

func (s *Server) acquireClient(conn net.Conn) *fasthttp.Client {
	client := s.clientPool.Get().(*fasthttp.Client)
	client.Dial = func(string) (net.Conn, error) {
		return conn, nil
	}
	return client
}

func (s *Server) releaseClient(client *fasthttp.Client) {
	client.Dial = nil
	s.clientPool.Put(client)
}

func (s *Server) requestHandler(ctx *fasthttp.RequestCtx) {
	urlParts := bytes.Split(ctx.Host(), domainSeparator)
	if len(urlParts) != 3 {
		ctx.Error("subdomain required", http.StatusBadRequest)
		return
	}

	subdomain := string(urlParts[0])

	handler, err := s.sshServer.ForwardController().GetForwardHandler(subdomain)
	if err != nil {
		ctx.Error(err.Error(), http.StatusBadGateway)
		return
	}

	conn, host, err := handler(ctx.RemoteAddr())
	if err != nil {
		logger.WithError(err).Warnln("create forward failed")
		ctx.Error(err.Error(), http.StatusBadGateway)
		return
	}

	ctx.Request.Header.Set("X-Forwarded-For", ctx.RemoteIP().String())
	ctx.Request.Header.Set("X-Forwarded-Host", string(ctx.Request.Host()))
	if ctx.IsTLS() {
		ctx.Request.Header.Set("X-Forwarded-Proto", "https")
	} else {
		ctx.Request.Header.Set("X-Forwarded-Proto", "http")
	}
	ctx.Request.SetHost(host)

	client := s.acquireClient(conn)
	err = client.Do(&ctx.Request, &ctx.Response)
	s.releaseClient(client)
	if err != nil {
		logger.WithError(err).Warnln("forward request failed")
		ctx.Error(err.Error(), http.StatusBadGateway)
		return
	}

	if !s.hideInfo {
		ctx.Response.Header.Set("X-Source", conn.RemoteAddr().String())
	}

}

func (s *Server) Listen() error {
	return fasthttp.ListenAndServe(s.endpoint, s.requestHandler)
}

func NewServer(sshServer *ssh.Server, endpoint, host string, hideInfo bool) *Server {
	return &Server{
		hideInfo:  hideInfo,
		sshServer: sshServer,
		endpoint:  endpoint,
		host:      host,
		clientPool: sync.Pool{
			New: func() interface{} {
				return &fasthttp.Client{
					MaxConnsPerHost: 1,
					DialDualStack:   false,
				}
			},
		},
	}
}
