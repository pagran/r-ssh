package web

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"net"
	"net/http"
	"r-ssh/common"
	"r-ssh/ssh"
	"sync"
)

var logger = logrus.WithField("component", "web")

type Server struct {
	host string

	sshServer *ssh.Server

	clientPool  sync.Pool
	hideInfo    bool
	sslRedirect bool
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
	if s.sslRedirect && !ctx.IsTLS() {
		uri := ctx.Request.URI()
		uri.SetScheme("https")

		ctx.Response.Header.Set("Location", string(uri.FullURI()))
		ctx.SetStatusCode(http.StatusPermanentRedirect)
		return
	}
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

	conn, info, err := handler(ctx.RemoteAddr())
	if err != nil {
		logger.WithError(err).Warnln("create forward failed")
		ctx.Error(err.Error(), http.StatusBadGateway)
		return
	}

	req := &ctx.Request

	req.Header.Set("Via", common.ApplicationName)
	req.Header.Set("X-Forwarded-For", ctx.RemoteIP().String())
	req.Header.Set("X-Forwarded-Host", string(req.Host()))
	if ctx.IsTLS() {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	req.SetHost(info.Host)
	if info.RewriteOrigin {
		origin := req.Header.Peek("Origin")
		if origin != nil {
			req.Header.Set("Origin", info.Host)
		}
	}

	if info.Https {
		req.URI().SetScheme("https")
	} else {
		req.URI().SetScheme("http")
	}

	client := s.acquireClient(conn)
	err = client.Do(req, &ctx.Response)
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

func (s *Server) ListenTLS(endpoint, certFile, keyFile string) error {
	return fasthttp.ListenAndServeTLS(endpoint, certFile, keyFile, s.requestHandler)
}

func (s *Server) Listen(endpoint string) error {
	return fasthttp.ListenAndServe(endpoint, s.requestHandler)
}

func NewServer(sshServer *ssh.Server, host string, hideInfo, sslRedirect bool) *Server {
	return &Server{
		hideInfo:    hideInfo,
		sshServer:   sshServer,
		host:        host,
		sslRedirect: sslRedirect,
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
