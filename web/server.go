package web

import (
	"bytes"
	"io"
	"net/http"
	"r-ssh/ssh"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

var logger = logrus.WithField("component", "web")

type Server struct {
	host      string
	endpoint  string
	sshServer *ssh.Server
}

var domainSeparator = []byte(".")

func (s *Server) requestHandler(ctx *fasthttp.RequestCtx) {
	urlParts := bytes.Split(ctx.Host(), domainSeparator)
	if len(urlParts) != 3 {
		ctx.Error("subdomain required", http.StatusBadRequest)
		return
	}

	subdomain := string(urlParts[0])

	handler, err := s.sshServer.GetForwardHandler(subdomain)
	if err != nil {
		ctx.Error(err.Error(), http.StatusBadGateway)
		return
	}

	channel, host, err := handler(ctx.RemoteAddr())
	if err != nil {
		ctx.Error(err.Error(), http.StatusBadGateway)
		return
	}

	ctx.Request.Header.Set("X-Forwarded-For", ctx.RemoteIP().String())
	ctx.Request.Header.Set("Host", host)

	_, err = ctx.Request.Header.WriteTo(channel)
	if err != nil {
		ctx.Error(err.Error(), http.StatusBadGateway)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer channel.Close()

		_, err := io.Copy(ctx.Conn(), channel)
		if err != nil && err != io.EOF {
			logger.WithError(err).Warnln("copy from channel failed")
		}
	}()

	go func() {
		defer wg.Done()
		defer channel.Close()

		_, err := io.Copy(channel, ctx.Conn())
		if err != nil && err != io.EOF {
			logger.WithError(err).Warnln("copy to channel")
		}
	}()

	wg.Wait()
}

func (s *Server) Listen() error {
	return fasthttp.ListenAndServe(s.endpoint, s.requestHandler)
}

func NewServer(sshServer *ssh.Server, endpoint, host string) *Server {
	return &Server{
		sshServer: sshServer,
		endpoint:  endpoint,
		host:      host,
	}
}
