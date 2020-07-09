package ssh

import (
	"golang.org/x/crypto/ssh"
	"net"
	"time"
)

type channelConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	channel    ssh.Channel
}

func (c *channelConn) Read(b []byte) (n int, err error)  { return c.channel.Read(b) }
func (c *channelConn) Write(b []byte) (n int, err error) { return c.channel.Write(b) }
func (c *channelConn) LocalAddr() net.Addr               { return c.localAddr }
func (c *channelConn) RemoteAddr() net.Addr              { return c.remoteAddr }
func (c *channelConn) SetDeadline(time.Time) error       { return nil }
func (c *channelConn) SetReadDeadline(time.Time) error   { return nil }
func (c *channelConn) SetWriteDeadline(time.Time) error  { return nil }
func (c *channelConn) Close() error {
	return nil
}

func NewChannelConn(localAddr, remoteAddr net.Addr, channel ssh.Channel) net.Conn {
	return &channelConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		channel:    channel,
	}
}
