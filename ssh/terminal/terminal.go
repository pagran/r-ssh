package terminal

import (
	"bytes"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io"
	"r-ssh/common"
	"sync"
)

type BasicTerminal struct {
	connection *ssh.ServerConn
	logger     *log.Entry

	messageBuffer *bytes.Buffer // Temporary buffer for messages written before "session" request
	messageWriter io.Writer

	messageMutex sync.Mutex
}

func NewBasicTerminal(connection *ssh.ServerConn) *BasicTerminal {
	buffer := &bytes.Buffer{}
	return &BasicTerminal{
		connection:    connection,
		logger:        common.NewConnectionLog(connection),
		messageBuffer: buffer,
		messageWriter: io.Writer(buffer),
	}
}

func (b *BasicTerminal) WriteString(str string) (n int, err error) {
	b.messageMutex.Lock()
	defer b.messageMutex.Unlock()

	return b.messageWriter.Write([]byte(str))
}

func (b *BasicTerminal) handleTerminalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		if !req.WantReply {
			continue
		}
		err := req.Reply(req.Type == "shell" || req.Type == "pty-req", nil)
		if err != nil {
			b.logger.Warnln("channel reply failed")
		}
	}
}

const keyCtrlC = 3

func (b *BasicTerminal) handleKeyboard(channel ssh.Channel) {
	var keyBuffer = make([]byte, 1)
	for {
		_, err := channel.Read(keyBuffer)
		if err != nil {
			if err != io.EOF {
				b.logger.WithError(err).Warnln("read key from channel failed")
			}
			break
		}

		if keyBuffer[0] != keyCtrlC {
			continue
		}

		err = channel.Close()
		if err != nil {
			b.logger.WithError(err).Warnln("close channel via ctrl+cl failed")
		}
	}
}

func (b *BasicTerminal) rejectChannels(channels <-chan ssh.NewChannel) {
	for newChannel := range channels {
		channelType := newChannel.ChannelType()
		if channelType != "session" {
			err := newChannel.Reject(ssh.ResourceShortage, "not allowed")
			if err != nil {
				b.logger.WithError(err).Warnln("reject channel failed")
			}
		}

		channel, _, err := newChannel.Accept()
		if err != nil {
			b.logger.WithError(err).Warnln("accept channel failed")
			continue
		}

		_, err = channel.Write([]byte(common.MultipleSessionMessage))
		if err != nil {
			b.logger.WithError(err).Warnln("channel write failed")
		}
		err = channel.Close()
		if err != nil {
			b.logger.WithError(err).Warnln("channel close failed")
		}
	}
}

func (b *BasicTerminal) HandleChannels(channels <-chan ssh.NewChannel) {
	for newChannel := range channels {
		channelType := newChannel.ChannelType()
		if channelType != "session" {
			err := newChannel.Reject(ssh.UnknownChannelType, "not supported")
			if err != nil {
				b.logger.WithError(err).Warnln("reject channel failed")
			}
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			b.logger.WithError(err).Warnln("accept channel failed")
			continue
		}

		go b.handleTerminalRequests(requests)

		b.messageMutex.Lock()

		_, _ = io.Copy(channel, b.messageBuffer)
		b.messageBuffer.Reset()
		b.messageWriter = channel

		b.messageMutex.Unlock()

		go b.handleKeyboard(channel)
		break
	}

	b.rejectChannels(channels)
}
