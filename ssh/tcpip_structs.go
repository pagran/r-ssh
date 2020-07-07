package ssh

// Source: https://tools.ietf.org/html/rfc4254#section-7.1
type portForwardRequest struct {
	Address string
	Port    uint32
}

type portForwardResponse struct {
	Port uint32
}

type remoteForwardData struct {
	DestAddress   string
	DestPort      uint32
	OriginAddress string
	OriginPort    uint32
}

const forwardedChannelType = "forwarded-tcpip"
