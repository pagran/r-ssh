package common

import (
	"regexp"
	"strconv"
	"strings"
)

const flagDelimiter = "+"

const (
	httpsFlag         = 's'
	rewriteOriginFlag = 'o'
)

var allowedCharsRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

type ForwardFlags struct {
	Https         bool
	RewriteOrigin bool
}

type ForwardInfo struct {
	*ForwardFlags
	Address string
	Host    string
	Port    uint32

	Subdomain string
}

var defaultFlags = &ForwardFlags{
	Https:         false,
	RewriteOrigin: false,
}

func makeSubdomain(fingerprint, host string, port uint32) string {
	prefix := ""

	if host != DefaultForwardAddr {
		prefix += allowedCharsRegexp.ReplaceAllString(host, "_") + "-"
	}

	if port != DefaultForwardPort {
		prefix += strconv.Itoa(int(port)) + "-"
	}

	return prefix + fingerprint
}

func parseFlags(host string) (*ForwardFlags, string) {
	parts := strings.Split(host, flagDelimiter)
	if len(parts) <= 1 {
		return defaultFlags, host
	}

	flags := parts[1]
	return &ForwardFlags{
		Https:         strings.ContainsRune(flags, httpsFlag),
		RewriteOrigin: strings.ContainsRune(flags, rewriteOriginFlag),
	}, parts[0]
}

func BuildForwardInfo(fingerprint, address string, port uint32) *ForwardInfo {
	flags, host := parseFlags(address)
	return &ForwardInfo{
		ForwardFlags: flags,
		Port:         port,
		Address:      address,
		Host:         host,
		Subdomain:    makeSubdomain(fingerprint, host, port),
	}
}
