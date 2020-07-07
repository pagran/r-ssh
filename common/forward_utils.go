package common

import (
	"regexp"
	"strconv"
)

var allowedCharsRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

func MakeSubdomain(fingerprint, host string, port uint32) string {
	prefix := ""

	if host != DefaultForwardAddr {
		prefix += allowedCharsRegexp.ReplaceAllString(host, "_") + "-"
	}

	if port != DefaultForwardPort {
		prefix += strconv.Itoa(int(port)) + "-"
	}

	return prefix + fingerprint
}
