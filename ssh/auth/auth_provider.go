package auth

type AuthProvider interface {
	Auth(string) bool
}

type defaultAuthProvider struct{}

func (*defaultAuthProvider) Auth(string) bool {
	return true
}

var DefaultAuthProvider = &defaultAuthProvider{}

type WhitelistAuthProvider struct {
	whitelist map[string]struct{}
}

func (w *WhitelistAuthProvider) Auth(fingerprint string) bool {
	_, ok := w.whitelist[fingerprint]
	return ok
}

func NewWhitelistAuthProvider(publicKeyWhitelist []string) *WhitelistAuthProvider {
	whitelist := make(map[string]struct{})
	for _, s := range publicKeyWhitelist {
		whitelist[s] = struct{}{}
	}
	return &WhitelistAuthProvider{whitelist: whitelist}
}
