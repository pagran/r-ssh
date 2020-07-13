package auth

type Provider interface {
	Auth(string) bool
}

type defaultProvider struct{}

func (*defaultProvider) Auth(string) bool {
	return true
}

var DefaultAuthProvider = &defaultProvider{}

type WhitelistProvider struct {
	whitelist map[string]struct{}
}

func (w *WhitelistProvider) Auth(fingerprint string) bool {
	_, ok := w.whitelist[fingerprint]
	return ok
}

func NewWhitelistAuthProvider(publicKeyWhitelist []string) *WhitelistProvider {
	whitelist := make(map[string]struct{})
	for _, s := range publicKeyWhitelist {
		whitelist[s] = struct{}{}
	}
	return &WhitelistProvider{whitelist: whitelist}
}
