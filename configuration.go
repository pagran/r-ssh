package main

type Configuration struct {
	Host string `required:"true"`

	WebEndpoint    string `default:"0.0.0.0:80" split_words:"true"`
	SslWebEndpoint string `default:"0.0.0.0:443" split_words:"true"`

	CertFile string `split_words:"true"`
	KeyFile  string `split_words:"true"`

	SSHEndpoint string `default:"0.0.0.0:22" split_words:"true"`
	HostKey     string `required:"true" split_words:"true"`

	PublicKeyWhitelist []string `split_words:"true"`

	LogLevel string `default:"info" split_words:"true"`

	Debug       bool
	WebHideInfo bool
}
