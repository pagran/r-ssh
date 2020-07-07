package main

type Configuration struct {
	Host        string `required:"true"`
	WebEndpoint string `default:"127.0.0.1:80" split_words:"true"`
	SSHEndpoint string `default:"127.0.0.1:22" split_words:"true"`
	HostKey     string `required:"true" split_words:"true"`

	PublicKeyWhitelist []string `split_words:"true"`

	LogLevel string `default:"info" split_words:"true"`

	Debug bool
}
