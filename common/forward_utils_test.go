package common

import (
	"reflect"
	"strconv"
	"testing"
)

func TestBuildForwardInfo(t *testing.T) {
	type args struct {
		fingerprint string
		host        string
		port        uint32
	}
	tests := []struct {
		name string
		args args
		want *ForwardInfo
	}{
		{
			name: "Default Host+Port",
			args: args{fingerprint: "f", host: DefaultForwardAddr, port: DefaultForwardPort},
			want: &ForwardInfo{
				ForwardFlags: defaultFlags,
				Address:      DefaultForwardAddr,
				Host:         DefaultForwardAddr,
				Port:         DefaultForwardPort,
				Subdomain:    "f",
			},
		},
		{
			name: "Default Host+Port+Flags",
			args: args{fingerprint: "f", host: DefaultForwardAddr + flagDelimiter + string(httpsFlag) + string(rewriteOriginFlag), port: DefaultForwardPort},
			want: &ForwardInfo{
				ForwardFlags: &ForwardFlags{
					Https:         true,
					RewriteOrigin: true,
				},
				Address:   DefaultForwardAddr + flagDelimiter + string(httpsFlag) + string(rewriteOriginFlag),
				Host:      DefaultForwardAddr,
				Port:      DefaultForwardPort,
				Subdomain: "f",
			},
		},
		{
			name: "Default Host",
			args: args{fingerprint: "f", host: DefaultForwardAddr, port: DefaultForwardPort + 1},
			want: &ForwardInfo{
				ForwardFlags: defaultFlags,
				Address:      DefaultForwardAddr,
				Host:         DefaultForwardAddr,
				Port:         DefaultForwardPort + 1,
				Subdomain:    strconv.Itoa(DefaultForwardPort+1) + "-f",
			},
		},
		{
			name: "Default Port",
			args: args{fingerprint: "f", host: DefaultForwardAddr + "A", port: DefaultForwardPort},
			want: &ForwardInfo{
				ForwardFlags: defaultFlags,
				Address:      DefaultForwardAddr + "A",
				Host:         DefaultForwardAddr + "A",
				Port:         DefaultForwardPort,
				Subdomain:    DefaultForwardAddr + "A" + "-f",
			},
		},
		{
			name: "Normal",
			args: args{fingerprint: "f", host: "test", port: 111},
			want: &ForwardInfo{
				ForwardFlags: defaultFlags,
				Address:      "test",
				Host:         "test",
				Port:         111,
				Subdomain:    "test-111-f",
			},
		},
		{
			name: "Normal+flags",
			args: args{fingerprint: "f", host: "test" + flagDelimiter + string(httpsFlag) + string(rewriteOriginFlag), port: 111},
			want: &ForwardInfo{
				ForwardFlags: &ForwardFlags{
					Https:         true,
					RewriteOrigin: true,
				},
				Address:   "test" + flagDelimiter + string(httpsFlag) + string(rewriteOriginFlag),
				Host:      "test",
				Port:      111,
				Subdomain: "test-111-f",
			},
		},
		{
			name: "Illegal Chars",
			args: args{fingerprint: "f", host: "test%^&*()=", port: 111},
			want: &ForwardInfo{
				ForwardFlags: defaultFlags,
				Address:      "test%^&*()=",
				Host:         "test%^&*()=",
				Port:         111,
				Subdomain:    "test_______-111-f",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildForwardInfo(tt.args.fingerprint, tt.args.host, tt.args.port); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("makeSubdomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
