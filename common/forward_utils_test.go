package common

import (
	"strconv"
	"testing"
)

func TestMakeSubdomain(t *testing.T) {
	type args struct {
		fingerprint string
		host        string
		port        uint32
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Default Host+Port",
			args: args{fingerprint: "f", host: DefaultForwardAddr, port: DefaultForwardPort},
			want: "f",
		},
		{
			name: "Default Host",
			args: args{fingerprint: "f", host: DefaultForwardAddr, port: DefaultForwardPort + 1},
			want: strconv.Itoa(DefaultForwardPort+1) + "-f",
		},
		{
			name: "Default Port",
			args: args{fingerprint: "f", host: DefaultForwardAddr + "A", port: DefaultForwardPort},
			want: DefaultForwardAddr + "A" + "-f",
		},
		{
			name: "Normal",
			args: args{fingerprint: "f", host: "test", port: 111},
			want: "test-111-f",
		},
		{
			name: "Illegal Chars",
			args: args{fingerprint: "f", host: "test%^&*()=", port: 111},
			want: "test_______-111-f",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MakeSubdomain(tt.args.fingerprint, tt.args.host, tt.args.port); got != tt.want {
				t.Errorf("MakeSubdomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
