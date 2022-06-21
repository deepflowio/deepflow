package logger

import (
	"testing"
)

func TestGetRemoteAddress(t *testing.T) {
	for _, tc := range []struct {
		input  string
		output string
	}{
		{"172.16.1.128", "172.16.1.128:20033"},
		{"172.16.1.128:20033", "172.16.1.128:20033"},
		{"2009::123", "[2009::123]:20033"},
		{"[2009::123]:20033", "[2009::123]:20033"},
		{"localhost", "localhost:20033"},
		{"localhost:20033", "localhost:20033"},
		{"gitlab.yunshan.net", "gitlab.yunshan.net:20033"},
		{"gitlab.yunshan.net:20033", "gitlab.yunshan.net:20033"},
	} {
		if result := getRemoteAddress(tc.input, 20033); result != tc.output {
			t.Errorf("应为%s, 实为%s", tc.output, result)
		}
	}
}
