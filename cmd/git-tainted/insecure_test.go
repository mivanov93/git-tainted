package main

import "testing"

func TestCheckServerURL(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		insecure bool
		wantErr  bool
	}{
		{"https allowed", "https://gt.example.com", false, false},
		{"https with port allowed", "https://gt.example.com:8443", false, false},
		{"http loopback ipv4 allowed", "http://127.0.0.1:8080", false, false},
		{"http loopback ipv6 allowed", "http://[::1]:8080", false, false},
		{"http localhost allowed", "http://localhost:8080", false, false},
		{"http remote host refused", "http://gt.example.com:8080", false, true},
		{"http remote ip refused", "http://203.0.113.5:8080", false, true},
		{"http remote allowed with --insecure", "http://gt.example.com:8080", true, false},
		{"http loopback fine without insecure", "http://127.0.0.1:9000", false, false},
		{"ftp refused", "ftp://gt.example.com", false, true},
		{"missing scheme refused", "gt.example.com:8080", false, true},
		{"garbage refused", "://nope", false, true},
		{"empty refused", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkServerURL(tc.url, tc.insecure)
			switch {
			case tc.wantErr && err == nil:
				t.Errorf("checkServerURL(%q, insecure=%v) = nil, want error", tc.url, tc.insecure)
			case !tc.wantErr && err != nil:
				t.Errorf("checkServerURL(%q, insecure=%v) = %v, want nil", tc.url, tc.insecure, err)
			}
		})
	}
}
