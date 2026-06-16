package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestServer_ServesHTTP1AndH2C verifies the http.Server Protocols config (the one
// main() applies) serves BOTH HTTP/1.1 and unencrypted HTTP/2 (h2c) on a single
// cleartext listener.
func TestServer_ServesHTTP1AndH2C(t *testing.T) {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		Protocols:         protocols,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	base := "http://" + ln.Addr().String() + "/"

	// HTTP/1.1 client.
	resp1, err := http.Get(base) //nolint:gosec // G107: test-only, address is the local test listener
	if err != nil {
		t.Fatalf("http/1.1 get: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.ProtoMajor != 1 {
		t.Errorf("http/1.1 client: got %s, want HTTP/1.x", resp1.Proto)
	}

	// h2c (prior-knowledge) client: x/net/http2 transport over a plain TCP dial.
	h2 := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}}
	resp2, err := h2.Get(base)
	if err != nil {
		t.Fatalf("h2c get: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.ProtoMajor != 2 {
		t.Errorf("h2c client: got %s, want HTTP/2 (h2c)", resp2.Proto)
	}
}
