package netproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateAndRedact(t *testing.T) {
	valid := []string{
		"",
		"direct",
		"DIRECT",
		"http://127.0.0.1:8080",
		"https://proxy.example.com:8443",
		"socks5://user:secretpass@127.0.0.1:1080",
		"socks5h://user:secretpass@proxy.example.com:1080",
	}
	for _, v := range valid {
		if err := Validate(v); err != nil {
			t.Errorf("Validate(%q) unexpected error: %v", v, err)
		}
	}

	invalid := []string{
		"ftp://proxy.example.com:21",
		"http://proxy.example.com",
		"socks5://proxy.example.com:99999",
		"http://user:TOPSECRET@proxy.example.com:8080/path",
		"http://:TOPSECRET@proxy.example.com:8080",
		"http://bad host:8080",
	}
	for _, v := range invalid {
		err := Validate(v)
		if err == nil {
			t.Errorf("Validate(%q) expected error, got nil", v)
			continue
		}
		if strings.Contains(err.Error(), "TOPSECRET") {
			t.Errorf("Validate error leaked secret: %v", err)
		}
	}

	if got := Redact("socks5h://alice:s3cr3t@proxy.example.com:1080"); got != "socks5h://proxy.example.com:1080" {
		t.Fatalf("Redact mismatch: got %q", got)
	}
	if got := Redact("DIRECT"); got != "direct" {
		t.Fatalf("Redact(DIRECT) = %q", got)
	}
	if got := Resolve("direct", "http://127.0.0.1:8080"); got != "" {
		t.Fatalf("Resolve(direct, global) = %q, want empty", got)
	}
	if got := Resolve("", "http://127.0.0.1:8080"); got != "http://127.0.0.1:8080" {
		t.Fatalf("Resolve(empty, global) = %q", got)
	}
	if got := Resolve("socks5://127.0.0.1:1080", "http://127.0.0.1:8080"); got != "socks5://127.0.0.1:1080" {
		t.Fatalf("Resolve(acct, global) = %q", got)
	}
}

// startLocalSOCKS5 spins up a minimal RFC 1928/1929 SOCKS5 test server supporting
// optional username/password auth and remote-DNS (ATYP=0x03) remapping to targetAddr.
func startLocalSOCKS5(t *testing.T, wantUser, wantPass, targetAddr string) (addr string, sawDomain *atomic.Bool, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sawDomain = &atomic.Bool{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var head [2]byte
				if _, err := io.ReadFull(conn, head[:]); err != nil {
					return
				}
				methods := make([]byte, head[1])
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if wantUser != "" {
					_, _ = conn.Write([]byte{0x05, 0x02})
					var ah [2]byte
					if _, err := io.ReadFull(conn, ah[:]); err != nil {
						return
					}
					u := make([]byte, ah[1])
					_, _ = io.ReadFull(conn, u)
					var pl [1]byte
					_, _ = io.ReadFull(conn, pl[:])
					p := make([]byte, pl[0])
					_, _ = io.ReadFull(conn, p)
					if string(u) != wantUser || string(p) != wantPass {
						_, _ = conn.Write([]byte{0x01, 0x01})
						return
					}
					_, _ = conn.Write([]byte{0x01, 0x00})
				} else {
					_, _ = conn.Write([]byte{0x05, 0x00})
				}

				var req [4]byte
				if _, err := io.ReadFull(conn, req[:]); err != nil {
					return
				}
				switch req[3] {
				case 0x01:
					var b [6]byte
					_, _ = io.ReadFull(conn, b[:])
				case 0x03:
					sawDomain.Store(true)
					var l [1]byte
					_, _ = io.ReadFull(conn, l[:])
					b := make([]byte, int(l[0])+2)
					_, _ = io.ReadFull(conn, b)
				case 0x04:
					var b [18]byte
					_, _ = io.ReadFull(conn, b[:])
				}
				upstream, err := net.DialTimeout("tcp", targetAddr, 3*time.Second)
				if err != nil {
					_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()
				resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
				binary.BigEndian.PutUint16(resp[8:10], 1)
				_, _ = conn.Write(resp)
				go func() { _, _ = io.Copy(upstream, conn) }()
				_, _ = io.Copy(conn, upstream)
			}(c)
		}
	}()
	return ln.Addr().String(), sawDomain, func() { _ = ln.Close() }
}

func TestSOCKS5AuthRemoteDNSAndNoFallback(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proxied-ok")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	socksAddr, sawDomain, stop := startLocalSOCKS5(t, "u1", "SUPERSECRET", backendAddr)
	defer stop()

	// 1. Valid credentials + remote DNS hostname (unresolvable locally, proves ATYP=0x03 remote DNS!)
	tr, err := NewTransport(nil, "socks5h://u1:SUPERSECRET@"+socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("http://nonexistent.remote.invalid:80/test")
	if err != nil {
		t.Fatalf("expected SOCKS5 remote-DNS request to succeed, got: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "proxied-ok" || !sawDomain.Load() {
		t.Fatalf("unexpected body=%q sawDomain=%v", string(body), sawDomain.Load())
	}

	// 2. Wrong credentials -> must fail, never fall back to direct, and never leak secret.
	trBad, err := NewTransport(nil, "socks5://u1:WRONGSECRET@"+socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	badClient := &http.Client{Transport: trBad, Timeout: 5 * time.Second}
	_, err = badClient.Get(backend.URL)
	if err == nil {
		t.Fatalf("expected auth error with wrong SOCKS5 credentials, got nil")
	}
	if strings.Contains(err.Error(), "WRONGSECRET") {
		t.Fatalf("SOCKS5 error leaked credentials: %v", err)
	}

	// 3. Context cancellation unwraps cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL, nil)
	_, err = client.Do(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled unwrap, got: %v", err)
	}
}

func TestNewTransportClonedBaseHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(r.Proto))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	// Deliberately pass a base transport with ForceAttemptHTTP2=false to reproduce Go's Transport.Clone ALPN pitfall.
	baseTr := &http.Transport{
		MaxIdleConns:    8,
		TLSClientConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
	}
	// First clone with nil TLSClientConfig triggers onceSetNextProtoDefaults on base, then test cloned HTTPS over H2.
	tr, err := NewTransport(baseTr, "")
	if err != nil {
		t.Fatal(err)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("expected ForceAttemptHTTP2=true on NewTransport result")
	}
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("HTTP/2 GET via cloned transport failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "HTTP/2.0" {
		t.Fatalf("expected HTTP/2.0, got %q", string(body))
	}
}
