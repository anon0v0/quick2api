package netproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// DirectKeyword explicitly opts an account out of the global proxy_url.
const DirectKeyword = "direct"

// ProxyError wraps a proxy transport error with sanitized text while preserving Unwrap
// so callers can still classify context.Canceled / context.DeadlineExceeded.
type ProxyError struct {
	Msg string
	Err error
}

func (e *ProxyError) Error() string { return e.Msg }
func (e *ProxyError) Unwrap() error { return e.Err }

// Validate checks whether raw is a valid proxy_url setting ("" | "direct" | http/https/socks5/socks5h URL).
// Returned errors intentionally never interpolate raw input to prevent credential leaks in logs.
func Validate(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, DirectKeyword) {
		return nil
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return errors.New("invalid proxy_url: must not contain whitespace")
	}
	u, err := url.Parse(s)
	if err != nil {
		return errors.New("invalid proxy_url: malformed URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return errors.New("invalid proxy_url: unsupported scheme (allowed: http, https, socks5, socks5h, direct)")
	}
	if u.Hostname() == "" {
		return errors.New("invalid proxy_url: missing host")
	}
	portStr := u.Port()
	if portStr == "" {
		return errors.New("invalid proxy_url: explicit port is required")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("invalid proxy_url: port must be between 1 and 65535")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("invalid proxy_url: path is not allowed")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid proxy_url: query and fragment are not allowed")
	}
	if u.User != nil {
		user := u.User.Username()
		pass, hasPass := u.User.Password()
		if user == "" && hasPass {
			return errors.New("invalid proxy_url: empty username with password")
		}
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("invalid proxy_url: credentials exceed maximum length")
		}
	}
	return nil
}

// Resolve determines the effective outbound proxy URL for an account given a global fallback.
// Returns "" for direct egress.
func Resolve(accountProxy, globalProxy string) string {
	ap := strings.TrimSpace(accountProxy)
	if strings.EqualFold(ap, DirectKeyword) {
		return ""
	}
	if ap != "" {
		return ap
	}
	gp := strings.TrimSpace(globalProxy)
	if strings.EqualFold(gp, DirectKeyword) {
		return ""
	}
	return gp
}

// Redact strips credentials from a proxy URL for safe display in status endpoints and logs.
func Redact(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.EqualFold(s, DirectKeyword) {
		return DirectKeyword
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<invalid-proxy>"
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

// NewTransport clones base (preserving TLS and timeout settings) and binds it to proxyURL.
// When proxyURL is empty, Proxy is explicitly set to nil so direct egress never inherits ambient env proxies.
func NewTransport(base *http.Transport, proxyURL string) (*http.Transport, error) {
	if err := Validate(proxyURL); err != nil {
		return nil, err
	}
	var tr *http.Transport
	if base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{
			MaxIdleConns:        32,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
		}
	}
	// Always ensure HTTP/2 handler registration matches ALPN when cloning transports
	// or attaching a custom SOCKS5 DialContext.
	tr.ForceAttemptHTTP2 = true
	s := strings.TrimSpace(proxyURL)
	if s == "" || strings.EqualFold(s, DirectKeyword) {
		tr.Proxy = nil
		return tr, nil
	}
	u, _ := url.Parse(s)
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		tr.Proxy = nil
		tr.DialContext = newSOCKS5Dialer(u)
	default:
		return nil, errors.New("invalid proxy_url: unsupported scheme")
	}
	return tr, nil
}

// ConfigureWebSocketDialer configures d to route through proxyURL (HTTP/HTTPS CONNECT or SOCKS5/SOCKS5h).
func ConfigureWebSocketDialer(d *websocket.Dialer, proxyURL string) error {
	if err := Validate(proxyURL); err != nil {
		return err
	}
	s := strings.TrimSpace(proxyURL)
	if s == "" || strings.EqualFold(s, DirectKeyword) {
		d.Proxy = nil
		d.NetDialContext = nil
		return nil
	}
	u, _ := url.Parse(s)
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		d.Proxy = http.ProxyURL(u)
		d.NetDialContext = nil
	case "socks5", "socks5h":
		d.Proxy = nil
		d.NetDialContext = newSOCKS5Dialer(u)
	default:
		return errors.New("invalid proxy_url: unsupported scheme")
	}
	return nil
}

// SanitizeError removes raw proxy URL/userinfo details while preserving context cancellation unwrapping.
func SanitizeError(err error, proxyURL string) error {
	if err == nil || strings.TrimSpace(proxyURL) == "" || strings.EqualFold(strings.TrimSpace(proxyURL), DirectKeyword) {
		return err
	}
	redacted := Redact(proxyURL)
	if errors.Is(err, context.Canceled) {
		return &ProxyError{Msg: fmt.Sprintf("proxy %s request canceled", redacted), Err: context.Canceled}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &ProxyError{Msg: fmt.Sprintf("proxy %s request timed out", redacted), Err: context.DeadlineExceeded}
	}
	var pe *ProxyError
	if errors.As(err, &pe) {
		return pe
	}
	return &ProxyError{Msg: fmt.Sprintf("proxy %s dial/request failed", redacted), Err: err}
}

// newSOCKS5Dialer implements RFC 1928 / RFC 1929 SOCKS5 dialing with remote DNS (ATYP=0x03)
// so both socks5:// and socks5h:// work identically across net/http and gorilla/websocket
// without leaking local DNS or adding third-party dependencies.
func newSOCKS5Dialer(proxyURL *url.URL) func(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	redacted := Redact(proxyURL.String())
	var username, password string
	hasAuth := false
	if proxyURL.User != nil {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
		hasAuth = username != ""
	}
	baseDialer := &net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return func(ctx context.Context, network, targetAddr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s unsupported network %s", redacted, network)}
		}
		host, portStr, err := net.SplitHostPort(targetAddr)
		if err != nil {
			return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s invalid target address", redacted), Err: err}
		}
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum < 1 || portNum > 65535 {
			return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s invalid target port", redacted)}
		}

		conn, err := baseDialer.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, SanitizeError(err, proxyURL.String())
		}

		// Bind handshake lifetime to context deadline (or 20s default).
		deadline := time.Now().Add(20 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)

		stopCancel := context.AfterFunc(ctx, func() {
			_ = conn.Close()
		})
		handshakeOK := false
		defer func() {
			stopCancel()
			if !handshakeOK {
				_ = conn.Close()
			}
		}()

		// 1. Greeting: VER=5, NMETHODS, METHODS
		var greeting []byte
		if hasAuth {
			greeting = []byte{0x05, 0x02, 0x00, 0x02}
		} else {
			greeting = []byte{0x05, 0x01, 0x00}
		}
		if _, err := conn.Write(greeting); err != nil {
			return nil, SanitizeError(err, proxyURL.String())
		}
		var methodResp [2]byte
		if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
			return nil, SanitizeError(err, proxyURL.String())
		}
		if methodResp[0] != 0x05 {
			return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s invalid SOCKS5 version", redacted)}
		}
		switch methodResp[1] {
		case 0x00:
			// No auth required.
		case 0x02:
			if !hasAuth {
				return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s requires authentication", redacted)}
			}
			authBuf := make([]byte, 0, 3+len(username)+len(password))
			authBuf = append(authBuf, 0x01, byte(len(username)))
			authBuf = append(authBuf, username...)
			authBuf = append(authBuf, byte(len(password)))
			authBuf = append(authBuf, password...)
			if _, err := conn.Write(authBuf); err != nil {
				return nil, SanitizeError(err, proxyURL.String())
			}
			var authResp [2]byte
			if _, err := io.ReadFull(conn, authResp[:]); err != nil {
				return nil, SanitizeError(err, proxyURL.String())
			}
			if authResp[1] != 0x00 {
				return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s authentication failed", redacted)}
			}
		default:
			return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s rejected auth methods", redacted)}
		}

		// 2. CONNECT request using IP literal or ATYP=0x03 (remote DNS for hostnames).
		req := make([]byte, 0, 7+len(host))
		req = append(req, 0x05, 0x01, 0x00)
		if ip := net.ParseIP(host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				req = append(req, 0x01)
				req = append(req, ip4...)
			} else {
				req = append(req, 0x04)
				req = append(req, ip.To16()...)
			}
		} else {
			if len(host) > 255 {
				return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s target hostname too long", redacted)}
			}
			req = append(req, 0x03, byte(len(host)))
			req = append(req, host...)
		}
		req = binary.BigEndian.AppendUint16(req, uint16(portNum))
		if _, err := conn.Write(req); err != nil {
			return nil, SanitizeError(err, proxyURL.String())
		}

		// 3. Read CONNECT reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, SanitizeError(err, proxyURL.String())
		}
		if hdr[0] != 0x05 {
			return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s invalid SOCKS5 reply version", redacted)}
		}
		if hdr[1] != 0x00 {
			return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s connect failed (rep=0x%02x)", redacted, hdr[1])}
		}
		var discardLen int
		switch hdr[3] {
		case 0x01:
			discardLen = 4 + 2
		case 0x04:
			discardLen = 16 + 2
		case 0x03:
			var l [1]byte
			if _, err := io.ReadFull(conn, l[:]); err != nil {
				return nil, SanitizeError(err, proxyURL.String())
			}
			discardLen = int(l[0]) + 2
		default:
			return nil, &ProxyError{Msg: fmt.Sprintf("proxy %s unsupported address type", redacted)}
		}
		if _, err := io.CopyN(io.Discard, conn, int64(discardLen)); err != nil {
			return nil, SanitizeError(err, proxyURL.String())
		}

		// Clear handshake deadline; caller manages I/O deadlines.
		_ = conn.SetDeadline(time.Time{})
		handshakeOK = true
		return conn, nil
	}
}
