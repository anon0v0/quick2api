package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"quick2api/internal/auth"
	"quick2api/internal/config"
	"quick2api/internal/netproxy"
)

const (
	// DefaultSocialIssuerURL is AWS Identity Center's public Amazon Quick social issuer.
	DefaultSocialIssuerURL = "https://identitycenter.amazonaws.com/ssoins-72233407e73f5d00"
	DefaultOIDCScope       = "sso:account:access"
)

// RunLogin executes the interactive or headless AWS sso-oidc PKCE login flow and upserts the account.
func RunLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "Optional config.json path to resolve accounts_file and global proxy_url")
	accountsPath := fs.String("accounts", "", "Target accounts.json path (overrides config.json)")
	accountID := fs.String("id", "", "Account ID label (auto-generated if empty)")
	region := fs.String("region", "us-east-1", "AWS sso-oidc region")
	issuerURL := fs.String("issuer-url", DefaultSocialIssuerURL, "AWS Identity Center issuer URL")
	tenantURL := fs.String("tenant-url", "", "Amazon Quick cell tenant URL (https://<cell>.dp.appintegrations.<region>.prod.plato.ai.aws.dev)")
	scopesCSV := fs.String("scopes", DefaultOIDCScope, "Comma-separated OIDC scopes")
	port := fs.Int("port", 18080, "Local loopback callback port on 127.0.0.1")
	headless := fs.Bool("headless", false, "Headless/SSH mode: do not open browser; paste redirected callback URL into stdin")
	proxyURL := fs.String("proxy", "", "Optional per-account outbound proxy URL (saved as proxy_url on the account)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	targetAccounts := strings.TrimSpace(*accountsPath)
	globalProxy := ""
	if strings.TrimSpace(*cfgPath) != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		if targetAccounts == "" {
			targetAccounts = cfg.AccountsFile
		}
		globalProxy = cfg.ProxyURL
	}
	if targetAccounts == "" {
		targetAccounts = "accounts.json"
	}

	acctProxy := strings.TrimSpace(*proxyURL)
	if err := netproxy.Validate(acctProxy); err != nil {
		return err
	}
	effProxy := netproxy.Resolve(acctProxy, globalProxy)

	reg := strings.TrimSpace(*region)
	if reg == "" {
		reg = "us-east-1"
	}
	issuer := strings.TrimSpace(*issuerURL)
	if issuer == "" {
		return errors.New("issuer-url is required")
	}

	tURL := strings.TrimRight(strings.TrimSpace(*tenantURL), "/")
	if tURL == "" {
		fmt.Print("Enter Amazon Quick tenant_url (e.g. https://<cell>.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev): ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read tenant_url: %w", err)
		}
		tURL = strings.TrimRight(strings.TrimSpace(line), "/")
	}
	if parsed, err := url.Parse(tURL); err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("invalid tenant_url: must be a valid https:// URL")
	}

	scopes := splitCSV(*scopesCSV)
	if len(scopes) == 0 {
		scopes = []string{DefaultOIDCScope}
	}

	tr, err := netproxy.NewTransport(nil, effProxy)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", *port)
	oidcBase := fmt.Sprintf("https://oidc.%s.amazonaws.com", reg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	clientReg, err := RegisterOIDCClient(ctx, httpClient, oidcBase, issuer, redirectURI, scopes, effProxy)
	if err != nil {
		return err
	}

	verifier, challenge := GeneratePKCE()
	state := randomHex(16)
	authURL := BuildAuthorizeURL(oidcBase, clientReg.ClientID, redirectURI, scopes, state, challenge)

	var code string
	if *headless {
		fmt.Println("\nOpen the following URL in your browser and complete sign-in:")
		fmt.Println(authURL)
		fmt.Printf("\nAfter sign-in, your browser will redirect to %s?code=...&state=...\n", redirectURI)
		fmt.Print("Paste the full callback URL (or code) here: ")
		code, err = readCodeFromStdin(state)
		if err != nil {
			return err
		}
	} else {
		code, err = waitForLoopbackOrStdin(ctx, *port, authURL, state)
		if err != nil {
			return err
		}
	}

	tok, err := ExchangeAuthCode(ctx, httpClient, oidcBase, clientReg.ClientID, clientReg.ClientSecret, redirectURI, code, verifier, effProxy)
	if err != nil {
		return err
	}

	id := strings.TrimSpace(*accountID)
	if id == "" {
		id = "social-" + randomHex(6)
	}
	expiresIn := tok.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	now := time.Now().Unix()
	acct := auth.Account{
		ID:                    id,
		ProxyURL:              acctProxy,
		TenantURL:             tURL,
		IssuerURL:             issuer,
		Region:                reg,
		ClientID:              clientReg.ClientID,
		ClientSecret:          clientReg.ClientSecret,
		ClientSecretExpiresAt: float64(clientReg.ClientSecretExpiresAt),
		AccessToken:           tok.AccessToken,
		AccessTokenExpiry:     float64(now + expiresIn),
		RefreshToken:          tok.RefreshToken,
	}

	added, updated, err := auth.UpsertAccountsFile(targetAccounts, []auth.Account{acct})
	if err != nil {
		return fmt.Errorf("save account: %w", err)
	}
	fmt.Printf("Saved account to %s (added=%v updated=%v region=%s expires_in=%ds proxy=%s)\n",
		targetAccounts, added, updated, reg, expiresIn, netproxy.Redact(acctProxy))
	fmt.Println("Tip: reload a running quick2api instance without downtime via SIGHUP or POST /admin/reload.")
	return nil
}

// OIDCClientRegistration holds the AWS sso-oidc /client/register response.
type OIDCClientRegistration struct {
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
}

// OIDCTokenResult holds the AWS sso-oidc /token authorization_code exchange response.
type OIDCTokenResult struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int64  `json:"expiresIn"`
}

// RegisterOIDCClient registers a public loopback PKCE client with AWS sso-oidc.
func RegisterOIDCClient(ctx context.Context, hc *http.Client, oidcBase, issuerURL, redirectURI string, scopes []string, effProxy string) (OIDCClientRegistration, error) {
	payload := map[string]any{
		"clientName":   "Amazon Quick",
		"clientType":   "public",
		"issuerUrl":    issuerURL,
		"grantTypes":   []string{"authorization_code", "refresh_token"},
		"redirectUris": []string{redirectURI},
		"scopes":       scopes,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return OIDCClientRegistration{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(oidcBase, "/")+"/client/register", bytes.NewReader(b))
	if err != nil {
		return OIDCClientRegistration{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return OIDCClientRegistration{}, netproxy.SanitizeError(err, effProxy)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return OIDCClientRegistration{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return OIDCClientRegistration{}, fmt.Errorf("oidc client/register failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out OIDCClientRegistration
	if err := json.Unmarshal(raw, &out); err != nil || out.ClientID == "" || out.ClientSecret == "" {
		return OIDCClientRegistration{}, errors.New("oidc client/register returned incomplete credentials")
	}
	return out, nil
}

// BuildAuthorizeURL constructs the AWS sso-oidc /authorize URL with PKCE S256 parameters.
func BuildAuthorizeURL(oidcBase, clientID, redirectURI string, scopes []string, state, codeChallenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scopes", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return strings.TrimRight(oidcBase, "/") + "/authorize?" + q.Encode()
}

// ExchangeAuthCode trades an OAuth authorization code + PKCE verifier for access and refresh tokens.
func ExchangeAuthCode(ctx context.Context, hc *http.Client, oidcBase, clientID, clientSecret, redirectURI, code, codeVerifier, effProxy string) (OIDCTokenResult, error) {
	payload := map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"grantType":    "authorization_code",
		"code":         code,
		"codeVerifier": codeVerifier,
		"redirectUri":  redirectURI,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return OIDCTokenResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(oidcBase, "/")+"/token", bytes.NewReader(b))
	if err != nil {
		return OIDCTokenResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return OIDCTokenResult{}, netproxy.SanitizeError(err, effProxy)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return OIDCTokenResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return OIDCTokenResult{}, fmt.Errorf("oidc token exchange failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out OIDCTokenResult
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		return OIDCTokenResult{}, errors.New("oidc token exchange returned empty accessToken")
	}
	return out, nil
}

// GeneratePKCE produces a random RFC 7636 verifier and S256 challenge.
func GeneratePKCE() (verifier, challenge string) {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	verifier = base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// ParseCallbackInput extracts the OAuth authorization code from a pasted callback URL or bare code string.
func ParseCallbackInput(rawInput, expectedState string) (string, error) {
	s := strings.TrimSpace(rawInput)
	if s == "" {
		return "", errors.New("empty callback input")
	}
	if strings.Contains(s, "://") || strings.Contains(s, "code=") {
		parseTarget := s
		if !strings.Contains(parseTarget, "://") {
			parseTarget = "http://127.0.0.1/oauth/callback?" + strings.TrimPrefix(parseTarget, "?")
		}
		u, err := url.Parse(parseTarget)
		if err != nil {
			return "", fmt.Errorf("parse callback URL: %w", err)
		}
		q := u.Query()
		if errMsg := q.Get("error"); errMsg != "" {
			return "", fmt.Errorf("oauth error: %s (%s)", errMsg, q.Get("error_description"))
		}
		if gotState := q.Get("state"); gotState != "" && expectedState != "" && gotState != expectedState {
			return "", errors.New("oauth state mismatch")
		}
		code := strings.TrimSpace(q.Get("code"))
		if code == "" {
			return "", errors.New("callback URL missing code parameter")
		}
		return code, nil
	}
	return s, nil
}

func readCodeFromStdin(expectedState string) (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return ParseCallbackInput(line, expectedState)
}

func waitForLoopbackOrStdin(ctx context.Context, port int, authURL, expectedState string) (string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", fmt.Errorf("listen loopback 127.0.0.1:%d: %w (hint: pass -headless or choose another -port)", port, err)
	}
	defer ln.Close()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errCode := q.Get("error"); errCode != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Sign-in failed: %s", errCode)
			select {
			case errCh <- fmt.Errorf("oauth error: %s", errCode):
			default:
			}
			return
		}
		if q.Get("state") != expectedState {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "State mismatch.")
			return
		}
		code := strings.TrimSpace(q.Get("code"))
		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "Missing authorization code.")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><body><h3>Authorization complete. You may close this tab.</h3></body></html>")
		select {
		case codeCh <- code:
		default:
		}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(shutCtx)
		shutCancel()
	}()

	fmt.Printf("Callback server listening on http://127.0.0.1:%d/oauth/callback\n", port)
	fmt.Println("Open this URL in your browser to sign in:")
	fmt.Println(authURL)
	openBrowser(authURL)

	select {
	case code := <-codeCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", errors.New("login timed out waiting for browser callback")
	}
}

func openBrowser(targetURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	case "darwin":
		cmd = exec.Command("open", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	_ = cmd.Start()
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
