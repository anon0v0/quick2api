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
	// DefaultSocialIssuerURL is only a fallback. Each Amazon Quick account is backed by its own
	// AWS Identity Center instance, so the issuer recorded by Amazon Quick Desktop is preferred.
	DefaultSocialIssuerURL = "https://identitycenter.amazonaws.com/ssoins-72233407e73f5d00"
	// DefaultOIDCScope is the production OIDC scope required by Amazon Quick DataPlane APIs.
	DefaultOIDCScope = "quicksight:read_write"
	// DefaultOIDCClientName matches the official Amazon Quick desktop OIDC client registration.
	DefaultOIDCClientName = "AmazonQuick-Desktop"
	// DefaultSocialDiscoveryURL is Amazon Quick's official social login discovery entry point.
	DefaultSocialDiscoveryURL = "https://quick.aws.com/sn"
	// DefaultDesktopAppVersion is advertised in qwSurface for desktop discovery callbacks.
	DefaultDesktopAppVersion = "1.2.4660"
)

// DiscoveryParams holds tenant & Identity Center parameters extracted from an Amazon Quick
// social login discovery callback URL (or direct tenant_url input).
type DiscoveryParams struct {
	TenantURL     string `json:"tenant_url"`
	IssuerURL     string `json:"issuer_url,omitempty"`
	Region        string `json:"region,omitempty"`
	IDCInstanceID string `json:"idc_instance_id,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
}

// BuildDiscoveryURL constructs the official Amazon Quick browser-login discovery URL using
// the qwSurface wire format `desktop:<nonce>:<port>:<appVersion>`.
func BuildDiscoveryURL(baseURL, nonce string, port int, appVersion string) string {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		base = DefaultSocialDiscoveryURL
	}
	if port <= 0 {
		port = 18080
	}
	if strings.TrimSpace(appVersion) == "" {
		appVersion = DefaultDesktopAppVersion
	}
	if strings.TrimSpace(nonce) == "" {
		nonce = randomHex(12)
	}
	surface := fmt.Sprintf("desktop:%s:%d:%s", nonce, port, appVersion)
	q := url.Values{}
	q.Set("qwSurface", surface)
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + q.Encode()
}

// ParseDiscoveryCallback extracts tenant_url, issuer_url, region, and nonce from a pasted
// loopback discovery redirect URL (supporting snake_case & camelCase query/fragment params)
// or a direct https://<cell>... tenant_url.
func ParseDiscoveryCallback(rawInput string) (DiscoveryParams, error) {
	s := strings.TrimSpace(rawInput)
	if s == "" {
		return DiscoveryParams{}, errors.New("empty discovery callback input")
	}
	parseTarget := s
	if !strings.Contains(parseTarget, "://") && (strings.Contains(parseTarget, "=") || strings.HasPrefix(parseTarget, "?")) {
		parseTarget = "http://127.0.0.1/discovery?" + strings.TrimPrefix(parseTarget, "?")
	}
	u, err := url.Parse(parseTarget)
	if err != nil {
		return DiscoveryParams{}, fmt.Errorf("malformed discovery URL: %w", err)
	}
	merged := url.Values{}
	for k, vals := range u.Query() {
		merged[k] = vals
	}
	if frag := strings.TrimPrefix(strings.TrimSpace(u.Fragment), "?"); frag != "" && strings.Contains(frag, "=") {
		if fq, err := url.ParseQuery(frag); err == nil {
			for k, vals := range fq {
				if merged.Get(k) == "" {
					merged[k] = vals
				}
			}
		}
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(merged.Get(k)); v != "" {
				return v
			}
		}
		return ""
	}
	if errCode := first("error"); errCode != "" {
		desc := first("error_description", "errorDescription")
		if desc != "" {
			return DiscoveryParams{}, fmt.Errorf("discovery error: %s (%s)", errCode, desc)
		}
		return DiscoveryParams{}, fmt.Errorf("discovery error: %s", errCode)
	}

	out := DiscoveryParams{
		TenantURL:     strings.TrimRight(first("tenant_url", "tenantUrl", "tenant"), "/"),
		IssuerURL:     strings.TrimRight(first("issuer_url", "issuerUrl", "issuer"), "/"),
		Region:        first("idc_region", "idcRegion", "region"),
		IDCInstanceID: first("idc_instance_id", "idcInstanceId"),
		Nonce:         first("nonce", "state"),
	}
	if out.TenantURL == "" {
		if wsHost := first("ws_host", "wsHost"); wsHost != "" {
			out.TenantURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(wsHost, "https://"), "http://")
		}
	}
	if out.TenantURL == "" && u.Scheme == "https" && u.Host != "" &&
		!strings.EqualFold(u.Hostname(), "127.0.0.1") && !strings.EqualFold(u.Hostname(), "localhost") {
		// User pasted a direct https://<cell>.dp.appintegrations... tenant_url.
		out.TenantURL = "https://" + u.Host
	}
	if out.TenantURL != "" && !strings.Contains(out.TenantURL, "://") {
		out.TenantURL = "https://" + out.TenantURL
	}
	if parsedT, err := url.Parse(out.TenantURL); err != nil || parsedT.Scheme != "https" || parsedT.Host == "" {
		return DiscoveryParams{}, errors.New("callback URL does not contain a valid https:// tenant_url (make sure you copied the full 127.0.0.1 redirect URL after signing in on quick.aws.com)")
	}
	if out.IssuerURL == "" && out.IDCInstanceID != "" {
		out.IssuerURL = "https://identitycenter.amazonaws.com/" + out.IDCInstanceID
	}
	if out.Region == "" {
		out.Region = InferRegionFromTenantURL(out.TenantURL)
	}
	return out, nil
}

// InferRegionFromTenantURL extracts the AWS region embedded in a Quick DataPlane host
// such as `<cell>.dp.appintegrations.<region>.prod.plato.ai.aws.dev`.
func InferRegionFromTenantURL(tenantURL string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(tenantURL), "https://"), "http://")
	if idx := strings.IndexByte(host, '/'); idx >= 0 {
		host = host[:idx]
	}
	for _, p := range strings.Split(host, ".") {
		if len(p) >= 9 && strings.Count(p, "-") == 2 &&
			(strings.HasPrefix(p, "us-") || strings.HasPrefix(p, "eu-") || strings.HasPrefix(p, "ap-") ||
				strings.HasPrefix(p, "ca-") || strings.HasPrefix(p, "sa-") || strings.HasPrefix(p, "me-") ||
				strings.HasPrefix(p, "af-")) {
			return p
		}
	}
	return ""
}

func discoverIssuerFromAccountsFile(path, tenantURL string) (string, bool) {
	if strings.TrimSpace(path) == "" {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	accts, err := auth.ParseAccountsJSONBytes(raw)
	if err != nil {
		return "", false
	}
	tenantURL = strings.TrimRight(strings.TrimSpace(tenantURL), "/")
	found := ""
	for _, a := range accts {
		if a == nil || !strings.EqualFold(strings.TrimRight(strings.TrimSpace(a.TenantURL), "/"), tenantURL) {
			continue
		}
		iss := strings.TrimRight(strings.TrimSpace(a.IssuerURL), "/")
		if !isValidHTTPSURL(iss) {
			continue
		}
		if found != "" && !strings.EqualFold(found, iss) {
			return "", false
		}
		found = iss
	}
	return found, found != ""
}

// RunLogin executes the interactive or headless AWS sso-oidc PKCE login flow and upserts the account.
func RunLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "Optional config.json path to resolve accounts_file and global proxy_url")
	accountsPath := fs.String("accounts", "", "Target accounts.json path (overrides config.json)")
	accountID := fs.String("id", "", "Account ID label (auto-generated if empty)")
	region := fs.String("region", "", "AWS sso-oidc region (default: inferred from tenant_url or us-east-1)")
	issuerURL := fs.String("issuer-url", "", "AWS Identity Center issuer URL (default: discovered from callback, accounts.json, or Amazon Quick Desktop)")
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
	issuer := strings.TrimRight(strings.TrimSpace(*issuerURL), "/")
	tURL := strings.TrimRight(strings.TrimSpace(*tenantURL), "/")
	if tURL == "" {
		desktopDefault, hasDesktopDefault := singleDesktopProfile()
		discURL := BuildDiscoveryURL(DefaultSocialDiscoveryURL, randomHex(12), *port, DefaultDesktopAppVersion)
		fmt.Println("\nNo -tenant-url provided. Open this official Amazon Quick discovery URL in your browser to auto-discover your account's tenant_url & issuer_url:")
		fmt.Println(discURL)
		if hasDesktopDefault {
			fmt.Printf("\nDetected Amazon Quick Desktop profile: %s\n", desktopDefault.LoginMetadata.TenantURL)
			fmt.Print("Press Enter to reuse this desktop profile, or paste a 127.0.0.1 discovery callback URL / https:// tenant_url for another account: ")
		} else {
			fmt.Print("\nPaste the redirected 127.0.0.1 discovery URL (or a direct https:// tenant_url): ")
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read tenant_url: %w", err)
		}
		if strings.TrimSpace(line) == "" && hasDesktopDefault {
			tURL = desktopDefault.LoginMetadata.TenantURL
			if issuer == "" {
				issuer = desktopDefault.LoginMetadata.IssuerURL
			}
			fmt.Printf("Using Amazon Quick Desktop profile: tenant=%s issuer=%s\n", tURL, issuer)
		} else {
			disc, err := ParseDiscoveryCallback(line)
			if err != nil {
				return err
			}
			tURL = disc.TenantURL
			if disc.IssuerURL != "" && issuer == "" {
				issuer = disc.IssuerURL
			}
			if disc.Region != "" && reg == "" {
				reg = disc.Region
			}
		}
	}
	if parsed, err := url.Parse(tURL); err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return errors.New("invalid tenant_url: must be a valid https:// URL")
	}
	if issuer != "" && !isValidHTTPSURL(issuer) {
		return errors.New("invalid issuer_url: must be a valid https:// URL")
	}
	if reg == "" {
		reg = InferRegionFromTenantURL(tURL)
	}
	if reg == "" {
		reg = "us-east-1"
	}
	if issuer == "" {
		if discovered, ok := discoverIssuerFromAccountsFile(targetAccounts, tURL); ok {
			issuer = discovered
			fmt.Printf("Using issuer from existing accounts file: %s\n", issuer)
		} else if discovered, ok := desktopProfileForTenant(tURL); ok {
			issuer = discovered.LoginMetadata.IssuerURL
			fmt.Printf("Using issuer from Amazon Quick Desktop: %s\n", issuer)
		} else {
			issuer = DefaultSocialIssuerURL
			fmt.Printf("Warning: no matching issuer found in accounts file or Quick Desktop; falling back to %s (pass -issuer-url or use quick.aws.com discovery if login shows Builder ID / session expired)\n", issuer)
		}
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
		"clientName":   DefaultOIDCClientName,
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
