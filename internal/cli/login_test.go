package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestPKCEAuthorizeRegisterAndTokenExchange(t *testing.T) {
	verifier, challenge := GeneratePKCE()
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
		t.Fatalf("PKCE challenge mismatch: got %q want %q", challenge, want)
	}

	authURL := BuildAuthorizeURL("https://oidc.us-east-1.amazonaws.com", "cid-1", "http://127.0.0.1:18080/oauth/callback", []string{"sso:account:access"}, "st-99", challenge)
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != "cid-1" || q.Get("code_challenge_method") != "S256" || q.Get("state") != "st-99" {
		t.Fatalf("unexpected authorize query: %v", q)
	}

	oidcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/client/register":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["issuerUrl"] != DefaultSocialIssuerURL {
				http.Error(w, "bad issuer", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientId":              "cid-mock",
				"clientSecret":          "csec-mock",
				"clientSecretExpiresAt": 1999999999,
			})
		case "/token":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["grantType"] != "authorization_code" || req["codeVerifier"] != verifier || req["code"] != "code-xyz" {
				http.Error(w, "bad token exchange", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken":  "aoa_mock",
				"refreshToken": "aor_mock",
				"expiresIn":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer oidcSrv.Close()

	reg, err := RegisterOIDCClient(context.Background(), oidcSrv.Client(), oidcSrv.URL, DefaultSocialIssuerURL, "http://127.0.0.1:18080/oauth/callback", []string{DefaultOIDCScope}, "")
	if err != nil || reg.ClientID != "cid-mock" || reg.ClientSecret != "csec-mock" {
		t.Fatalf("RegisterOIDCClient failed: %+v err=%v", reg, err)
	}
	tok, err := ExchangeAuthCode(context.Background(), oidcSrv.Client(), oidcSrv.URL, reg.ClientID, reg.ClientSecret, "http://127.0.0.1:18080/oauth/callback", "code-xyz", verifier, "")
	if err != nil || tok.AccessToken != "aoa_mock" || tok.RefreshToken != "aor_mock" {
		t.Fatalf("ExchangeAuthCode failed: %+v err=%v", tok, err)
	}

	// ParseCallbackInput cases.
	code, err := ParseCallbackInput("http://127.0.0.1:18080/oauth/callback?code=abc123&state=st-99", "st-99")
	if err != nil || code != "abc123" {
		t.Fatalf("ParseCallbackInput URL failed: code=%q err=%v", code, err)
	}
	if _, err := ParseCallbackInput("http://127.0.0.1:18080/oauth/callback?code=abc123&state=wrong", "st-99"); err == nil {
		t.Fatal("expected state mismatch error")
	}
	bare, err := ParseCallbackInput("raw-code-token", "st-99")
	if err != nil || bare != "raw-code-token" {
		t.Fatalf("ParseCallbackInput bare code failed: %q err=%v", bare, err)
	}
}

func encodeUTF16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	return buf
}

func TestReassembleDesktopCredentialsChunkedAndSingle(t *testing.T) {
	payload := `{"tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","issuer_url":"https://identitycenter.amazonaws.com/ssoins-72233407e73f5d00","client_id":"cid-1","client_secret":"csec-1","access_token":"aoa_1","access_token_expiry":1999999999,"refresh_token":"aor_1","email":"hidden@example.com","external_id":"ext-1"}`
	sum := sha256.Sum256([]byte(payload))
	manifest, _ := json.Marshal(map[string]any{
		"__chunks__": 2,
		"__sha__":    hex.EncodeToString(sum[:]),
	})
	mid := len(payload) / 2

	raw := map[string][]byte{
		"quickwork-social-social-abc123":         encodeUTF16LE(string(manifest)),
		"quickwork-social-social-abc123_chunk_0": encodeUTF16LE(payload[:mid]),
		"quickwork-social-social-abc123_chunk_1": encodeUTF16LE(payload[mid:]),
		// Corrupt SHA entry should be skipped.
		"quickwork-social-social-badsha":         encodeUTF16LE(`{"__chunks__":1,"__sha__":"0000"}`),
		"quickwork-social-social-badsha_chunk_0": encodeUTF16LE(payload),
		// Unchunked UTF-8 entry should also be parsed.
		"quickwork-social-single-1": []byte(`{"tenant_url":"https://cell2.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"aoa_2","access_token_expiry":1999999999}`),
	}

	accounts := reassembleDesktopCredentials(raw, "socks5h://127.0.0.1:1080")
	if len(accounts) != 2 {
		t.Fatalf("expected 2 valid accounts (chunked + single), got %d: %+v", len(accounts), accounts)
	}
	foundChunked := false
	for _, a := range accounts {
		if a.ProxyURL != "socks5h://127.0.0.1:1080" {
			t.Fatalf("expected proxy assigned, got %q", a.ProxyURL)
		}
		if a.ID == "social-abc123" && a.AccessToken == "aoa_1" && a.RefreshToken == "aor_1" && a.ExternalID == "ext-1" {
			foundChunked = true
		}
		// Ensure email PII is not serialized on Account.
		b, _ := json.Marshal(a)
		if strings.Contains(string(b), "hidden@example.com") {
			t.Fatalf("PII email must not be persisted in Account JSON: %s", string(b))
		}
	}
	if !foundChunked {
		t.Fatalf("chunked UTF-16LE desktop credential was not reassembled cleanly: %+v", accounts)
	}
}
