package cli

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"quick2api/internal/auth"
)

var credChunkSuffixRe = regexp.MustCompile(`_chunk_\d+$`)

type chunkedCredMeta struct {
	Chunks int    `json:"__chunks__"`
	SHA256 string `json:"__sha__"`
}

func decodeCredentialBlobText(blob []byte) string {
	if len(blob) >= 2 && len(blob)%2 == 0 && blob[1] == 0 {
		u16 := make([]uint16, len(blob)/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(blob[i*2 : i*2+2])
		}
		return strings.TrimRight(string(utf16.Decode(u16)), "\x00")
	}
	return strings.TrimRight(string(blob), "\x00")
}

// reassembleDesktopCredentials decodes both single-blob and Amazon Quick Desktop's chunked
// Windows Credential Manager entries ({"__chunks__": N, "__sha__": "..."} + _chunk_0..N-1).
func reassembleDesktopCredentials(rawCreds map[string][]byte, proxyURL string) []auth.Account {
	decoded := make(map[string]string, len(rawCreds))
	targets := make([]string, 0, len(rawCreds))
	for target, blob := range rawCreds {
		decoded[target] = decodeCredentialBlobText(blob)
		if !credChunkSuffixRe.MatchString(target) {
			targets = append(targets, target)
		}
	}
	sort.Strings(targets)

	var out []auth.Account
	for _, target := range targets {
		txt := strings.TrimSpace(decoded[target])
		if !strings.HasPrefix(txt, "{") {
			continue
		}

		// Handle chunked manifest: {"__chunks__": N, "__sha__": "<sha256>"}
		var meta chunkedCredMeta
		if err := json.Unmarshal([]byte(txt), &meta); err == nil && meta.Chunks > 0 {
			var sb strings.Builder
			complete := true
			for i := 0; i < meta.Chunks; i++ {
				part, ok := decoded[fmt.Sprintf("%s_chunk_%d", target, i)]
				if !ok {
					complete = false
					break
				}
				sb.WriteString(part)
			}
			if !complete {
				continue
			}
			joined := sb.String()
			if meta.SHA256 != "" {
				sum := sha256.Sum256([]byte(joined))
				if !strings.EqualFold(hex.EncodeToString(sum[:]), meta.SHA256) {
					continue
				}
			}
			txt = strings.TrimSpace(joined)
		}

		if acct, ok := parseDesktopAccountJSON(target, txt, proxyURL); ok {
			out = append(out, acct)
		}
	}
	return out
}

func parseDesktopAccountJSON(target, txt, proxyURL string) (auth.Account, bool) {
	if !strings.HasPrefix(txt, "{") {
		return auth.Account{}, false
	}
	var acct auth.Account
	if err := json.Unmarshal([]byte(txt), &acct); err != nil {
		return auth.Account{}, false
	}
	if acct.TenantURL == "" || acct.AccessToken == "" {
		return auth.Account{}, false
	}
	if acct.ID == "" {
		id := strings.TrimPrefix(target, "quickwork-social-")
		id = strings.TrimPrefix(id, "quickwork-")
		acct.ID = strings.TrimSpace(id)
	}
	acct.ProxyURL = proxyURL
	return acct, true
}
