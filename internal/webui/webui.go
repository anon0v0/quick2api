package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed assets/*
var assetFS embed.FS

// Handler returns an http.Handler serving the embedded management console under /admin/.
// Static HTML/CSS/JS contain no secrets; all live data is fetched via auth-protected /admin/* APIs.
func Handler() http.Handler {
	sub, err := fs.Sub(assetFS, "assets")
	if err != nil {
		panic(err)
	}
	fileSrv := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:")
		w.Header().Set("Cache-Control", "no-cache")

		// Strip "/admin" prefix so "/admin/" serves index.html and "/admin/assets/..." maps cleanly.
		p := strings.TrimPrefix(r.URL.Path, "/admin")
		if p == "" || p == "/" {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileSrv.ServeHTTP(w, r2)
			return
		}
		if strings.HasPrefix(p, "/assets/") {
			r2 := r.Clone(r.Context())
			r2.URL.Path = strings.TrimPrefix(p, "/assets")
			fileSrv.ServeHTTP(w, r2)
			return
		}
		http.NotFound(w, r)
	})
}
