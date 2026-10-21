package domainproof

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchEnforcesLocationSchemeAndSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case wellKnownPath:
			_, _ = w.Write([]byte(`{"schema":"ptpan-provider-domain/1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	if _, _, err := New(false).Fetch(ctx, server.URL+wellKnownPath); err == nil {
		t.Fatal("plain HTTP accepted outside the test profile")
	}
	body, at, err := New(true).Fetch(ctx, server.URL+wellKnownPath)
	if err != nil || !strings.Contains(string(body), "ptpan-provider-domain/1") || at.IsZero() {
		t.Fatalf("body=%s err=%v", body, err)
	}
	if _, _, err := New(true).Fetch(ctx, server.URL+"/other.json"); err == nil {
		t.Fatal("non-well-known path accepted")
	}
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", MaxBytes+1)))
	}))
	defer big.Close()
	if _, _, err := New(true).Fetch(ctx, big.URL+wellKnownPath); err == nil {
		t.Fatal("oversized document accepted")
	}
}

func TestHTTPSUsesVerifiedCertificates(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	if _, _, err := New(false).Fetch(context.Background(), server.URL+wellKnownPath); err == nil {
		t.Fatal("self-signed certificate accepted")
	}
}
