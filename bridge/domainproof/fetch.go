// Package domainproof fetches a provider's well-known domain document (D14)
// for the adapter runtime. Production uses HTTPS with the system's WebPKI
// roots and certificate verification; plain HTTP is accepted only when the
// bridge runs with the local test profile. Base checks the content.
package domainproof

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// MaxBytes bounds a domain document (Base accepts at most 16 KiB).
const MaxBytes = 16 << 10

const wellKnownPath = "/.well-known/ptpan-provider.json"

type Fetcher struct {
	client    *http.Client
	allowHTTP bool
}

// New returns a fetcher. allowHTTP enables the isolated test profile only.
func New(allowHTTP bool) *Fetcher {
	return &Fetcher{
		allowHTTP: allowHTTP,
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Fetch returns the document bytes and the UTC fetch time.
func (f *Fetcher) Fetch(ctx context.Context, raw string) ([]byte, time.Time, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Path != wellKnownPath || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, time.Time{}, errors.New("not a well-known domain-proof URL")
	}
	if parsed.Scheme != "https" && !(f.allowHTTP && parsed.Scheme == "http") {
		return nil, time.Time{}, errors.New("domain proof requires HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Accept", "application/json")
	response, err := f.client.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("domain proof returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(body) == 0 || len(body) > MaxBytes {
		return nil, time.Time{}, errors.New("domain proof size")
	}
	return body, time.Now().UTC(), nil
}
