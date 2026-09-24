// Package peertransport supplies authenticated bytes to PTPAN Base.
// SPIRE/go-spiffe own SVIDs, bundles, TLS verification, and exact peer service
// authorization. This package neither parses Base events nor approves peers.
package peertransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// PEER_HELLO can contain a complete 64 KiB provider manifest plus its envelope.
const MaxBodyBytes = 72 << 10

type AuthenticatedRequest struct {
	ServiceID spiffeid.ID
	Body      []byte
}

// Handle must return only after Base has durably applied or rejected the
// message. Its response is a Base receipt, not owner consent or Ready state.
type Handle func(context.Context, AuthenticatedRequest) ([]byte, error)

type Transport struct {
	source  *workloadapi.X509Source
	allowed []spiffeid.ID
}

func Open(ctx context.Context, expectedPeerServiceIDs ...string) (*Transport, error) {
	if len(expectedPeerServiceIDs) == 0 {
		return nil, errors.New("at least one expected peer service ID is required")
	}
	allowed := make([]spiffeid.ID, 0, len(expectedPeerServiceIDs))
	seen := make(map[string]struct{}, len(expectedPeerServiceIDs))
	for _, raw := range expectedPeerServiceIDs {
		id, err := spiffeid.FromString(raw)
		if err != nil {
			return nil, fmt.Errorf("expected peer service ID: %w", err)
		}
		if _, ok := seen[id.String()]; ok {
			return nil, fmt.Errorf("duplicate expected peer service ID %s", id.String())
		}
		seen[id.String()] = struct{}{}
		allowed = append(allowed, id)
	}
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return nil, fmt.Errorf("SPIRE Workload API: %w", err)
	}
	return &Transport{source: source, allowed: allowed}, nil
}

func (t *Transport) allows(id spiffeid.ID) bool {
	for _, allowed := range t.allowed {
		if allowed == id {
			return true
		}
	}
	return false
}

func (t *Transport) serverAuthorizer() tlsconfig.Authorizer {
	if len(t.allowed) == 1 {
		return tlsconfig.AuthorizeID(t.allowed[0])
	}
	return tlsconfig.AuthorizeOneOf(t.allowed...)
}

func (t *Transport) Close() error { return t.source.Close() }

func (t *Transport) ServerTLS() *tls.Config {
	return tlsconfig.MTLSServerConfig(t.source, t.source, t.serverAuthorizer())
}

func (t *Transport) ClientTLS() *tls.Config {
	return tlsconfig.MTLSClientConfig(t.source, t.source, tlsconfig.AuthorizeID(t.allowed[0]))
}

func (t *Transport) clientTLSFor(id spiffeid.ID) (*tls.Config, error) {
	if !t.allows(id) {
		return nil, errors.New("service is not an authorized peer")
	}
	return tlsconfig.MTLSClientConfig(t.source, t.source, tlsconfig.AuthorizeID(id)), nil
}

func (t *Transport) Handler(handle Handle) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "authenticated service required", http.StatusUnauthorized)
			return
		}
		id, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
		if err != nil || !t.allows(id) {
			http.Error(w, "wrong service", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
		if err != nil || len(body) == 0 || len(body) > MaxBodyBytes {
			http.Error(w, "invalid body size", http.StatusRequestEntityTooLarge)
			return
		}
		receipt, err := handle(r.Context(), AuthenticatedRequest{ServiceID: id, Body: body})
		if err != nil {
			http.Error(w, "Base rejected message", http.StatusUnprocessableEntity)
			return
		}
		if len(receipt) == 0 || len(receipt) > MaxBodyBytes {
			http.Error(w, "invalid Base receipt", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(receipt)
	})
}

func (t *Transport) Serve(listener net.Listener, handle Handle) error {
	server := &http.Server{Handler: t.Handler(handle), ReadHeaderTimeout: 5 * time.Second}
	return server.Serve(tls.NewListener(listener, t.ServerTLS()))
}

func (t *Transport) Send(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "/control" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("peer control endpoint must be an exact HTTPS /control URL")
	}
	if len(body) == 0 || len(body) > MaxBodyBytes {
		return nil, errors.New("invalid control body size")
	}
	if len(t.allowed) != 1 {
		return nil, errors.New("service ID is required when more than one peer is authorized")
	}
	return t.SendTo(ctx, endpoint, t.allowed[0].String(), body)
}

func (t *Transport) SendTo(ctx context.Context, endpoint string, serviceID string, body []byte) ([]byte, error) {
	id, err := spiffeid.FromString(serviceID)
	if err != nil {
		return nil, fmt.Errorf("expected peer service ID: %w", err)
	}
	clientTLS, err := t.clientTLSFor(id)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "/control" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("peer control endpoint must be an exact HTTPS /control URL")
	}
	if len(body) == 0 || len(body) > MaxBodyBytes {
		return nil, errors.New("invalid control body size")
	}
	transport := &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	receipt, err := io.ReadAll(io.LimitReader(response.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer control returned HTTP %d", response.StatusCode)
	}
	if len(receipt) == 0 || len(receipt) > MaxBodyBytes || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return nil, errors.New("invalid peer control receipt")
	}
	return receipt, nil
}
