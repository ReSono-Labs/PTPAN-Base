// Package peertransport is the bridge's mutual TLS to peers: the /control
// endpoint for provider and relationship messages, and the TLS used by the
// agent edge and relay. SPIRE/go-spiffe own SVIDs, bundles and verification;
// every authorization is an exact SPIFFE ID from the live peer set. This
// package neither parses PTPAN messages nor decides trust.
package peertransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"federation-base/bridge/peerset"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// A PEER_HELLO can carry a complete 64 KiB provider manifest plus envelope.
const MaxBodyBytes = 72 << 10

type AuthenticatedRequest struct {
	ServiceID spiffeid.ID
	Body      []byte
}

// Handle returns only after the runtime durably applied or rejected the
// message. Its response is a receipt, not owner consent or Ready state.
type Handle func(context.Context, AuthenticatedRequest) ([]byte, error)

// Transport holds two SVID sources from the same SPIRE agent: the control
// service identity and the edge service identity, so each listener and each
// client presents exactly its own role.
type Transport struct {
	control *workloadapi.X509Source
	edge    *workloadapi.X509Source
	peers   *peerset.Set
}

func pick(id spiffeid.ID) func([]*x509svid.SVID) *x509svid.SVID {
	return func(svids []*x509svid.SVID) *x509svid.SVID {
		for _, svid := range svids {
			if svid.ID == id {
				return svid
			}
		}
		return nil
	}
}

// Open uses the SPIRE Workload API at SPIFFE_ENDPOINT_SOCKET. The workload
// must be issued both controlID and edgeID.
func Open(ctx context.Context, peers *peerset.Set, controlID, edgeID string) (*Transport, error) {
	control, err := spiffeid.FromString(controlID)
	if err != nil {
		return nil, fmt.Errorf("control service ID: %w", err)
	}
	edge, err := spiffeid.FromString(edgeID)
	if err != nil || edge == control {
		return nil, errors.New("edge service ID must be a different SPIFFE ID")
	}
	controlSource, err := workloadapi.NewX509Source(ctx, workloadapi.WithDefaultX509SVIDPicker(pick(control)))
	if err != nil {
		return nil, fmt.Errorf("SPIRE Workload API (control): %w", err)
	}
	if svid, err := controlSource.GetX509SVID(); err != nil || svid.ID != control {
		_ = controlSource.Close()
		return nil, fmt.Errorf("no SVID for %s", control)
	}
	edgeSource, err := workloadapi.NewX509Source(ctx, workloadapi.WithDefaultX509SVIDPicker(pick(edge)))
	if err != nil {
		_ = controlSource.Close()
		return nil, fmt.Errorf("SPIRE Workload API (edge): %w", err)
	}
	if svid, err := edgeSource.GetX509SVID(); err != nil || svid.ID != edge {
		_ = controlSource.Close()
		_ = edgeSource.Close()
		return nil, fmt.Errorf("no SVID for %s", edge)
	}
	return &Transport{control: controlSource, edge: edgeSource, peers: peers}, nil
}

func (t *Transport) Close() error { return errors.Join(t.control.Close(), t.edge.Close()) }

func authorizeIf(allowed func(spiffeid.ID) bool) tlsconfig.Authorizer {
	return func(id spiffeid.ID, _ [][]*x509.Certificate) error {
		if allowed(id) {
			return nil
		}
		return errors.New("service is not a trusted peer")
	}
}

// ControlServerTLS presents our control identity and accepts exactly the
// control services in the live set.
func (t *Transport) ControlServerTLS() *tls.Config {
	return tlsconfig.MTLSServerConfig(t.control, t.control, authorizeIf(t.peers.AllowsControl))
}

// EdgeServerTLS presents our edge identity and accepts exactly the edge
// services in the live set.
func (t *Transport) EdgeServerTLS() *tls.Config {
	return tlsconfig.MTLSServerConfig(t.edge, t.edge, authorizeIf(t.peers.AllowsEdge))
}

// ControlClientTLS and EdgeClientTLS authorize exactly one peer service.
func (t *Transport) ControlClientTLS(id spiffeid.ID) *tls.Config {
	return tlsconfig.MTLSClientConfig(t.control, t.control, tlsconfig.AuthorizeID(id))
}

func (t *Transport) EdgeClientTLS(id spiffeid.ID) *tls.Config {
	return tlsconfig.MTLSClientConfig(t.edge, t.edge, tlsconfig.AuthorizeID(id))
}

// PeerID is the SPIFFE ID of the verified peer certificate on a TLS state.
func PeerID(state *tls.ConnectionState) (spiffeid.ID, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return spiffeid.ID{}, errors.New("authenticated service required")
	}
	return x509svid.IDFromCert(state.PeerCertificates[0])
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
		id, err := PeerID(r.TLS)
		if err != nil || !t.peers.AllowsControl(id) {
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
			http.Error(w, "message not applied", http.StatusUnprocessableEntity)
			return
		}
		if len(receipt) == 0 || len(receipt) > MaxBodyBytes {
			http.Error(w, "invalid receipt", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(receipt)
	})
}

func (t *Transport) ServeControl(listener net.Listener, handle Handle) error {
	server := &http.Server{Handler: t.Handler(handle), ReadHeaderTimeout: 5 * time.Second}
	return server.Serve(tls.NewListener(listener, t.ControlServerTLS()))
}

// SendControl posts exact bytes to the peer whose control service is
// serviceID and returns its receipt.
func (t *Transport) SendControl(ctx context.Context, serviceID string, body []byte) ([]byte, error) {
	id, err := spiffeid.FromString(serviceID)
	if err != nil {
		return nil, fmt.Errorf("peer service ID: %w", err)
	}
	route, ok := t.peers.ByControl(id)
	if !ok {
		return nil, errors.New("service is not a trusted peer")
	}
	if len(body) == 0 || len(body) > MaxBodyBytes {
		return nil, errors.New("invalid control body size")
	}
	transport := &http.Transport{TLSClientConfig: t.ControlClientTLS(id), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, route.ControlEndpoint, bytes.NewReader(body))
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
