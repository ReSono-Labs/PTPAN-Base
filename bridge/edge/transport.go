package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"federation-base/bridge/peerset"
	"federation-base/bridge/peertransport"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// AgentTransport carries agent streams between platform edges. TLS 1.3 with
// exact SPIFFE IDs is the default and the only enabled transport; SLIM is
// the AGNTCY alternative, wired in behind the same interface and off (D3,
// review 16.8).
type AgentTransport interface {
	Name() string
	// Listen accepts streams from peer relays at addr.
	Listen(addr string) (Listener, error)
	// Dial opens a stream to the peer's edge.
	Dial(ctx context.Context, route peerset.Route) (net.Conn, error)
}

type Listener interface {
	Accept() (net.Conn, spiffeid.ID, error)
	Close() error
}

// TLSTransport is mutual TLS 1.3 from the SPIRE Workload API.
type TLSTransport struct {
	peers *peertransport.Transport
}

func NewTLSTransport(peers *peertransport.Transport) *TLSTransport {
	return &TLSTransport{peers: peers}
}

func (t *TLSTransport) Name() string { return "tls" }

func (t *TLSTransport) Listen(addr string) (Listener, error) {
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	config := t.peers.EdgeServerTLS()
	config.MinVersion = tls.VersionTLS13
	return &tlsListener{inner: tls.NewListener(raw, config)}, nil
}

func (t *TLSTransport) Dial(ctx context.Context, route peerset.Route) (net.Conn, error) {
	config := t.peers.EdgeClientTLS(route.EdgeServiceID)
	config.MinVersion = tls.VersionTLS13
	dialer := tls.Dialer{Config: config}
	return dialer.DialContext(ctx, "tcp", route.EdgeEndpoint)
}

type tlsListener struct{ inner net.Listener }

func (l *tlsListener) Close() error { return l.inner.Close() }

func (l *tlsListener) Accept() (net.Conn, spiffeid.ID, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, spiffeid.ID{}, err
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			continue
		}
		state := tlsConn.ConnectionState()
		id, err := peertransport.PeerID(&state)
		if err != nil {
			_ = conn.Close()
			continue
		}
		return tlsConn, id, nil
	}
}

// ErrSLIMNotBuilt is returned when SLIM is selected in a build without it.
var ErrSLIMNotBuilt = errors.New("SLIM agent transport is not built (deferred, D3); use --agent-transport tls")
