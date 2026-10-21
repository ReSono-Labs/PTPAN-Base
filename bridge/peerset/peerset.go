// Package peerset holds the trusted peers the adapter runtime published with
// SET_PEERS. Every bridge part reads it live, so approving, suspending or
// removing a peer needs no restart (principle 10). The runtime decides who is
// in the set; the bridge only enforces exact SPIFFE IDs against it.
package peerset

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"federation-base/bridge/privateipc"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Route is one peer's control and edge services.
type Route struct {
	ControlServiceID spiffeid.ID
	ControlEndpoint  string
	EdgeServiceID    spiffeid.ID
	EdgeEndpoint     string
}

var ErrInvalidRoute = errors.New("peer route must name SPIFFE IDs, an https://host/control endpoint and an edge host:port")

// Set is safe for concurrent use.
type Set struct {
	mu      sync.RWMutex
	version uint64
	routes  []Route
}

// Replace installs a published set. An older version is ignored (an equal
// one is a periodic republish and replaces); a malformed set is refused whole.
func (s *Set) Replace(body privateipc.SetPeersBody) error {
	routes := make([]Route, 0, len(body.Routes))
	seen := map[string]struct{}{}
	for _, raw := range body.Routes {
		route, err := parse(raw)
		if err != nil {
			return err
		}
		for _, id := range []string{route.ControlServiceID.String(), route.EdgeServiceID.String()} {
			if _, dup := seen[id]; dup {
				return errors.New("duplicate peer service ID")
			}
			seen[id] = struct{}{}
		}
		routes = append(routes, route)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if body.Version < s.version {
		return nil
	}
	s.version = body.Version
	s.routes = routes
	return nil
}

func parse(raw privateipc.PeerRoute) (Route, error) {
	control, err := spiffeid.FromString(raw.ControlServiceID)
	if err != nil {
		return Route{}, ErrInvalidRoute
	}
	edge, err := spiffeid.FromString(raw.EdgeServiceID)
	if err != nil || edge == control {
		return Route{}, ErrInvalidRoute
	}
	endpoint, err := url.Parse(raw.ControlEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Path != "/control" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return Route{}, ErrInvalidRoute
	}
	host, port, err := net.SplitHostPort(raw.EdgeEndpoint)
	if err != nil || host == "" || strings.ContainsAny(host, "/@") {
		return Route{}, ErrInvalidRoute
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return Route{}, ErrInvalidRoute
	}
	return Route{ControlServiceID: control, ControlEndpoint: raw.ControlEndpoint, EdgeServiceID: edge, EdgeEndpoint: raw.EdgeEndpoint}, nil
}

// ByControl returns the route whose control service is exactly id.
func (s *Set) ByControl(id spiffeid.ID) (Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, route := range s.routes {
		if route.ControlServiceID == id {
			return route, true
		}
	}
	return Route{}, false
}

// ByEdge returns the route whose edge service is exactly id.
func (s *Set) ByEdge(id spiffeid.ID) (Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, route := range s.routes {
		if route.EdgeServiceID == id {
			return route, true
		}
	}
	return Route{}, false
}

// AllowsControl and AllowsEdge are mutual-TLS authorizer checks.
func (s *Set) AllowsControl(id spiffeid.ID) bool { _, ok := s.ByControl(id); return ok }
func (s *Set) AllowsEdge(id spiffeid.ID) bool    { _, ok := s.ByEdge(id); return ok }
