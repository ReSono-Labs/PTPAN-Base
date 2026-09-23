// Package peerroute chooses one authorized control service for an outbound
// send. The choice is the exact SPIFFE ID named by the local Base. A platform
// ID inside the event body is not an input.
package peerroute

import (
	"errors"
	"net/url"
	"strings"
)

type Route struct {
	ServiceID string
	Endpoint  string
}

var (
	ErrUnknownPeer     = errors.New("service is not an authorized peer")
	ErrServiceRequired = errors.New("service ID is required when more than one peer is authorized")
	ErrDuplicatePeer   = errors.New("duplicate peer service ID")
	ErrInvalidPeer     = errors.New("peer must be spiffe-id=https://host/control")
)

func Parse(value string) (Route, error) {
	service, endpoint, ok := strings.Cut(value, "=")
	if !ok {
		return Route{}, ErrInvalidPeer
	}
	route := Route{ServiceID: service, Endpoint: endpoint}
	if err := route.validate(); err != nil {
		return Route{}, err
	}
	return route, nil
}

func Normalize(routes []Route) ([]Route, error) {
	seen := make(map[string]struct{}, len(routes))
	out := make([]Route, 0, len(routes))
	for _, route := range routes {
		if err := route.validate(); err != nil {
			return nil, err
		}
		if _, ok := seen[route.ServiceID]; ok {
			return nil, ErrDuplicatePeer
		}
		seen[route.ServiceID] = struct{}{}
		out = append(out, route)
	}
	if len(out) == 0 {
		return nil, ErrInvalidPeer
	}
	return out, nil
}

// Select returns the endpoint for requestedService. An empty request is the
// single configured peer. It does not inspect event bytes.
func Select(routes []Route, requestedService string) (Route, error) {
	normalized, err := Normalize(routes)
	if err != nil {
		return Route{}, err
	}
	if requestedService == "" {
		if len(normalized) != 1 {
			return Route{}, ErrServiceRequired
		}
		return normalized[0], nil
	}
	for _, route := range normalized {
		if route.ServiceID == requestedService {
			return route, nil
		}
	}
	return Route{}, ErrUnknownPeer
}

func (route Route) validate() error {
	parsed, err := url.Parse(route.Endpoint)
	if err != nil || !strings.HasPrefix(route.ServiceID, "spiffe://") || strings.Contains(route.ServiceID, "=") || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "/control" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidPeer
	}
	return nil
}
