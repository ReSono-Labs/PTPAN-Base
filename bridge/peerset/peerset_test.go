package peerset

import (
	"testing"

	"federation-base/bridge/privateipc"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func route(name string) privateipc.PeerRoute {
	return privateipc.PeerRoute{
		ControlServiceID: "spiffe://" + name + ".test/federation/control",
		ControlEndpoint:  "https://" + name + "-bridge:8444/control",
		EdgeServiceID:    "spiffe://" + name + ".test/federation/edge",
		EdgeEndpoint:     name + "-bridge:8443",
	}
}

func id(raw string) spiffeid.ID { return spiffeid.RequireFromString(raw) }

func TestLiveReplaceAddsAndRemovesPeersWithoutRestart(t *testing.T) {
	var set Set
	if err := set.Replace(privateipc.SetPeersBody{Version: 1, Routes: []privateipc.PeerRoute{route("b")}}); err != nil {
		t.Fatal(err)
	}
	if !set.AllowsControl(id("spiffe://b.test/federation/control")) || !set.AllowsEdge(id("spiffe://b.test/federation/edge")) {
		t.Fatal("b not allowed")
	}
	if set.AllowsControl(id("spiffe://b.test/federation/edge")) {
		t.Fatal("edge ID accepted as control")
	}
	_ = set.Replace(privateipc.SetPeersBody{Version: 2, Routes: []privateipc.PeerRoute{route("c")}})
	if set.AllowsControl(id("spiffe://b.test/federation/control")) || !set.AllowsControl(id("spiffe://c.test/federation/control")) {
		t.Fatal("set not replaced")
	}
	_ = set.Replace(privateipc.SetPeersBody{Version: 1, Routes: []privateipc.PeerRoute{route("b")}})
	if !set.AllowsControl(id("spiffe://c.test/federation/control")) {
		t.Fatal("older version applied")
	}
}

func TestMalformedOrDuplicateRoutesAreRefusedWhole(t *testing.T) {
	var set Set
	bad := route("b")
	bad.ControlEndpoint = "http://b-bridge/control"
	if set.Replace(privateipc.SetPeersBody{Version: 1, Routes: []privateipc.PeerRoute{bad}}) == nil {
		t.Fatal("plain HTTP control accepted")
	}
	bad = route("b")
	bad.EdgeEndpoint = "https://b-bridge:8443"
	if set.Replace(privateipc.SetPeersBody{Version: 1, Routes: []privateipc.PeerRoute{bad}}) == nil {
		t.Fatal("edge URL accepted")
	}
	if set.Replace(privateipc.SetPeersBody{Version: 1, Routes: []privateipc.PeerRoute{route("b"), route("b")}}) == nil {
		t.Fatal("duplicate accepted")
	}
}
