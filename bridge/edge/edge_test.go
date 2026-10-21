package edge

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"federation-base/bridge/peerset"
	"federation-base/bridge/privateipc"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// plainTransport stands in for TLS: it dials and listens on loopback TCP and
// reports a fixed peer ID, which mutual TLS would supply in production.
type plainTransport struct{ peer spiffeid.ID }

func (p plainTransport) Name() string { return "plain-test" }
func (p plainTransport) Listen(addr string) (Listener, error) {
	l, err := net.Listen("tcp", addr)
	return plainListener{l, p.peer}, err
}
func (p plainTransport) Dial(ctx context.Context, route peerset.Route) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", route.EdgeEndpoint)
}

type plainListener struct {
	net.Listener
	peer spiffeid.ID
}

func (l plainListener) Accept() (net.Conn, spiffeid.ID, error) {
	c, err := l.Listener.Accept()
	return c, l.peer, err
}

func TestRelayAndEdgeCarryOpaqueBytesOnlyAfterAdmission(t *testing.T) {
	dir := t.TempDir()
	uid := uint32(os.Getuid())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aEdge := spiffeid.RequireFromString("spiffe://a.test/federation/edge")
	bEdge := spiffeid.RequireFromString("spiffe://b.test/federation/edge")

	// Edge on B.
	edgeListener, _ := plainTransport{peer: aEdge}.Listen("127.0.0.1:0")
	edgeAddr := edgeListener.(plainListener).Addr().String()
	var bPeers, aPeers peerset.Set
	route := func(name, edge string) privateipc.PeerRoute {
		return privateipc.PeerRoute{ControlServiceID: "spiffe://" + name + ".test/federation/control",
			ControlEndpoint: "https://" + name + "/control", EdgeServiceID: "spiffe://" + name + ".test/federation/edge", EdgeEndpoint: edge}
	}
	_ = bPeers.Replace(privateipc.SetPeersBody{Version: 1, Routes: []privateipc.PeerRoute{route("a", "a:1")}})
	_ = aPeers.Replace(privateipc.SetPeersBody{Version: 1, Routes: []privateipc.PeerRoute{route("b", edgeAddr)}})

	allow := true
	runtimeSocket := filepath.Join(dir, "runtime.sock")
	go privateipc.Serve(ctx, runtimeSocket, uid, func(_ context.Context, r privateipc.Request) privateipc.Response {
		switch r.Operation {
		case privateipc.Admit:
			if r.ServiceID != aEdge.String() {
				return privateipc.Response{ErrorCode: "WRONG_PEER"}
			}
			reply := privateipc.AdmitReply{Allow: allow, RelationshipID: "rel-1", DestinationAddress: "agent1.b.test"}
			if allow {
				reply.Deadline = uint64(time.Now().Add(time.Minute).Unix())
				reply.Response, _ = json.Marshal(map[string]any{"schema": "live-admission/v3", "result": "ALLOW", "deadline": reply.Deadline})
			} else {
				reply.Response, _ = json.Marshal(map[string]any{"schema": "live-admission/v3", "result": "DENY", "reason": "REUSED_NONCE"})
			}
			body, _ := json.Marshal(reply)
			return privateipc.Response{Body: body}
		case privateipc.RouteEgress:
			body, _ := json.Marshal(privateipc.RouteEgressReply{EdgeServiceID: bEdge.String(), EdgeEndpoint: edgeAddr, RelationshipID: "rel-1"})
			return privateipc.Response{Body: body}
		}
		return privateipc.Response{ErrorCode: "UNSUPPORTED"}
	})

	// B's platform ingress socket: echo the header and the agent bytes back.
	ingress := filepath.Join(dir, "ingress.sock")
	ingressListener, _ := privateipc.Listen(ingress)
	headers := make(chan []byte, 2)
	go func() {
		for {
			conn, err := ingressListener.AcceptUnix()
			if err != nil {
				return
			}
			header, _ := ReadFrame(conn)
			headers <- header
			go func() { _, _ = io.Copy(conn, conn) }()
		}
	}()
	streams := &Streams{}
	b := &Edge{Transport: plainTransport{peer: aEdge}, Peers: &bPeers, Runtime: Runtime{runtimeSocket, uid},
		Platform: Platform{IngressSocket: ingress, UID: uid}, Streams: streams}
	go b.Serve(edgeListener)
	relayStreams := &Streams{}
	a := &Relay{Transport: plainTransport{}, Peers: &aPeers, Runtime: Runtime{runtimeSocket, uid}, Streams: relayStreams}
	egress := filepath.Join(dir, "egress.sock")
	go a.ServeEgress(ctx, egress, uid)
	time.Sleep(100 * time.Millisecond)

	open := func() (net.Conn, map[string]any) {
		conn, err := net.Dial("unix", egress)
		if err != nil {
			t.Fatal(err)
		}
		frame, _ := json.Marshal(map[string]any{"schema": "live-admission/v3", "token": "a.b.c",
			"destination_address": "agent1.b.test", "relationship_id": "rel-1"})
		if err := WriteFrame(conn, frame); err != nil {
			t.Fatal(err)
		}
		response, err := ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		var decision map[string]any
		_ = json.Unmarshal(response, &decision)
		return conn, decision
	}

	conn, decision := open()
	if decision["result"] != "ALLOW" {
		t.Fatalf("decision %v", decision)
	}
	header := <-headers
	if string(header) == "" || !json.Valid(header) {
		t.Fatal("no ingress header")
	}
	var h map[string]any
	_ = json.Unmarshal(header, &h)
	if h["schema"] != "ptpan-ingress/1" || h["destination_address"] != "agent1.b.test" {
		t.Fatalf("header %v", h)
	}
	if _, err := conn.Write([]byte("opaque-tls-bytes")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("opaque-tls-bytes"))
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "opaque-tls-bytes" {
		t.Fatalf("echo %q err %v", echo, err)
	}
	relationship := "rel-1"
	deadlineWait := time.Now().Add(time.Second)
	for streams.Count() == 0 && time.Now().Before(deadlineWait) {
		time.Sleep(10 * time.Millisecond)
	}
	if closed := streams.Close(&relationship, nil); closed != 1 {
		t.Fatalf("closed %d streams", closed)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream still open after revoke")
	}

	allow = false
	conn2, decision := open()
	if decision["result"] != "DENY" || decision["reason"] != "REUSED_NONCE" {
		t.Fatalf("decision %v", decision)
	}
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn2.Read(make([]byte, 1)); err == nil {
		t.Fatal("denied stream carried bytes")
	}
	select {
	case <-headers:
		t.Fatal("denied stream reached the platform")
	default:
	}
}

func TestFramesAreBounded(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if WriteFrame(a, make([]byte, MaxFrameBytes+1)) == nil {
		t.Fatal("oversized frame written")
	}
	if WriteFrame(a, nil) == nil {
		t.Fatal("empty frame written")
	}
}

func TestSLIMIsOffInTheDefaultBuild(t *testing.T) {
	if _, err := NewSLIMTransport(SLIMConfig{}); err != ErrSLIMNotBuilt {
		t.Fatalf("SLIM available: %v", err)
	}
}
