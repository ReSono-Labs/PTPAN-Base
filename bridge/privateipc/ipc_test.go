package privateipc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateUnixFrameAndPeerUID(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "bridge.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uid := uint32(os.Getuid())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, socket, uid, func(_ context.Context, r Request) Response {
			return Response{Body: r.Body}
		})
	}()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	reply, err := Call(ctx, socket, uid, Request{Operation: ReceiveControl, ServiceID: "spiffe://a.test/control", Body: []byte(`{"x":1}`)})
	if err != nil || string(reply.Body) != `{"x":1}` {
		t.Fatalf("reply=%+v err=%v", reply, err)
	}
	if _, err := Call(ctx, socket, uid+1, Request{Operation: SetPeers, Body: []byte(`{}`)}); err == nil {
		t.Fatal("wrong server owner accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server failed to stop")
	}
}

func TestServiceIDPresentExactlyForPeerNamingOperations(t *testing.T) {
	for _, op := range []string{SendControl, ReceiveControl, Admit} {
		if (Request{Schema: Schema, Operation: op, ServiceID: "spiffe://a.test/x", Body: []byte("x")}).Validate() != nil {
			t.Fatalf("%s with service rejected", op)
		}
		if (Request{Schema: Schema, Operation: op, Body: []byte("x")}).Validate() == nil {
			t.Fatalf("%s without service accepted", op)
		}
	}
	for _, op := range []string{SetPeers, FetchDomainProof, CloseStreams, RouteEgress} {
		if (Request{Schema: Schema, Operation: op, Body: []byte("x")}).Validate() != nil {
			t.Fatalf("%s rejected", op)
		}
		if (Request{Schema: Schema, Operation: op, ServiceID: "spiffe://a.test/x", Body: []byte("x")}).Validate() == nil {
			t.Fatalf("%s with service accepted", op)
		}
	}
	if (Request{Schema: Schema, Operation: "RESOLVE_NAME_EVIDENCE", Body: []byte("x")}).Validate() == nil {
		t.Fatal("removed operation accepted")
	}
	if (Request{Schema: "base-bridge-ipc/v1", Operation: SetPeers, Body: []byte("x")}).Validate() == nil {
		t.Fatal("old schema accepted")
	}
}
