package edge

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"time"

	"federation-base/bridge/peerset"
	"federation-base/bridge/privateipc"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Relay carries the local platform's outbound agent streams.
type Relay struct {
	Transport AgentTransport
	Peers     *peerset.Set
	Runtime   Runtime
	Streams   *Streams
}

// ServeEgress accepts streams on the platform's egress socket (mode 0660,
// peer-UID checked) until ctx ends.
func (r *Relay) ServeEgress(ctx context.Context, socket string, platformUID uint32) error {
	listener, err := privateipc.Listen(socket)
	if err != nil {
		return err
	}
	defer os.Remove(socket)
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if uid, err := privateipc.PeerUID(conn); err != nil || uid != platformUID {
			_ = conn.Close()
			continue
		}
		go r.handle(ctx, conn)
	}
}

func (r *Relay) handle(ctx context.Context, local net.Conn) {
	_ = local.SetDeadline(time.Now().Add(handshakeTimeout))
	frame, err := ReadFrame(local)
	if err != nil {
		_ = local.Close()
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	body, err := r.Runtime.call(callCtx, privateipc.RouteEgress, "", frame)
	var route privateipc.RouteEgressReply
	if err != nil || json.Unmarshal(body, &route) != nil {
		_ = local.Close()
		return
	}
	edgeID, err := spiffeid.FromString(route.EdgeServiceID)
	if err != nil {
		_ = local.Close()
		return
	}
	peer, ok := r.Peers.ByEdge(edgeID)
	if !ok || peer.EdgeEndpoint != route.EdgeEndpoint {
		_ = local.Close()
		return
	}
	remote, err := r.Transport.Dial(callCtx, peer)
	if err != nil {
		log.Printf("edge %s unreachable: %v", route.EdgeServiceID, err)
		_ = local.Close()
		return
	}
	_ = remote.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := WriteFrame(remote, frame); err != nil {
		_ = remote.Close()
		_ = local.Close()
		return
	}
	response, err := ReadFrame(remote)
	if err != nil {
		_ = remote.Close()
		_ = local.Close()
		return
	}
	_ = WriteFrame(local, response)
	var decision struct {
		Result   string `json:"result"`
		Deadline uint64 `json:"deadline"`
	}
	if json.Unmarshal(response, &decision) != nil || decision.Result != "ALLOW" || decision.Deadline == 0 {
		_ = remote.Close()
		_ = local.Close()
		return
	}
	r.Streams.pipe(route.RelationshipID, route.EdgeServiceID, local, remote, time.Unix(int64(decision.Deadline), 0))
}

