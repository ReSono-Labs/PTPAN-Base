package edge

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"time"

	"federation-base/bridge/peerset"
	"federation-base/bridge/privateipc"
)

// Runtime is the adapter runtime's IPC socket.
type Runtime struct {
	Socket string
	UID    uint32
}

func (r Runtime) call(ctx context.Context, operation, serviceID string, body []byte) ([]byte, error) {
	reply, err := privateipc.Call(ctx, r.Socket, r.UID, privateipc.Request{Operation: operation, ServiceID: serviceID, Body: body})
	if err != nil {
		return nil, err
	}
	if reply.ErrorCode != "" {
		return nil, errors.New(reply.ErrorCode)
	}
	return reply.Body, nil
}

// Platform is the local platform's stream sockets and process user.
type Platform struct {
	IngressSocket string
	UID           uint32
}

// Edge serves peer relays.
type Edge struct {
	Transport AgentTransport
	Peers     *peerset.Set
	Runtime   Runtime
	Platform  Platform
	Streams   *Streams
}

const handshakeTimeout = 10 * time.Second

// Serve accepts peer streams until the listener closes.
func (e *Edge) Serve(listener Listener) error {
	for {
		conn, peer, err := listener.Accept()
		if err != nil {
			return err
		}
		if _, ok := e.Peers.ByEdge(peer); !ok {
			_ = conn.Close()
			continue
		}
		go e.handle(conn, peer.String())
	}
}

func (e *Edge) handle(conn net.Conn, peerEdgeID string) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	frame, err := ReadFrame(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	body, err := e.Runtime.call(ctx, privateipc.Admit, peerEdgeID, frame)
	var reply privateipc.AdmitReply
	if err != nil || json.Unmarshal(body, &reply) != nil || len(reply.Response) == 0 {
		_ = conn.Close()
		return
	}
	if err := WriteFrame(conn, reply.Response); err != nil || !reply.Allow {
		_ = conn.Close()
		return
	}
	deadline := time.Unix(int64(reply.Deadline), 0)
	local, err := dialPlatform(e.Platform.IngressSocket, e.Platform.UID)
	if err != nil {
		log.Printf("ingress socket unavailable: %v", err)
		_ = conn.Close()
		return
	}
	header, _ := json.Marshal(map[string]any{
		"schema":              "ptpan-ingress/1",
		"relationship_id":     reply.RelationshipID,
		"destination_address": reply.DestinationAddress,
		"deadline":            reply.Deadline,
	})
	if err := WriteFrame(local, header); err != nil {
		_ = local.Close()
		_ = conn.Close()
		return
	}
	e.Streams.pipe(reply.RelationshipID, peerEdgeID, conn, local, deadline)
}

func dialPlatform(socket string, uid uint32) (net.Conn, error) {
	raw, err := net.DialTimeout("unix", socket, handshakeTimeout)
	if err != nil {
		return nil, err
	}
	conn := raw.(*net.UnixConn)
	if got, err := privateipc.PeerUID(conn); err != nil || got != uid {
		_ = conn.Close()
		return nil, errors.New("unexpected platform socket owner")
	}
	return conn, nil
}
