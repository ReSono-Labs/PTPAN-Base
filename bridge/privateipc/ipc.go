// Package privateipc is the bridge side of base-bridge-ipc/v2, the private
// Unix socket between the bridge and the adapter runtime. Each side checks
// the other's user ID. The bridge alone supplies the go-spiffe observed
// service ID on inbound calls; a network header cannot supply it.
//
// Runtime to bridge: SEND_CONTROL, SET_PEERS, FETCH_DOMAIN_PROOF,
// CLOSE_STREAMS. Bridge to runtime: RECEIVE_CONTROL, ADMIT, ROUTE_EGRESS.
package privateipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const Schema = "base-bridge-ipc/v2"
const MaxFrameBytes = 128 << 10
const MaxBodyBytes = 72 << 10

const (
	SendControl      = "SEND_CONTROL"
	ReceiveControl   = "RECEIVE_CONTROL"
	SetPeers         = "SET_PEERS"
	FetchDomainProof = "FETCH_DOMAIN_PROOF"
	CloseStreams     = "CLOSE_STREAMS"
	Admit            = "ADMIT"
	RouteEgress      = "ROUTE_EGRESS"
)

type Request struct {
	Schema    string `json:"schema"`
	Operation string `json:"operation"`
	ServiceID string `json:"service_id"`
	Body      []byte `json:"body"`
}

type Response struct {
	Schema    string `json:"schema"`
	Body      []byte `json:"body"`
	ErrorCode string `json:"error_code"`
}

// PeerRoute is one trusted peer's routes as published by the runtime.
type PeerRoute struct {
	ControlServiceID string `json:"control_service_id"`
	ControlEndpoint  string `json:"control_endpoint"`
	EdgeServiceID    string `json:"edge_service_id"`
	EdgeEndpoint     string `json:"edge_endpoint"`
}

type SetPeersBody struct {
	Version uint64      `json:"version"`
	Routes  []PeerRoute `json:"routes"`
}

type FetchDomainProofBody struct {
	URL string `json:"url"`
}

type DomainProofReply struct {
	URL       string `json:"url"`
	FetchedAt string `json:"fetched_at"`
	Body      []byte `json:"body"`
}

type CloseStreamsBody struct {
	RelationshipID *string `json:"relationship_id"`
	PeerServiceID  *string `json:"peer_service_id"`
}

type AdmitReply struct {
	Response           []byte `json:"response"`
	Allow              bool   `json:"allow"`
	Deadline           uint64 `json:"deadline"`
	RelationshipID     string `json:"relationship_id"`
	DestinationAddress string `json:"destination_address"`
}

type RouteEgressReply struct {
	EdgeServiceID  string `json:"edge_service_id"`
	EdgeEndpoint   string `json:"edge_endpoint"`
	RelationshipID string `json:"relationship_id"`
}

func namesService(operation string) (bool, error) {
	switch operation {
	case SendControl, ReceiveControl, Admit:
		return true, nil
	case SetPeers, FetchDomainProof, CloseStreams, RouteEgress:
		return false, nil
	}
	return false, errors.New("unknown IPC operation")
}

func (r Request) Validate() error {
	if r.Schema != Schema || len(r.Body) == 0 || len(r.Body) > MaxBodyBytes {
		return errors.New("invalid IPC request")
	}
	names, err := namesService(r.Operation)
	if err != nil {
		return err
	}
	if names == (r.ServiceID == "") {
		return errors.New("service ID must be present exactly for peer-naming operations")
	}
	return nil
}

// Call sends one request and waits for the reply. expectedUID is the user
// the serving process must run as.
func Call(ctx context.Context, socket string, expectedUID uint32, request Request) (Response, error) {
	request.Schema = Schema
	if err := request.Validate(); err != nil {
		return Response{}, err
	}
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return Response{}, err
	}
	conn := raw.(*net.UnixConn)
	defer conn.Close()
	if uid, err := PeerUID(conn); err != nil || uid != expectedUID {
		return Response{}, errors.New("unexpected IPC peer")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if err := writeFrame(conn, request); err != nil {
		return Response{}, err
	}
	var reply Response
	if err := readFrame(conn, &reply); err != nil {
		return Response{}, err
	}
	if reply.Schema != Schema || len(reply.Body) > MaxBodyBytes || (reply.ErrorCode == "" && len(reply.Body) == 0) {
		return Response{}, errors.New("invalid IPC reply")
	}
	return reply, nil
}

// Listen binds a local socket with mode 0660 (the adapter, bridge and
// platform share one dedicated group; each side checks the other's exact user
// ID), replacing only a stale socket.
func Listen(socket string) (*net.UnixListener, error) {
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("path exists and is not a socket")
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// Serve accepts one framed request per connection from expectedUID only.
func Serve(ctx context.Context, socket string, expectedUID uint32, handle func(context.Context, Request) Response) error {
	listener, err := Listen(socket)
	if err != nil {
		return err
	}
	defer listener.Close()
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
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			uid, err := PeerUID(conn)
			if err != nil || uid != expectedUID {
				return
			}
			var request Request
			if err := readFrame(conn, &request); err != nil {
				return
			}
			var reply Response
			if request.Validate() != nil {
				reply = Response{ErrorCode: "INVALID_REQUEST"}
			} else {
				reply = handle(ctx, request)
			}
			reply.Schema = Schema
			_ = writeFrame(conn, reply)
		}()
	}
}

// PeerUID is the user ID of the process on the other end of a Unix socket.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var inner error
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			inner = e
			return
		}
		uid = cred.Uid
	})
	if err != nil {
		return 0, err
	}
	return uid, inner
}

func writeFrame(w io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > MaxFrameBytes {
		return errors.New("IPC frame too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func readFrame(r io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return errors.New("IPC frame too large")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing IPC JSON: %v", err)
	}
	return nil
}
