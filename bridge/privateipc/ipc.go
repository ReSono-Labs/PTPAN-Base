// Package privateipc carries authenticated peer bytes between the Go bridge
// and the Rust Base over a local Unix socket. The bridge alone supplies the
// go-spiffe observed ServiceID; a network header cannot supply this field.
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

const Schema = "base-bridge-ipc/v1"
const MaxFrameBytes = 128 << 10
const MaxBodyBytes = 72 << 10

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

func (r Request) Validate() error {
	if r.Schema != Schema || len(r.Body) == 0 || len(r.Body) > MaxBodyBytes {
		return errors.New("invalid IPC request")
	}
	switch r.Operation {
	case "SEND_CONTROL":
		// The local Base may name the destination service. The bridge checks
		// that name against its authorized set. RESOLVE_NAME_EVIDENCE cannot.
	case "RESOLVE_NAME_EVIDENCE":
		if r.ServiceID != "" {
			return errors.New("outbound service ID is bridge-owned")
		}
	case "RECEIVE_CONTROL":
		if r.ServiceID == "" {
			return errors.New("authenticated service ID required")
		}
	default:
		return errors.New("unknown IPC operation")
	}
	return nil
}

func Call(ctx context.Context, socket string, request Request) (Response, error) {
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

// Serve accepts one framed request per connection. expectedUID is the Rust
// Base process UID; the private socket must be mounted only into this pair.
func Serve(ctx context.Context, socket string, expectedUID uint32, handle func(context.Context, Request) Response) error {
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
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
			uid, err := peerUID(conn)
			if err != nil || uid != expectedUID {
				return
			}
			var request Request
			if err := readFrame(conn, &request); err != nil || request.Validate() != nil {
				return
			}
			reply := handle(ctx, request)
			reply.Schema = Schema
			_ = writeFrame(conn, reply)
		}()
	}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
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
