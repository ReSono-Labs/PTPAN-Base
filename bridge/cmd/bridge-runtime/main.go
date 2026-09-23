// bridge-runtime connects Base's private IPC to the exact-ID SPIFFE peer
// transport. It carries bytes and authenticated service evidence; Base owns
// all parsing, policy decisions, receipts, and persistence.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"federation-base/bridge/peerroute"
	"federation-base/bridge/peertransport"
	"federation-base/bridge/privateipc"
	"federation-base/bridge/upstream"
	directory "github.com/agntcy/dir/client"
)

func main() {
	var listen, peerEndpoint, expectedPeer, baseSocket, bridgeSocket, directoryEndpoint, directoryServerID, oasfURL string
	var baseUID uint
	var extraPeers []string
	flag.StringVar(&listen, "listen", "", "control listener address")
	flag.StringVar(&peerEndpoint, "peer-endpoint", "", "exact peer HTTPS /control endpoint")
	flag.StringVar(&expectedPeer, "expected-peer", "", "exact peer control SPIFFE ID")
	flag.Func("peer", "additional spiffe-id=https://host/control route; repeat for each peer", func(value string) error {
		extraPeers = append(extraPeers, value)
		return nil
	})
	flag.StringVar(&baseSocket, "base-socket", "", "Base inbound Unix socket")
	flag.StringVar(&bridgeSocket, "bridge-socket", "", "Bridge outbound Unix socket")
	flag.StringVar(&directoryEndpoint, "directory", "", "local Directory gRPC endpoint")
	flag.StringVar(&directoryServerID, "directory-server-id", "", "exact local Directory SPIFFE ID")
	flag.StringVar(&oasfURL, "oasf", "", "local OASF schema endpoint")
	flag.UintVar(&baseUID, "base-uid", 0, "expected Base process UID")
	flag.Parse()
	if listen == "" || peerEndpoint == "" || expectedPeer == "" || baseSocket == "" || bridgeSocket == "" || directoryEndpoint == "" || directoryServerID == "" || oasfURL == "" || baseUID > uint(^uint32(0)) {
		log.Fatal("all endpoint, identity, socket, and Base UID flags are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	spiffeSocket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	clients, err := upstream.Open(ctx, upstream.Config{Directory: directory.Config{ServerAddress: directoryEndpoint, AuthMode: "x509", SpiffeSocketPath: spiffeSocket}, OASFSchemaURL: oasfURL, ExpectedDirectoryServerID: directoryServerID})
	if err != nil {
		log.Fatal(err)
	}
	defer clients.Close()
	routes := []peerroute.Route{{ServiceID: expectedPeer, Endpoint: peerEndpoint}}
	for _, extra := range extraPeers {
		route, parseErr := peerroute.Parse(extra)
		if parseErr != nil {
			log.Fatal(parseErr)
		}
		routes = append(routes, route)
	}
	routes, err = peerroute.Normalize(routes)
	if err != nil {
		log.Fatal(err)
	}
	serviceIDs := make([]string, 0, len(routes))
	for _, route := range routes {
		serviceIDs = append(serviceIDs, route.ServiceID)
	}
	transport, err := peertransport.Open(ctx, serviceIDs...)
	if err != nil {
		log.Fatal(err)
	}
	defer transport.Close()
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- transport.Serve(listener, func(requestCtx context.Context, inbound peertransport.AuthenticatedRequest) ([]byte, error) {
			callCtx, cancel := context.WithTimeout(requestCtx, 10*time.Second)
			defer cancel()
			response, callErr := privateipc.Call(callCtx, baseSocket, privateipc.Request{
				Schema: privateipc.Schema, Operation: "RECEIVE_CONTROL",
				ServiceID: inbound.ServiceID.String(), Body: inbound.Body,
			})
			if callErr != nil {
				return nil, callErr
			}
			if response.ErrorCode != "" {
				return nil, errors.New("Base rejected inbound control")
			}
			return response.Body, nil
		})
	}()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	log.Printf("BRIDGE_READY listen=%s peers=%d", listener.Addr(), len(routes))
	ipcResult := make(chan error, 1)
	go func() {
		ipcResult <- privateipc.Serve(ctx, bridgeSocket, uint32(baseUID), func(callCtx context.Context, request privateipc.Request) privateipc.Response {
			if request.Operation == "RESOLVE_NAME_EVIDENCE" {
				var query struct {
					CID string `json:"cid"`
				}
				if err := json.Unmarshal(request.Body, &query); err != nil || query.CID == "" {
					return privateipc.Response{ErrorCode: "INVALID_EVIDENCE_QUERY"}
				}
				lookupCtx, cancel := context.WithTimeout(callCtx, 10*time.Second)
				defer cancel()
				evidence, err := clients.NameEvidenceByCID(lookupCtx, query.CID, directoryServerID)
				if err != nil {
					return privateipc.Response{ErrorCode: "DIRECTORY_EVIDENCE_FAILED"}
				}
				body, err := json.Marshal(evidence)
				if err != nil {
					return privateipc.Response{ErrorCode: "DIRECTORY_EVIDENCE_FAILED"}
				}
				return privateipc.Response{Body: body}
			}
			if request.Operation != "SEND_CONTROL" {
				return privateipc.Response{ErrorCode: "UNSUPPORTED_OPERATION"}
			}
			route, routeErr := peerroute.Select(routes, request.ServiceID)
			if routeErr != nil {
				return privateipc.Response{ErrorCode: "PEER_NOT_AUTHORIZED"}
			}
			sendCtx, cancel := context.WithTimeout(callCtx, 10*time.Second)
			defer cancel()
			body, sendErr := transport.SendTo(sendCtx, route.Endpoint, route.ServiceID, request.Body)
			if sendErr != nil {
				return privateipc.Response{ErrorCode: "PEER_DELIVERY_FAILED"}
			}
			return privateipc.Response{Body: body}
		})
	}()
	select {
	case err = <-serverResult:
	case err = <-ipcResult:
	case <-ctx.Done():
		return
	}
	if err != nil && ctx.Err() == nil {
		log.Fatal(fmt.Errorf("bridge stopped: %w", err))
	}
}
