// bridge-runtime is the adapter's network side. It serves the peer /control
// endpoint and the agent edge over SPIFFE mutual TLS with exact service IDs
// from the live peer set, relays the local platform's agent streams, fetches
// domain proofs, and carries everything else to the adapter runtime over the
// private IPC socket. It decides nothing: the runtime does.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"federation-base/bridge/domainproof"
	"federation-base/bridge/edge"
	"federation-base/bridge/peerset"
	"federation-base/bridge/peertransport"
	"federation-base/bridge/privateipc"
)

func main() {
	var controlListen, edgeListen, bridgeSocket, runtimeSocket, egressSocket, ingressSocket, agentTransport string
	var controlServiceID, edgeServiceID string
	var runtimeUID, platformUID uint
	var testHTTPProof bool
	flag.StringVar(&controlListen, "control-listen", "", "peer /control listener address")
	flag.StringVar(&controlServiceID, "control-service-id", "", "this platform's control service SPIFFE ID")
	flag.StringVar(&edgeServiceID, "edge-service-id", "", "this platform's edge service SPIFFE ID")
	flag.StringVar(&edgeListen, "edge-listen", "", "agent edge listener address")
	flag.StringVar(&bridgeSocket, "bridge-socket", "", "IPC socket served for the adapter runtime")
	flag.StringVar(&runtimeSocket, "runtime-socket", "", "the adapter runtime's IPC socket")
	flag.UintVar(&runtimeUID, "runtime-uid", 0, "user ID of the adapter runtime process")
	flag.StringVar(&egressSocket, "egress-socket", "", "local socket for the platform's outbound agent streams")
	flag.StringVar(&ingressSocket, "ingress-socket", "", "the platform's socket for inbound agent streams")
	flag.UintVar(&platformUID, "platform-uid", 0, "user ID of the platform process")
	flag.StringVar(&agentTransport, "agent-transport", "tls", "agent transport: tls (SLIM is not built)")
	flag.BoolVar(&testHTTPProof, "test-allow-http-domain-proof", false, "isolated test stacks only: accept plain HTTP domain proofs")
	flag.Parse()
	for name, value := range map[string]string{"control-listen": controlListen, "edge-listen": edgeListen, "bridge-socket": bridgeSocket,
		"control-service-id": controlServiceID, "edge-service-id": edgeServiceID,
		"runtime-socket": runtimeSocket, "egress-socket": egressSocket, "ingress-socket": ingressSocket} {
		if value == "" {
			log.Fatalf("--%s is required", name)
		}
	}
	if runtimeUID > uint(^uint32(0)) || platformUID > uint(^uint32(0)) {
		log.Fatal("user IDs out of range")
	}
	if os.Getenv("SPIFFE_ENDPOINT_SOCKET") == "" {
		log.Fatal("SPIFFE_ENDPOINT_SOCKET is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	peers := &peerset.Set{}
	transport, err := peertransport.Open(ctx, peers, controlServiceID, edgeServiceID)
	if err != nil {
		log.Fatal(err)
	}
	defer transport.Close()
	var agents edge.AgentTransport
	switch agentTransport {
	case "tls":
		agents = edge.NewTLSTransport(transport)
	case "slim":
		if agents, err = edge.NewSLIMTransport(edge.SLIMConfig{}); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown agent transport %q", agentTransport)
	}
	runtime := edge.Runtime{Socket: runtimeSocket, UID: uint32(runtimeUID)}
	streams := &edge.Streams{}
	proofs := domainproof.New(testHTTPProof)
	results := make(chan error, 4)

	controlListener, err := net.Listen("tcp", controlListen)
	if err != nil {
		log.Fatal(err)
	}
	go func() { <-ctx.Done(); _ = controlListener.Close() }()
	go func() {
		results <- transport.ServeControl(controlListener, func(callCtx context.Context, inbound peertransport.AuthenticatedRequest) ([]byte, error) {
			callCtx, cancel := context.WithTimeout(callCtx, 10*time.Second)
			defer cancel()
			reply, err := privateipc.Call(callCtx, runtime.Socket, runtime.UID, privateipc.Request{
				Operation: privateipc.ReceiveControl, ServiceID: inbound.ServiceID.String(), Body: inbound.Body,
			})
			if err != nil {
				return nil, err
			}
			if reply.ErrorCode != "" {
				return nil, errors.New(reply.ErrorCode)
			}
			return reply.Body, nil
		})
	}()

	edgeListener, err := agents.Listen(edgeListen)
	if err != nil {
		log.Fatal(err)
	}
	go func() { <-ctx.Done(); _ = edgeListener.Close() }()
	inbound := &edge.Edge{Transport: agents, Peers: peers, Runtime: runtime,
		Platform: edge.Platform{IngressSocket: ingressSocket, UID: uint32(platformUID)}, Streams: streams}
	go func() { results <- inbound.Serve(edgeListener) }()
	relay := &edge.Relay{Transport: agents, Peers: peers, Runtime: runtime, Streams: streams}
	go func() { results <- relay.ServeEgress(ctx, egressSocket, uint32(platformUID)) }()

	go func() {
		results <- privateipc.Serve(ctx, bridgeSocket, uint32(runtimeUID), func(callCtx context.Context, request privateipc.Request) privateipc.Response {
			return handleRuntime(callCtx, request, transport, peers, proofs, streams)
		})
	}()
	log.Printf("BRIDGE_READY control=%s edge=%s transport=%s", controlListener.Addr(), edgeListen, agents.Name())
	select {
	case err = <-results:
	case <-ctx.Done():
		return
	}
	if err != nil && ctx.Err() == nil {
		log.Fatalf("bridge stopped: %v", err)
	}
}

func handleRuntime(ctx context.Context, request privateipc.Request, transport *peertransport.Transport, peers *peerset.Set,
	proofs *domainproof.Fetcher, streams *edge.Streams) privateipc.Response {
	ok := func(v any) privateipc.Response {
		body, _ := json.Marshal(v)
		return privateipc.Response{Body: body}
	}
	switch request.Operation {
	case privateipc.SendControl:
		sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		receipt, err := transport.SendControl(sendCtx, request.ServiceID, request.Body)
		if err != nil {
			log.Printf("delivery to %s failed: %v", request.ServiceID, err)
			return privateipc.Response{ErrorCode: "PEER_DELIVERY_FAILED"}
		}
		return privateipc.Response{Body: receipt}
	case privateipc.SetPeers:
		var body privateipc.SetPeersBody
		if json.Unmarshal(request.Body, &body) != nil || peers.Replace(body) != nil {
			return privateipc.Response{ErrorCode: "INVALID_PEER_SET"}
		}
		return ok(map[string]uint64{"version": body.Version})
	case privateipc.FetchDomainProof:
		var body privateipc.FetchDomainProofBody
		if json.Unmarshal(request.Body, &body) != nil {
			return privateipc.Response{ErrorCode: "INVALID_REQUEST"}
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		document, at, err := proofs.Fetch(fetchCtx, body.URL)
		if err != nil {
			return privateipc.Response{ErrorCode: "DOMAIN_PROOF_UNAVAILABLE"}
		}
		return ok(privateipc.DomainProofReply{URL: body.URL, FetchedAt: at.Format(time.RFC3339), Body: document})
	case privateipc.CloseStreams:
		var body privateipc.CloseStreamsBody
		if json.Unmarshal(request.Body, &body) != nil {
			return privateipc.Response{ErrorCode: "INVALID_REQUEST"}
		}
		return ok(map[string]int{"closed": streams.Close(body.RelationshipID, body.PeerServiceID)})
	}
	return privateipc.Response{ErrorCode: "UNSUPPORTED_OPERATION"}
}
