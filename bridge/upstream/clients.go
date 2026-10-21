// Package upstream holds the optional AGNTCY Directory and OASF clients for
// the publication path and optional Directory evidence. bridge-runtime does
// not open them: no PTPAN trust decision depends on Directory.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"os"

	catalogv1 "github.com/agntcy/dir/api/catalog/v1"
	corev1 "github.com/agntcy/dir/api/core/v1"
	routingv1 "github.com/agntcy/dir/api/routing/v1"
	searchv1 "github.com/agntcy/dir/api/search/v1"
	signv1 "github.com/agntcy/dir/api/sign/v1"
	storev1 "github.com/agntcy/dir/api/store/v1"
	directory "github.com/agntcy/dir/client"
	"github.com/agntcy/oasf-sdk/pkg/schema"
	"github.com/agntcy/oasf-sdk/pkg/validator"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

type Config struct {
	Directory                 directory.Config
	OASFSchemaURL             string
	ExpectedDirectoryServerID string
}

// Clients contains the real upstream SDK handles. Its construction fails
// closed if the Directory auth profile or SPIFFE socket was not selected.
type Clients struct {
	Directory      *directory.Client
	Catalog        catalogv1.AIFinderServiceClient
	OASF           *validator.Validator
	OASFSchema     *schema.Schema
	Workload       *workloadapi.X509Source
	bundles        *workloadapi.BundleSource
	workloadClient *workloadapi.Client
	catalogConn    *grpc.ClientConn
}

func Open(ctx context.Context, cfg Config) (*Clients, error) {
	if cfg.Directory.ServerAddress == "" {
		return nil, errors.New("Directory server address is required")
	}
	if cfg.Directory.AuthMode != "x509" || cfg.Directory.TlsSkipVerify {
		return nil, errors.New("baseline Directory auth requires SPIRE x509 and certificate verification")
	}
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socket == "" {
		return nil, errors.New("bridge requires an explicit SPIFFE Workload API socket")
	}
	if cfg.Directory.SpiffeSocketPath != socket {
		return nil, errors.New("Directory and bridge must use the same SPIRE socket")
	}
	id, err := spiffeid.FromString(cfg.ExpectedDirectoryServerID)
	if err != nil {
		return nil, fmt.Errorf("exact Directory server identity required: %w", err)
	}
	validate, err := validator.New(cfg.OASFSchemaURL)
	if err != nil {
		return nil, fmt.Errorf("OASF validator: %w", err)
	}
	schemaClient, err := schema.New(cfg.OASFSchemaURL)
	if err != nil {
		return nil, fmt.Errorf("OASF schema client: %w", err)
	}
	workloadClient, err := workloadapi.New(ctx, workloadapi.WithAddr(socket))
	if err != nil {
		return nil, fmt.Errorf("SPIFFE Workload API: %w", err)
	}
	workload, err := workloadapi.NewX509Source(ctx, workloadapi.WithClient(workloadClient))
	if err != nil {
		_ = workloadClient.Close()
		return nil, fmt.Errorf("SPIRE X509 source: %w", err)
	}
	bundles, err := workloadapi.NewBundleSource(ctx, workloadapi.WithClient(workloadClient))
	if err != nil {
		_ = workload.Close()
		_ = workloadClient.Close()
		return nil, fmt.Errorf("SPIRE bundle source: %w", err)
	}
	catalogConn, err := grpc.NewClient(cfg.Directory.ServerAddress, grpc.WithTransportCredentials(grpccredentials.MTLSClientCredentials(workload, bundles, tlsconfig.AuthorizeID(id))))
	if err != nil {
		_ = bundles.Close()
		_ = workload.Close()
		_ = workloadClient.Close()
		return nil, fmt.Errorf("AGNTCY AI Finder connection: %w", err)
	}
	// Directory's exported Client embeds its generated service interfaces.
	// Its official convenience methods use those interfaces. This construction
	// preserves upstream Push/Pull/Sign/Publish logic while replacing only the
	// wrapper's AuthorizeAny transport with one exact-ID go-spiffe connection.
	dir := &directory.Client{
		StoreServiceClient:   storev1.NewStoreServiceClient(catalogConn),
		SyncServiceClient:    storev1.NewSyncServiceClient(catalogConn),
		RoutingServiceClient: routingv1.NewRoutingServiceClient(catalogConn),
		SearchServiceClient:  searchv1.NewSearchServiceClient(catalogConn),
		SignServiceClient:    signv1.NewSignServiceClient(catalogConn),
	}
	return &Clients{
		Directory:      dir,
		Catalog:        catalogv1.NewAIFinderServiceClient(catalogConn),
		OASF:           validate,
		OASFSchema:     schemaClient,
		Workload:       workload,
		bundles:        bundles,
		workloadClient: workloadClient,
		catalogConn:    catalogConn,
	}, nil
}

func (c *Clients) Close() error {
	return errors.Join(c.catalogConn.Close(), c.Workload.Close(), c.bundles.Close(), c.workloadClient.Close())
}

func (c *Clients) ReadCatalog(ctx context.Context) (*catalogv1.GetWellKnownCatalogResponse, error) {
	return c.Catalog.GetWellKnownCatalog(ctx, &catalogv1.GetWellKnownCatalogRequest{})
}

func (c *Clients) ValidateRecord(ctx context.Context, record *structpb.Struct) (bool, []string, []string, error) {
	return c.OASF.ValidateRecord(ctx, record)
}

func (c *Clients) AvailableOASFVersions(ctx context.Context) ([]string, error) {
	return c.OASFSchema.GetAvailableSchemaVersions(ctx)
}

func (c *Clients) Push(ctx context.Context, record *corev1.Record) (*corev1.RecordRef, error) {
	return c.Directory.Push(ctx, record)
}

func (c *Clients) Pull(ctx context.Context, ref *corev1.RecordRef) (*corev1.Record, error) {
	return c.Directory.Pull(ctx, ref)
}

// SignRecord calls the Go Directory SDK's native cosign path. The caller
// supplies an operator-controlled key reference; Base never fabricates one.
func (c *Clients) SignRecord(ctx context.Context, ref *corev1.RecordRef, keyRef string) (*signv1.SignResponse, error) {
	if keyRef == "" {
		return nil, errors.New("signing key reference is required")
	}
	return c.Directory.Sign(ctx, &signv1.SignRequest{
		RecordRef: ref,
		Provider: &signv1.SignRequestProvider{Request: &signv1.SignRequestProvider_Key{
			Key: &signv1.SignWithKey{PrivateKey: keyRef},
		}},
	})
}

// PublishRecord is deliberately separate from Push and Sign. The Base policy
// layer must explicitly permit this CID as provider-level public evidence.
func (c *Clients) PublishRecord(ctx context.Context, ref *corev1.RecordRef) error {
	if ref == nil || ref.GetCid() == "" {
		return errors.New("published record CID is required")
	}
	return c.Directory.Publish(ctx, &routingv1.PublishRequest{Request: &routingv1.PublishRequest_RecordRefs{
		RecordRefs: &routingv1.RecordRefs{Refs: []*corev1.RecordRef{ref}},
	}})
}

func (c *Clients) UnpublishRecord(ctx context.Context, ref *corev1.RecordRef) error {
	if ref == nil || ref.GetCid() == "" {
		return errors.New("unpublished record CID is required")
	}
	return c.Directory.Unpublish(ctx, &routingv1.UnpublishRequest{Request: &routingv1.UnpublishRequest_RecordRefs{
		RecordRefs: &routingv1.RecordRefs{Refs: []*corev1.RecordRef{ref}},
	}})
}

func (c *Clients) VerifyRecord(ctx context.Context, ref *corev1.RecordRef) (*signv1.VerifyResponse, error) {
	return c.Directory.Verify(ctx, &signv1.VerifyRequest{RecordRef: ref})
}
