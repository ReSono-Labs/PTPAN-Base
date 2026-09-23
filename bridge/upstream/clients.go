// Package upstream calls the selected upstream Directory, OASF, and SPIFFE
// modules. It does not make Federation Base peer or relationship decisions.
package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"time"

	catalogv1 "github.com/agntcy/dir/api/catalog/v1"
	corev1 "github.com/agntcy/dir/api/core/v1"
	namingv1 "github.com/agntcy/dir/api/naming/v1"
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
		NamingServiceClient:  namingv1.NewNamingServiceClient(catalogConn),
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

// PeerClientTLS and PeerServerTLS use the live SPIRE Workload API source for
// SVIDs and federated bundles. Both authorize one exact peer service ID.
// SPIRE, not this bridge, administers federation and bundle refresh.
func (c *Clients) PeerClientTLS(expectedServerID string) (*tls.Config, error) {
	id, err := spiffeid.FromString(expectedServerID)
	if err != nil {
		return nil, fmt.Errorf("peer server SPIFFE ID: %w", err)
	}
	return tlsconfig.MTLSClientConfig(c.Workload, c.Workload, tlsconfig.AuthorizeID(id)), nil
}

func (c *Clients) PeerServerTLS(expectedClientID string) (*tls.Config, error) {
	id, err := spiffeid.FromString(expectedClientID)
	if err != nil {
		return nil, fmt.Errorf("peer client SPIFFE ID: %w", err)
	}
	return tlsconfig.MTLSServerConfig(c.Workload, c.Workload, tlsconfig.AuthorizeID(id)), nil
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

// ResolveProviderName returns every Directory candidate. Base must evaluate
// each candidate's provenance and never assume the first one is trusted.
func (c *Clients) ResolveProviderName(ctx context.Context, name, version string) (*namingv1.ResolveResponse, error) {
	if name == "" {
		return nil, errors.New("provider evidence name is required")
	}
	return c.Directory.Resolve(ctx, name, version)
}

func (c *Clients) VerificationInfoByCID(ctx context.Context, cid string) (*namingv1.GetVerificationInfoResponse, error) {
	return c.Directory.GetVerificationInfo(ctx, cid)
}

// NameEvidenceByCID returns Directory's own verification result together with
// the name in the selected record. Base still decides whether these values
// match its independently provisioned provider bootstrap and current manifest.
func (c *Clients) NameEvidenceByCID(ctx context.Context, cid, localDirectoryServiceID string) (map[string]any, error) {
	if cid == "" || localDirectoryServiceID == "" {
		return nil, errors.New("CID and local Directory service identity required")
	}
	info, err := c.VerificationInfoByCID(ctx, cid)
	if err != nil { return nil, err }
	if !info.GetVerified() { return nil, errors.New("Directory name is unverified") }
	domain := info.GetVerification().GetDomain()
	if domain == nil || domain.GetDomain() == "" || domain.GetMethod() == "" || domain.GetKeyId() == "" || domain.GetVerifiedAt() == nil {
		return nil, errors.New("Directory name evidence incomplete")
	}
	record, err := c.Pull(ctx, &corev1.RecordRef{Cid:cid})
	if err != nil { return nil, err }
	if record.GetData() == nil || record.GetData().GetFields()["name"] == nil || record.GetData().GetFields()["name"].GetStringValue() == "" {
		return nil, errors.New("Directory record name missing")
	}
	return map[string]any{
		"record_cid":cid,
		"record_name":record.GetData().GetFields()["name"].GetStringValue(),
		"verified":true,
		"domain":domain.GetDomain(),
		"method":domain.GetMethod(),
		"key_id":domain.GetKeyId(),
		"verified_at":domain.GetVerifiedAt().AsTime().UTC().Format(time.RFC3339Nano),
		"source_directory_service_id":localDirectoryServiceID,
	},nil
}
