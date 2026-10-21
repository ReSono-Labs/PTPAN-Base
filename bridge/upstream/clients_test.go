package upstream

import (
	"context"
	"strings"
	"testing"

	directory "github.com/agntcy/dir/client"
)

func TestOpenRejectsDirectoryInsecureModesBeforeDial(t *testing.T) {
	for _, mode := range []string{"", "insecure", "none", "tls"} {
		t.Run(mode, func(t *testing.T) {
			_, err := Open(context.Background(), Config{
				Directory:     directory.Config{ServerAddress: "directory.invalid:443", AuthMode: mode},
				OASFSchemaURL: "https://oasf.invalid",
			})
			if err == nil || !strings.Contains(err.Error(), "requires SPIRE x509") {
				t.Fatalf("mode %q was not rejected before dial: %v", mode, err)
			}
		})
	}
}

func TestOpenRejectsMissingWorkloadSocket(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	_, err := Open(context.Background(), Config{
		Directory:     directory.Config{ServerAddress: "directory.invalid:443", AuthMode: "x509"},
		OASFSchemaURL: "https://oasf.invalid",
	})
	if err == nil || !strings.Contains(err.Error(), "explicit SPIFFE") {
		t.Fatalf("missing Workload API socket was not rejected: %v", err)
	}
}
