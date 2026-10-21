package terms

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type vector struct {
	RequestCanonical   string `json:"request_canonical"`
	RequestSHA256      string `json:"request_sha256"`
	EffectiveCanonical string `json:"effective_canonical"`
	EffectiveSHA256    string `json:"effective_sha256"`
}

func TestRustGoCanonicalTermsVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "terms-v1", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ name, canonical, digest string }{
		{"request", v.RequestCanonical, v.RequestSHA256},
		{"effective", v.EffectiveCanonical, v.EffectiveSHA256},
	} {
		actual, err := jsoncanonicalizer.Transform([]byte(entry.canonical))
		if err != nil {
			t.Fatalf("%s: %v", entry.name, err)
		}
		if string(actual) != entry.canonical {
			t.Fatalf("%s canonical bytes differ", entry.name)
		}
		sum := sha256.Sum256(actual)
		if hex.EncodeToString(sum[:]) != entry.digest {
			t.Fatalf("%s SHA-256 differs", entry.name)
		}
	}
	for _, internal := range []string{"subject_id", "resource_id", "account", "\"agent_id"} {
		if strings.Contains(v.RequestCanonical, internal) || strings.Contains(v.EffectiveCanonical, internal) {
			t.Fatalf("terms carry an internal identifier field %q", internal)
		}
	}
	if v.RequestSHA256 == v.EffectiveSHA256 {
		t.Fatal("request and narrowed lease digest are equal")
	}
	changed := strings.Replace(v.EffectiveCanonical, `"expires_at":4700`, `"expires_at":4701`, 1)
	if changed == v.EffectiveCanonical {
		t.Fatal("expiry vector replacement failed")
	}
	canonical, err := jsoncanonicalizer.Transform([]byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) == v.EffectiveSHA256 {
		t.Fatal("altered effective terms kept the digest")
	}
}
