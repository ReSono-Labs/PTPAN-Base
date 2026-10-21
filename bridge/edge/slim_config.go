package edge

// SLIMConfig is the configuration a SLIM agent transport needs. It is parsed
// in every build so a configuration naming SLIM fails clearly when SLIM is
// off.
type SLIMConfig struct {
	// Endpoint of this platform's SLIM node.
	NodeEndpoint string
	// SLIM name components of this platform's edge: organization/namespace.
	Organization string
	Namespace    string
}
