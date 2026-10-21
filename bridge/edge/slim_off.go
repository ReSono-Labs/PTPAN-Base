//go:build !slim

package edge

// NewSLIMTransport is unavailable in the default build: the SLIM bindings
// need cgo and a native library, and SLIM between independent operators is
// not decided yet (review 16.8).
func NewSLIMTransport(SLIMConfig) (AgentTransport, error) { return nil, ErrSLIMNotBuilt }
