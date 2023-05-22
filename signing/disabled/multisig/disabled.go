package multisig

const signature = "signature"

// DisabledMultiSig represents a disabled multisigner implementation
type DisabledMultiSig struct {
}

// CreateSignatureShare returns the default signature as this is a disabled component
func (dms *DisabledMultiSig) CreateSignatureShare(_ []byte, _ []byte) ([]byte, error) {
	return []byte(signature), nil
}

// VerifySignatureShare returns nil as this is a disabled component
func (dms *DisabledMultiSig) VerifySignatureShare(_ []byte, _ []byte, _ []byte) error {
	return nil
}

// AggregateSigs returns a dummy signature, as this is a disabled component
func (dms *DisabledMultiSig) AggregateSigs(_ [][]byte, _ [][]byte) ([]byte, error) {
	return []byte(signature), nil
}

// VerifyAggregatedSig returns nil as this is a disabled component
func (dms *DisabledMultiSig) VerifyAggregatedSig(_ [][]byte, _ []byte, _ []byte) error {
	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (dms *DisabledMultiSig) IsInterfaceNil() bool {
	return dms == nil
}
