package diffscan

type Option struct {
	// CaptureEvidence owns only snapshots in the current probe/selected attacks.
	// Opt-in avoids retaining full bodies for diffscan consumers that don't report receipts.
	CaptureEvidence           bool
	Confirmations             int
	QuantitativeConfirmations int
	QuantileFactor            int
	QuantitativeDiffKeys      []string
	// CustomCanary is prepended to canaryKeys for response fingerprinting.
	CustomCanary string
}

func NewOption() *Option {
	return &Option{
		Confirmations:             5,
		QuantitativeConfirmations: 50,
		QuantileFactor:            5,
		QuantitativeDiffKeys:      []string{},
	}
}
