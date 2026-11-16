package diffscan

// recordConfirmation is called only at verify's explicit reproduction operations.
// Baseline stabilization merges never enter this list.
func (s *Attack) recordConfirmation(operation *Attack) {
	if s == nil || operation == nil || operation.FirstSnapshot == nil || operation.FirstSnapshot.Exchange == nil || len(s.ConfirmationReceipts) >= 10 {
		return
	}
	s.ConfirmationReceipts = append(s.ConfirmationReceipts, operation.FirstSnapshot.Exchange.Clone())
}
