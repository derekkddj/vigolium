package cli

import (
	"encoding/json"
	"fmt"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// ResultEvent's severity/confidence enums marshal as names but do not implement
// UnmarshalJSON. Accept those public JSONL names as well as the legacy numeric
// enums here, without changing the event schema or reinterpreting its receipts.
func unmarshalFindingResultEvent(data []byte, event *output.ResultEvent) error {
	type eventAlias output.ResultEvent
	type infoAlias output.Info
	var wire struct {
		*eventAlias
		Info struct {
			*infoAlias
			Severity   json.RawMessage `json:"severity"`
			Confidence json.RawMessage `json:"confidence"`
		} `json:"info"`
	}
	wire.eventAlias = (*eventAlias)(event)
	wire.Info.infoAlias = (*infoAlias)(&event.Info)
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if len(wire.Info.Severity) > 0 {
		var name string
		if err := json.Unmarshal(wire.Info.Severity, &name); err == nil {
			event.Info.Severity = severity.ToSeverity(name)
			if name != "" && event.Info.Severity == severity.Undefined {
				return fmt.Errorf("invalid ResultEvent severity: %q", name)
			}
		} else if err := json.Unmarshal(wire.Info.Severity, &event.Info.Severity); err != nil {
			return fmt.Errorf("invalid ResultEvent severity: %w", err)
		}
	}
	if len(wire.Info.Confidence) > 0 {
		var name string
		if err := json.Unmarshal(wire.Info.Confidence, &name); err == nil {
			event.Info.Confidence = severity.ToConfidence(name)
			if name != "" && event.Info.Confidence == severity.ConfidenceUndefined {
				return fmt.Errorf("invalid ResultEvent confidence: %q", name)
			}
		} else if err := json.Unmarshal(wire.Info.Confidence, &event.Info.Confidence); err != nil {
			return fmt.Errorf("invalid ResultEvent confidence: %w", err)
		}
	}
	return nil
}
