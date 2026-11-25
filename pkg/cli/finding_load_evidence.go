package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
)

// parseFindingBundle handles the machine/export wrappers before permissive agent
// parsers can discard association roles or base64 raw receipt fields.
func parseFindingBundle(raw, scanUUID, projectUUID string) ([]*database.Finding, string, bool, error) {
	parse := func(data json.RawMessage) ([]*database.Finding, error) {
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(data, &keys); err != nil {
			return nil, err
		}
		if _, ok := keys["template-id"]; ok {
			f, err := tryParseSingleResultEvent(string(data), scanUUID, projectUUID)
			if err != nil {
				return nil, err
			}
			return []*database.Finding{f}, nil
		}
		findings, err := tryParseDBFindings(string(data), projectUUID)
		for _, f := range findings {
			rehomeLoadedFinding(f, scanUUID, projectUUID)
		}
		return findings, err
	}
	var document struct {
		Items []json.RawMessage `json:"items"`
		Type  string            `json:"type"`
		Data  json.RawMessage   `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &document); err == nil && document.Items != nil {
		var findings []*database.Finding
		for _, item := range document.Items {
			parsed, err := parse(item)
			if err != nil {
				return nil, "finding-json", true, err
			}
			findings = append(findings, parsed...)
		}
		return findings, "finding-json", true, nil
	}
	var findings []*database.Finding
	recognized := false
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var envelope struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil || envelope.Type == "" || envelope.Data == nil {
			if recognized {
				return nil, "export-jsonl", true, fmt.Errorf("invalid export envelope")
			}
			break
		}
		recognized = true
		if envelope.Type != "finding" {
			continue
		}
		parsed, err := parse(envelope.Data)
		if err != nil {
			return nil, "export-jsonl", true, err
		}
		findings = append(findings, parsed...)
	}
	if recognized {
		return findings, "export-jsonl", true, nil
	}
	// A pretty-printed single export envelope occupies multiple lines.
	if document.Type == "finding" && document.Data != nil {
		findings, err := parse(document.Data)
		return findings, "export-jsonl", true, err
	}
	return nil, "", false, nil
}
