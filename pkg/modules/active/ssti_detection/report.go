package ssti_detection

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
)

// attackPair represents a break/escape attack pair for reporting.
type attackPair struct {
	ProbeName     string
	BreakPayload  string
	BreakStatus   int
	BreakLength   int
	EscapePayload string
	EscapeStatus  int
	EscapeLength  int
	// DiffSignal lists the response-fingerprint attribute(s) that actually
	// differed between the break and escape responses — i.e. the evidence the
	// detection fired on. Surfacing it lets a triager see why the finding was
	// raised even when the visible columns (status, length) look identical.
	DiffSignal string
}

// generateMarkdownReport creates a markdown table report from attack results.
func generateMarkdownReport(attacks []*diffscan.Attack, paramName string) string {
	if len(attacks) == 0 {
		return ""
	}

	pairs := extractAttackPairs(attacks)
	if len(pairs) == 0 {
		return ""
	}

	var sb strings.Builder

	// Header
	fmt.Fprintf(&sb, "## SSTI Detection - %s\n\n", paramName)

	// Group by probe name
	probeGroups := groupByProbeName(pairs)

	for probeName, groupedPairs := range probeGroups {
		fmt.Fprintf(&sb, "### %s\n\n", probeName)
		sb.WriteString("| Type | Payload | Status | Content Length | Diff Signal |\n")
		sb.WriteString("|------|---------|--------|----------------|-------------|\n")

		for i, pair := range groupedPairs {
			signal := pair.DiffSignal
			if signal == "" {
				signal = "—"
			}
			// Break row
			fmt.Fprintf(&sb,
				"| break %d | `%s` | %d | %d | %s |\n",
				i+1,
				escapeMarkdown(pair.BreakPayload),
				pair.BreakStatus,
				pair.BreakLength,
				signal,
			)
			// Escape row
			fmt.Fprintf(&sb,
				"| escape %d | `%s` | %d | %d | %s |\n",
				i+1,
				escapeMarkdown(pair.EscapePayload),
				pair.EscapeStatus,
				pair.EscapeLength,
				signal,
			)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// extractAttackPairs converts attack list to pairs (break, escape).
func extractAttackPairs(attacks []*diffscan.Attack) []attackPair {
	var pairs []attackPair

	for i := 0; i < len(attacks); i += 2 {
		breakAttack := attacks[i]
		if i+1 >= len(attacks) {
			break
		}
		escapeAttack := attacks[i+1]

		if breakAttack == nil || escapeAttack == nil {
			continue
		}

		// Skip WAF-blocked attacks
		if breakAttack.FirstSnapshot != nil && breakAttack.FirstSnapshot.WafBlocked() {
			continue
		}
		if escapeAttack.FirstSnapshot != nil && escapeAttack.FirstSnapshot.WafBlocked() {
			continue
		}

		pair := attackPair{
			ProbeName:     breakAttack.Probe.Name,
			BreakPayload:  breakAttack.Payload,
			EscapePayload: escapeAttack.Payload,
		}

		if breakAttack.FirstSnapshot != nil {
			if breakAttack.FirstSnapshot.Payload != "" {
				pair.BreakPayload = breakAttack.FirstSnapshot.Payload
			}
			pair.BreakStatus = breakAttack.FirstSnapshot.StatusCode
			pair.BreakLength = breakAttack.FirstSnapshot.ContentLength
		}
		if escapeAttack.FirstSnapshot != nil {
			if escapeAttack.FirstSnapshot.Payload != "" {
				pair.EscapePayload = escapeAttack.FirstSnapshot.Payload
			}
			pair.EscapeStatus = escapeAttack.FirstSnapshot.StatusCode
			pair.EscapeLength = escapeAttack.FirstSnapshot.ContentLength
		}
		pair.DiffSignal = diffSignal(breakAttack, escapeAttack)

		pairs = append(pairs, pair)
	}

	return pairs
}

// diffSignal returns a sorted, comma-joined list of the response-fingerprint
// attributes that differed between the break and escape responses. This is the
// concrete evidence the detection fired on (e.g. "status_code, whole_body_content").
//
// It compares the merged (stable) fingerprints rather than the last single
// sample, so the reported signal is the one that actually survived every
// confirmation and drove the decision — not a transient last-request artifact
// (e.g. a header that only jittered on the final probe).
func diffSignal(breakAttack, escapeAttack *diffscan.Attack) string {
	keys := diffscan.GetMergedNonMatchingFingerprints(breakAttack, escapeAttack)
	if len(keys) == 0 {
		return ""
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// selectAttackEvidence keeps bounded, whole reported break/control pairs and
// their final confirmations, not intermediate scan traffic. A caller may reserve
// supporting slots for its deciding guards. The first selected break stays the
// primary; the baseline is reserved but can never stand in for a missing control.
func selectAttackEvidence(attacks []*diffscan.Attack, baseline *diffscan.Attack, budgets ...int) []evidence.Entry {
	budget := modkit.MaxEvidencePairs
	if len(budgets) > 0 {
		budget = max(0, min(budget, budgets[0]))
	}
	var baselineEntry []evidence.Entry
	if baseline != nil && baseline.FirstSnapshot != nil && baseline.FirstSnapshot.Exchange != nil && budget > 0 {
		baselineEntry = append(baselineEntry, evidence.Select(baseline.FirstSnapshot.Exchange, evidence.RoleBaseline, false, "soft baseline"))
		budget--
	}
	var entries []evidence.Entry
	primarySelected := false
	contextCount := 0
	for i := 0; i+1 < len(attacks); i += 2 {
		attack, control := attacks[i], attacks[i+1]
		if attack == nil || control == nil {
			continue
		}
		if attack.FirstSnapshot != nil && attack.FirstSnapshot.WafBlocked() {
			continue
		}
		if control.FirstSnapshot != nil && control.FirstSnapshot.WafBlocked() {
			continue
		}
		// Sparse earlier pairs must not consume the slots needed by the same
		// first available break that the producer selected before bounding.
		if !primarySelected && (attack.FirstSnapshot == nil || attack.FirstSnapshot.Exchange == nil) {
			continue
		}
		name := "probe"
		if attack.Probe != nil {
			name = attack.Probe.Name
		}
		var pair []evidence.Entry
		pairHasPrimary := false
		for index, probe := range []*diffscan.Attack{attack, control} {
			role, label := evidence.RoleAttack, name+" break"
			if index == 1 {
				role, label = evidence.RoleControl, name+" escape"
			}
			if first := probe.FirstSnapshot; first != nil && first.Exchange != nil {
				primary := index == 0 && !primarySelected
				pair = append(pair, evidence.Select(first.Exchange, role, primary, label))
				pairHasPrimary = pairHasPrimary || primary
			}
			if last := probe.LastSnapshot; last != nil && last.Exchange != nil && last != probe.FirstSnapshot {
				pair = append(pair, evidence.Select(last.Exchange, evidence.RoleConfirmation, false, label+" final confirmation"))
			}
		}
		pairContext := len(pair)
		if pairHasPrimary {
			pairContext--
		}
		if contextCount+pairContext > budget {
			continue
		}
		entries = append(entries, pair...)
		contextCount += pairContext
		primarySelected = primarySelected || pairHasPrimary
	}
	return append(entries, baselineEntry...)
}

// groupByProbeName groups attack pairs by probe name.
func groupByProbeName(pairs []attackPair) map[string][]attackPair {
	groups := make(map[string][]attackPair)
	for _, pair := range pairs {
		groups[pair.ProbeName] = append(groups[pair.ProbeName], pair)
	}
	return groups
}

// escapeMarkdown escapes markdown special characters.
func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "`", "\\`")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}
