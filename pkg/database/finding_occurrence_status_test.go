package database

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestOccurrenceEvidenceStatus(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []evidence.Entry
		want    string
	}{
		{
			name:    "one selected attack primary",
			entries: []evidence.Entry{{ExchangeID: "exchange-a", Role: evidence.RoleAttack, Primary: true}},
			want:    "selected",
		},
		{
			name:    "one unclassified primary",
			entries: []evidence.Entry{{ExchangeID: "exchange-a", Role: evidence.RoleControl, Primary: true}},
			want:    "unclassified",
		},
		{
			name:    "no primary",
			entries: []evidence.Entry{{ExchangeID: "exchange-a", Role: evidence.RoleAttack}},
			want:    "missing",
		},
		{
			name:    "primary has no exchange identity",
			entries: []evidence.Entry{{Role: evidence.RoleAttack, Primary: true}},
			want:    "missing",
		},
		{
			name: "ambiguous primaries",
			entries: []evidence.Entry{
				{ExchangeID: "exchange-a", Role: evidence.RoleAttack, Primary: true},
				{ExchangeID: "exchange-b", Role: evidence.RoleConfirmation, Primary: true},
			},
			want: "missing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := occurrenceEvidenceStatus(tc.entries); got != tc.want {
				t.Fatalf("occurrenceEvidenceStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}
