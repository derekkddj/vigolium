package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestEvidenceSameIdentityConflictsFailClosedBeforePostHookSeal(t *testing.T) {
	for _, variant := range []string{"response", "timestamp", "destination"} {
		for _, reversed := range []bool{false, true} {
			for _, hook := range []string{"none", "identity", "reintroduce"} {
				t.Run(variant+"/"+map[bool]string{false: "attack-first", true: "control-first"}[reversed]+"/"+hook, func(t *testing.T) {
					e, db := newRepoExecutor(t)
					x := evidence.NewExchange("https://proof.test:443", "https://proof.test/attack", []byte("GET /attack HTTP/1.1\r\nHost: proof.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nattack"), evidence.ProvenanceCaptured)
					y := x.Clone()
					switch variant {
					case "response":
						y.Response = []byte("HTTP/1.1 200 OK\r\n\r\ncontrol")
					case "timestamp":
						y.CapturedAt = x.CapturedAt.Add(time.Nanosecond)
					case "destination":
						y.Service = "https://other.test:443"
					}
					y.ContentHash = y.Hash()
					require.NoError(t, x.Validate())
					require.NoError(t, y.Validate(), "self-consistency does not establish shared execution identity")
					entries := []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "attack"), evidence.Select(y, evidence.RoleControl, false, "control")}
					if reversed {
						entries[0], entries[1] = entries[1], entries[0]
					}
					if hook != "none" {
						e.hooks = evidenceReviewHook{post: func(r *output.ResultEvent) *output.ResultEvent {
							if hook == "reintroduce" {
								r.Evidence = []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "attempted reintroduction")}
							}
							return r
						}}
					}
					got := e.emitResult(context.Background(), &output.ResultEvent{ModuleID: "test", URL: x.URL, Evidence: entries}, nil, nil).event
					require.NotNil(t, got)
					require.Equal(t, "missing", got.EvidenceStatus)
					require.Empty(t, got.Request)
					require.Empty(t, got.Response)
					require.Contains(t, got.Error, "conflicting evidence capture identity")
					for _, entry := range got.Evidence {
						require.True(t, strings.HasPrefix(entry.ExchangeID, "rejected-evidence:"))
						require.Nil(t, entry.Exchange)
					}
					findings := loadFindings(t, db)
					require.Len(t, findings, 1, "keep the unavailable finding declaration, not forged bytes")
					require.Equal(t, "missing", findings[0].EvidenceStatus)
					require.Empty(t, findings[0].HTTPRecordUUIDs)
					require.NoError(t, e.repo.HydrateFindingEvidenceForExport(context.Background(), findings[0]))
					for _, entry := range findings[0].Evidence {
						require.Nil(t, entry.Exchange)
					}
					count, err := db.NewSelect().Model((*database.EvidenceExchange)(nil)).Count(context.Background())
					require.NoError(t, err)
					require.Zero(t, count, "neither conflicting variant becomes canonical authority")
				})
			}
		}
	}
}

func TestEvidenceIdenticalIdentityAllowsSupportingRole(t *testing.T) {
	for _, reversed := range []bool{false, true} {
		t.Run(map[bool]string{false: "attack-first", true: "control-first"}[reversed], func(t *testing.T) {
			e, db := newRepoExecutor(t)
			x := evidence.NewExchange("https://proof.test:443", "https://proof.test/attack", []byte("GET /attack HTTP/1.1\r\nHost: proof.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nattack"), evidence.ProvenanceCaptured)
			entries := []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "attack"), evidence.Select(x, evidence.RoleControl, false, "same capture used as support")}
			if reversed {
				entries[0], entries[1] = entries[1], entries[0]
			}
			got := e.emitResult(context.Background(), &output.ResultEvent{ModuleID: "test", URL: x.URL, Evidence: entries}, nil, nil).event
			require.Equal(t, "selected", got.EvidenceStatus)
			require.Empty(t, got.Error)
			require.Equal(t, string(x.Response), got.Response)
			f := loadFindings(t, db)[0]
			require.NoError(t, e.repo.HydrateFindingEvidenceForExport(context.Background(), f))
			require.Len(t, f.Evidence, 2)
			for _, entry := range f.Evidence {
				require.Equal(t, x, entry.Exchange)
			}
		})
	}
}

func TestEvidenceIncompleteReceiptNeverBecomesCompleteRawRecord(t *testing.T) {
	for _, state := range []evidence.State{evidence.StateTruncated, evidence.StateUnknown, evidence.StateMissing} {
		for _, side := range []string{"request", "response"} {
			t.Run(string(state)+"/"+side, func(t *testing.T) {
				e, db := newRepoExecutor(t)
				x := evidence.NewExchange("http://proof.test:8081", "http://proof.test/actual", []byte("POST /actual HTTP/1.1\r\nHost: proof.test\r\nContent-Length: 999\r\n\r\n\x00\xffshort"), []byte("HTTP/1.1 200 OK\r\n\r\n\xff\x00answer"), evidence.ProvenanceCaptured)
				if side == "request" {
					x.RequestState = state
					if state == evidence.StateMissing {
						x.Request = nil
					}
				} else {
					x.ResponseState = state
					if state == evidence.StateMissing {
						x.Response = nil
					}
				}
				x.ContentHash = x.Hash()
				got := e.emitResult(context.Background(), &output.ResultEvent{ModuleID: "test", URL: "https://assertion.test/vuln", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "partial actual proof")}}, nil, nil).event
				require.NotNil(t, got)
				f := loadFindings(t, db)[0]
				require.Empty(t, f.HTTPRecordUUIDs, "raw records cannot express this capture boundary")
				count, err := db.NewSelect().Model((*database.HTTPRecord)(nil)).Count(context.Background())
				require.NoError(t, err)
				require.Zero(t, count, "no record can be reloaded and promoted to complete supplied traffic")
				require.NoError(t, e.repo.HydrateFindingEvidenceForExport(context.Background(), f))
				require.Len(t, f.Evidence, 1)
				require.Equal(t, x, f.Evidence[0].Exchange, "canonical bytes and explicit fidelity stay available")
				rr, err := resultEvidenceMessages(got, nil)
				require.Error(t, err)
				require.Nil(t, rr)
			})
		}
	}
}
