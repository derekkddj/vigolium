package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/authsession"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"

	"go.uber.org/zap"
)

// probeRecords sends HTTP requests for records that don't have responses,
// enriching them with live response data. This ensures records saved to the
// database have response bodies, status codes, and headers for the scanner
// modules to analyze. Records are probed concurrently with a bounded worker pool.
// validateProbeAndSave filters records with valid URLs, injects auth headers,
// probes them for live responses, and saves them to the database.
// Records that fail the first probe are retried once.
// Notes and previousUUIDs are aligned 1:1 with records. Returned UUIDs have the
// same alignment, with an empty slot on invalid input, incomplete probe or save
// failure. Probed exchanges replace caller slots, not historical request objects.
func (s *SwarmRunner) validateProbeAndSave(ctx context.Context, records []*httpmsg.HttpRequestResponse, notes []string, previousUUIDs []string, authHeaders map[string]string, source, projectUUID string, pc ProbeConfig) []string {
	if len(records) == 0 {
		return nil
	}

	savedUUIDs := make([]string, len(records))
	var valid []*httpmsg.HttpRequestResponse
	var validNotes []string
	var validIndices []int
	for i, rr := range records {
		if rr == nil || rr.Request() == nil {
			continue
		}
		if u, urlErr := rr.URL(); urlErr != nil || u == nil || u.Host == "" {
			zap.L().Debug("Skipping record with invalid URL", zap.String("source", source), zap.Error(urlErr))
			continue
		}
		valid = append(valid, rr)
		validIndices = append(validIndices, i)
		if i < len(notes) {
			validNotes = append(validNotes, notes[i])
		} else {
			validNotes = append(validNotes, "")
		}
	}

	refreshProbeAuth(valid, authHeaders)
	if len(valid) > 0 {
		probeRecordsWithConfig(ctx, valid, pc)

		// Retry probe for records that still have no response (transient failures).
		var unprobed []int
		for i, rr := range valid {
			if !rr.HasResponse() {
				unprobed = append(unprobed, i)
			}
		}
		if len(unprobed) > 0 {
			zap.L().Info("Retrying probe for records with no response",
				zap.Int("count", len(unprobed)))
			retry := make([]*httpmsg.HttpRequestResponse, len(unprobed))
			for j, idx := range unprobed {
				retry[j] = valid[idx]
			}
			probeRecordsWithConfig(ctx, retry, pc)
			for j, idx := range unprobed {
				valid[idx] = retry[j]
			}
		}
	}
	// Probing/injection may replace objects in valid. Publish those exact
	// exchanges back to the original slots before any downstream status/scan use.
	for i, idx := range validIndices {
		records[idx] = valid[i]
	}
	if s.repo != nil && len(valid) > 0 {
		var savedCount int
		remarksMap := make(map[string][]string)
		for i, rr := range valid {
			// Failed probes leave their request-only seed in the slot. Keep it
			// available for retry, but never publish it as a saved success/version.
			// Already observed legacy pairs remain eligible; explicit incomplete
			// receipts cannot be promoted to complete records by this save loop.
			if rr == nil || !rr.HasResponse() {
				continue
			}
			if x := rr.Evidence(); x != nil && (x.RequestState != evidence.StateComplete || x.ResponseState != evidence.StateComplete) {
				continue
			}
			idx := validIndices[i]
			var savedUUID string
			var saveErr error
			if idx < len(previousUUIDs) && previousUUIDs[idx] != "" {
				savedUUID, saveErr = s.repo.SaveRecordVersion(ctx, previousUUIDs[idx], rr)
			} else {
				savedUUID, saveErr = s.repo.SaveRecord(ctx, rr, source, projectUUID)
			}
			if saveErr != nil {
				zap.L().Debug("Failed to save record", zap.String("source", source), zap.Error(saveErr))
			} else {
				savedCount++
				savedUUIDs[idx] = savedUUID
				if i < len(validNotes) && validNotes[i] != "" && savedUUID != "" {
					remarksMap[savedUUID] = []string{validNotes[i]}
				}
			}
		}
		if savedCount > 0 {
			zap.L().Info("Saved records to database", zap.String("source", source), zap.Int("count", savedCount))
		}
		if len(remarksMap) > 0 {
			if err := s.repo.AppendRemarks(ctx, remarksMap); err != nil {
				zap.L().Warn("Failed to append remarks from agent notes", zap.Error(err))
			}
		}
	}
	return savedUUIDs
}

// swarmRecordUUIDsAfterProbe retains seed identities for fallback adoption when
// a probe/save fails. These current UUIDs are not the success-only probe result.
func swarmRecordUUIDsAfterProbe(previousUUIDs, savedUUIDs []string) []string {
	currentUUIDs := make([]string, max(len(previousUUIDs), len(savedUUIDs)))
	copy(currentUUIDs, previousUUIDs)
	for i, savedUUID := range savedUUIDs {
		if savedUUID != "" {
			currentUUIDs[i] = savedUUID
		}
	}
	return currentUUIDs
}

// refreshProbeAuth preserves already observed pairs when prepared bytes match.
// Changing a request invalidates its response and receipt until a fresh probe
// captures both halves; it never donates the old response to the new request.
func refreshProbeAuth(records []*httpmsg.HttpRequestResponse, authHeaders map[string]string) {
	if len(authHeaders) == 0 {
		return
	}
	prepared := make([]*httpmsg.HttpRequestResponse, len(records))
	for i, rr := range records {
		prepared[i] = rr.Clone()
	}
	authsession.ReplaceAuthHeadersInHTTPRR(prepared, authHeaders)
	injectAuthHeaders(prepared, authHeaders)
	for i, rr := range prepared {
		if !bytes.Equal(records[i].Request().Raw(), rr.Request().Raw()) {
			records[i] = rr.WithResponse(nil)
		}
	}
}

// ProbeConfig holds tuning parameters for HTTP record probing.
type ProbeConfig struct {
	Concurrency int                        // max parallel probe requests; 0 = default 10
	Timeout     time.Duration              // per-request probe timeout; 0 = default 10s
	MaxBodySize int                        // max response body bytes; 0 = default 2MB
	OnProgress  func(completed, total int) // optional progress callback
}

func (pc ProbeConfig) effectiveConcurrency() int {
	if pc.Concurrency <= 0 {
		return 10
	}
	return pc.Concurrency
}

func (pc ProbeConfig) effectiveTimeout() time.Duration {
	if pc.Timeout <= 0 {
		return 10 * time.Second
	}
	return pc.Timeout
}

func (pc ProbeConfig) effectiveMaxBodySize() int {
	if pc.MaxBodySize <= 0 {
		return 2 * 1024 * 1024
	}
	return pc.MaxBodySize
}

func probeRecordsWithConfig(ctx context.Context, records []*httpmsg.HttpRequestResponse, pc ProbeConfig) {
	maxConcurrency := pc.effectiveConcurrency()
	probeTimeout := pc.effectiveTimeout()
	maxBody := pc.effectiveMaxBodySize()

	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Don't follow redirects — capture the redirect response itself
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	// Count probeable records for progress reporting
	var probeable int
	for _, rr := range records {
		if !rr.HasResponse() && rr.Request() != nil && rr.Target() != "" {
			probeable++
		}
	}

	var completed atomic.Int64 // atomic counter for progress
	for i, rr := range records {
		if rr.HasResponse() {
			continue
		}
		if rr.Request() == nil {
			continue
		}
		targetURL := rr.Target()
		if targetURL == "" {
			continue
		}

		wg.Add(1)
		idx := i
		go func(rec *httpmsg.HttpRequestResponse, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			probed := probeSingleRecordWithLimit(ctx, client, rec, target, maxBody)
			if probed != nil {
				records[idx] = probed
			}
			done := int(completed.Add(1))
			if pc.OnProgress != nil {
				pc.OnProgress(done, probeable)
			}
		}(rr, targetURL)
	}

	wg.Wait()
}

// probeSingleRecordWithLimit sends an HTTP request with a configurable body size limit.
func probeSingleRecordWithLimit(ctx context.Context, client *http.Client, rr *httpmsg.HttpRequestResponse, targetURL string, maxBody int) *httpmsg.HttpRequestResponse {
	method := "GET"
	if rr.Request() != nil {
		method = rr.Request().Method()
	}

	var bodyReader io.Reader
	if rr.Request() != nil && len(rr.Request().Body()) > 0 {
		bodyReader = bytes.NewReader(rr.Request().Body())
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		zap.L().Debug("Failed to build probe request", zap.String("url", targetURL), zap.Error(err))
		return nil
	}

	// Copy headers from the original request
	if rr.Request() != nil {
		for _, h := range rr.Request().Headers() {
			if strings.EqualFold(h.Name, "Host") {
				httpReq.Host = h.Value
			} else {
				httpReq.Header.Add(h.Name, h.Value)
			}
		}
	}

	start := time.Now()
	chain, err := vhttp.DoCaptured(client, httpReq, int64(maxBody))
	if chain != nil {
		defer chain.Close()
	}
	// A partial error chain is not a successful probed record. Do not adopt
	// it or donate its response to the intended request/historical exchange.
	if err != nil {
		zap.L().Warn("Probe exchange capture failed", zap.String("url", targetURL), zap.Error(err))
		return nil
	}
	x := vhttp.CaptureEvidence(chain)
	if x == nil || x.RequestState != evidence.StateComplete || x.ResponseState != evidence.StateComplete {
		zap.L().Warn("Probe has no complete captured exchange", zap.String("url", targetURL))
		return nil
	}
	sent, err := httpmsg.FromEvidenceExchange(x)
	if err != nil {
		zap.L().Warn("Invalid probe capture", zap.String("url", targetURL), zap.Error(err))
		return nil
	}
	// Include the full body read in transaction duration. The captured request
	// (including redirect method/body changes and transport headers) is adopted,
	// not the intended rr paired with a response from a different exchange.
	return sent.WithResponse(httpmsg.NewHttpResponseWithDuration(x.Response, time.Since(start))).WithEvidence(x)
}

// reprobeUnprobedRecords queries records without responses from the DB and
// probes them using a simple HTTP client. This acts as a fallback for records
// that earlier probes failed to fetch.
func (s *SwarmRunner) reprobeUnprobedRecords(ctx context.Context, projectUUID, hostname string, authHeaders map[string]string, source string, records []*httpmsg.HttpRequestResponse, recordUUIDs []string) (map[string]string, error) {
	versions, captures, probeErr := reprobeObservedRecordVersions(ctx, s.repo, projectUUID, hostname, authHeaders, source)
	adoptErr := adoptSwarmRecordVersions(ctx, s.repo, projectUUID, records, recordUUIDs, versions, captures)
	return versions, errors.Join(probeErr, adoptErr)
}

// adoptSwarmRecordVersions updates current slots and UUIDs together, leaving
// unmapped/failed slots alone. Never rewrite old stored rows or finding links.
func adoptSwarmRecordVersions(ctx context.Context, repo *database.Repository, projectUUID string, records []*httpmsg.HttpRequestResponse, recordUUIDs []string, versions map[string]string, captures ...map[string]*httpmsg.HttpRequestResponse) error {
	var failures []error
	for i, oldUUID := range recordUUIDs {
		versionUUID, ok := versions[oldUUID]
		if !ok || i >= len(records) {
			continue
		}
		var captured []*httpmsg.HttpRequestResponse
		if len(captures) > 0 {
			captured = append(captured, captures[0][oldUUID])
		}
		observed, err := loadObservedRecordVersion(ctx, repo, projectUUID, versionUUID, captured...)
		if err != nil {
			failures = append(failures, fmt.Errorf("adopt %s: %w", oldUUID, err))
			continue
		}
		records[i] = observed
		recordUUIDs[i] = versionUUID
	}
	return errors.Join(failures...)
}
