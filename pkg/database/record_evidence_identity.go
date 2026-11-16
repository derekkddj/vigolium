package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ErrImmutableRecordExchange rejects legacy APIs that would change what an
// existing UUID identifies. SaveRecordVersion returns a new/exact-version UUID.
var ErrImmutableRecordExchange = errors.New("stored HTTP exchanges are immutable")

// recordExchangeColumns loads only identity and raw bytes, never enrichment or
// evidence JSON. Used for exact candidates and writer cache validation.
var recordExchangeIdentityColumns = append([]string{
	"uuid", "project_uuid", "method", "hostname", "path", "url", "scheme", "port",
	"request_hash", "response_hash", "has_response",
}, recordCaptureStateColumns...)
var recordExchangeColumns = append(append([]string(nil), recordExchangeIdentityColumns...),
	"raw_request", "raw_response", "body_compaction")

func rawRecordHash(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

// The destination is the service, not an authority an absolute-form request
// might name in its raw bytes. Full conversion already hashes the response;
// writer admission needs both halves before its cache lookup.
func prepareRecordServiceIdentity(record *HTTPRecord, rr *httpmsg.HttpRequestResponse) {
	if service := rr.Service(); service != nil {
		record.Scheme = service.Protocol()
		record.Hostname = service.Host()
		record.Port = service.Port()
	}
}

func prepareRecordExchangeIdentity(record *HTTPRecord, rr *httpmsg.HttpRequestResponse) {
	prepareRecordServiceIdentity(record, rr)
	record.HasResponse = rr.HasResponse()
	record.ResponseHash = ""
	if rr.HasResponse() {
		record.ResponseHash = rawRecordHash(rr.Response().Raw())
	}
}

// recordExchangeBytesValid rejects truncated or stale legacy rows. Hashes alone
// are insufficient: compaction deliberately retains original hashes, and older
// mutation paths may have left identity metadata describing different bytes.
// No HTTP parser is used here, so malformed or unusual wire bytes stay exact.
func recordExchangeBytesValid(record *HTTPRecord) bool {
	if record == nil || record.ValidateCaptureStates() != nil || record.BodyCompaction != nil || record.RequestHash != rawRecordHash(record.RawRequest) {
		return false
	}
	if !record.HasResponse {
		return len(record.RawResponse) == 0 && record.ResponseHash == ""
	}
	// Reload represents a response only when message bytes exist, including
	// legacy candidates. An empty object's hash must never establish presence.
	return len(record.RawResponse) != 0 && record.ResponseHash == rawRecordHash(record.RawResponse)
}

// validRecordCandidates hydrates at most one row per requested identity per
// pass. Overlapping imports may have many UUIDs for the same exchange; loading
// every candidate body at once would make a small writer batch retain a corpus.
// Stale candidates are skipped without modifying them, trying another UUID only
// when necessary. Metadata and enrichment JSON are never loaded.
func (r *Repository) validRecordCandidates(ctx context.Context, rows []*HTTPRecord) (map[string]string, error) {
	remaining := make(map[string][]string, len(rows))
	for _, row := range rows {
		key := recordDedupKey(row)
		remaining[key] = append(remaining[key], row.UUID)
	}
	valid := make(map[string]string, len(remaining))
	for len(remaining) > 0 {
		ids := make([]string, 0, len(remaining))
		expected := make(map[string]string, len(remaining))
		for key, candidates := range remaining {
			id := candidates[0]
			ids = append(ids, id)
			expected[id] = key
			if len(candidates) == 1 {
				delete(remaining, key)
			} else {
				remaining[key] = candidates[1:]
			}
		}
		records, err := r.getRecordsByUUIDs(ctx, ids, recordExchangeColumns...)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			key := expected[record.UUID]
			if recordExchangeBytesValid(record) && recordDedupKey(record) == key {
				valid[key] = record.UUID
				delete(remaining, key)
			}
		}
	}
	return valid, nil
}

// cachedRecordMatches verifies the actual row before a writer returns a cached
// UUID. Cache residency cannot hide deletion, legacy response mutation, or body
// compaction. A miss falls through to the batched exact lookup/insert; a read
// error fails the call rather than returning an unverified historical UUID.
func (r *Repository) cachedRecordMatches(ctx context.Context, id, key string) (bool, error) {
	records, err := r.getRecordsByUUIDs(ctx, []string{id}, recordExchangeColumns...)
	if err != nil {
		return false, err
	}
	return len(records) == 1 && recordExchangeBytesValid(records[0]) && recordDedupKey(records[0]) == key, nil
}

// SaveRecordVersion stores the complete observed exchange in the old record's
// project, preserving the old row and its references. Callers must adopt the
// returned UUID, which may reuse an existing EXACT exchange. In particular a
// fetched request must never donate only its response to a different request.
func (r *Repository) SaveRecordVersion(ctx context.Context, previousUUID string, rr *httpmsg.HttpRequestResponse) (string, error) {
	previous, err := r.GetRecordByUUID(ctx, previousUUID)
	if err != nil {
		return "", fmt.Errorf("load record version source: %w", err)
	}
	root := previous.RootUUID
	if root == previous.UUID {
		root = "" // a standalone version roots itself, not the old standalone row
	}
	return r.SaveRecordWithLineage(ctx, rr, previous.Source, previous.ProjectUUID, RecordLineage{
		ParentUUID: previous.ParentUUID, RootUUID: root, Target: previous.Target,
		ChainTruncated: previous.ChainTruncated, Remarks: previous.Remarks,
	})
}
