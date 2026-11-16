package database

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Shared by candidate hydration, scan projections and SQL dedup partitions.
// NULL and empty are equivalent only to each other, never to a known unknown.
var recordCaptureStateColumns = []string{"capture_request_state", "capture_response_state"}

func recordCaptureStateSQL() string {
	parts := make([]string, len(recordCaptureStateColumns))
	for i, column := range recordCaptureStateColumns {
		parts[i] = "COALESCE(" + column + ", '')"
	}
	return strings.Join(parts, ", ")
}

func (r *HTTPRecord) hasCaptureStates() bool {
	return r.CaptureRequestState != "" || r.CaptureResponseState != ""
}

// An absent half of otherwise known metadata is unknown, not complete even if
// its bytes are nonempty. Entirely absent metadata retains legacy behavior.
func (r *HTTPRecord) captureStates() (evidence.State, evidence.State) {
	request, response := r.CaptureRequestState, r.CaptureResponseState
	if request == "" {
		request = evidence.StateUnknown
	}
	if response == "" {
		response = evidence.StateUnknown
	}
	return request, response
}

// ValidateCaptureStates validates the closed evidence vocabulary and byte/state
// consistency using evidence's canonical validator. Used by model-level imports
// too: arbitrary row JSON must not infer a receipt from raw bytes.
func (r *HTTPRecord) ValidateCaptureStates() error {
	if r == nil {
		return fmt.Errorf("nil HTTP record")
	}
	if !r.hasCaptureStates() {
		return nil
	}
	request, response := r.captureStates()
	x := &evidence.Exchange{ID: "raw-record-fidelity", Request: r.RawRequest, Response: r.RawResponse,
		RequestState: request, ResponseState: response, Provenance: evidence.ProvenanceSupplied,
		CapturedAt: time.Unix(0, 0).UTC()}
	x.ContentHash = x.Hash()
	if err := x.Validate(); err != nil {
		return fmt.Errorf("invalid raw-record capture fidelity: %w", err)
	}
	if r.HasResponse != (len(r.RawResponse) != 0) {
		return fmt.Errorf("raw-record capture fidelity response presence disagrees with response bytes")
	}
	return nil
}

// prepareRecordCaptureStates runs before writer cache lookup. A typed receipt's
// fidelity only describes its own bytes: analysis-normalized live messages must
// not inherit complete from a different snapshot. Invalid receipts fail closed.
func prepareRecordCaptureStates(r *HTTPRecord, rr *httpmsg.HttpRequestResponse) error {
	// An empty response object is not a response on reload: supplied receipts
	// restore presence from bytes. Reject it before either direct enrichment or
	// writer cache admission constructs HasResponse/ResponseHash. Producers can
	// represent missing/unknown/truncated empty responses with a nil object.
	if rr.HasResponse() && len(rr.Response().Raw()) == 0 {
		return fmt.Errorf("HTTP record has an empty response object; use an absent response")
	}
	r.CaptureRequestState, r.CaptureResponseState = "", ""
	r.SentAt = time.Time{}
	x := rr.Evidence()
	if x == nil {
		return nil
	}
	if err := x.Validate(); err != nil {
		return fmt.Errorf("invalid HTTP record receipt: %w", err)
	}
	r.CaptureRequestState, r.CaptureResponseState = x.RequestState, x.ResponseState
	if !bytes.Equal(x.Request, rr.Request().Raw()) {
		r.CaptureRequestState = evidence.StateUnknown
	}
	var response []byte
	if rr.HasResponse() {
		response = rr.Response().Raw()
	}
	if !bytes.Equal(x.Response, response) {
		r.CaptureResponseState = evidence.StateUnknown
	}
	// Retain the source time without retaining its execution identity. Legacy
	// receipts may have no time; enrichment keeps the existing write-time rule.
	r.SentAt = x.CapturedAt
	return nil
}

// EffectiveCaptureStates validates known stored fidelity and accounts for
// explicit body loss without copying message bytes or creating a receipt. The
// immutable capture columns remain unchanged. Entirely absent metadata reports
// unknown/unknown, including legacy compacted rows, not a new fidelity claim.
func (r *HTTPRecord) EffectiveCaptureStates() (request, response evidence.State, err error) {
	if err := r.ValidateCaptureStates(); err != nil {
		return "", "", err
	}
	request, response = r.captureStates()
	if !r.hasCaptureStates() {
		return request, response, nil
	}
	if r.BodyCompaction != nil {
		if part := r.BodyCompaction.Request; part != nil && part.KeptLength < part.OriginalLength {
			request = evidence.StateTruncated
		}
		if part := r.BodyCompaction.Response; part != nil && part.KeptLength < part.OriginalLength {
			response = evidence.StateTruncated
		}
	}
	return request, response, nil
}

// recordWithSuppliedFidelity creates a new supplied view from the stored bytes
// and actual destination. It never associates the raw-record UUID/hash with a
// captured receipt, nor repairs missing bytes from URL/headers/Content-Length.
func recordWithSuppliedFidelity(r *HTTPRecord) (*httpmsg.HttpRequestResponse, error) {
	request, response, err := r.EffectiveCaptureStates()
	if err != nil {
		return nil, err
	}
	service := r.Scheme + "://" + net.JoinHostPort(r.Hostname, strconv.Itoa(r.Port))
	x := evidence.NewExchange(service, r.URL, r.RawRequest, r.RawResponse, evidence.ProvenanceSupplied)
	x.RequestState, x.ResponseState = request, response
	x.CapturedAt = r.SentAt
	x.ContentHash = x.Hash()
	return httpmsg.FromEvidenceExchange(x)
}

// Import UUID conflicts cannot discard a different known snapshot. Ownership
// always matches; only same-project rows with no metadata on EITHER side retain
// the historical skip behavior. Validate inside the insertion transaction, so a
// conflicting in-batch duplicate rolls back before any saved callback fires.
// Raw hashes and parsed/enrichment fields cannot substitute for exact bytes.
func validateExistingRecordCaptureStates(ctx context.Context, tx bun.Tx, records []*HTTPRecord) error {
	incoming := make(map[string]*HTTPRecord, len(records))
	for _, record := range records {
		if previous := incoming[record.UUID]; previous != nil {
			if !recordCaptureIdentityEqual(previous, record) {
				return fmt.Errorf("%w: conflicting imported capture fidelity for %s", ErrImmutableRecordExchange, record.UUID)
			}
			continue
		}
		incoming[record.UUID] = record
	}
	for chunk := range slices.Chunk(records, SQLChunkSize) {
		ids := make([]string, 0, len(chunk))
		for _, record := range chunk {
			ids = append(ids, record.UUID)
		}
		q := tx.NewSelect().Model((*HTTPRecord)(nil)).
			Column(recordCaptureIdentityColumns...).
			Where("uuid IN (?)", bun.List(ids))
		rows, err := q.Rows(ctx)
		if err != nil {
			return err
		}
		// A SQL chunk bounds identifiers, not body sizes: even a single row can
		// carry an 8 MiB response. Hydrate and release one candidate at a time.
		err = func() error {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var stored HTTPRecord
				if err := q.DB().ScanRow(ctx, rows, &stored); err != nil {
					return err
				}
				if !recordCaptureIdentityEqual(&stored, incoming[stored.UUID]) {
					return fmt.Errorf("%w: conflicting stored capture fidelity for %s", ErrImmutableRecordExchange, stored.UUID)
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

var recordCaptureIdentityColumns = append([]string{
	"uuid", "project_uuid", "scheme", "hostname", "port", "has_response",
	"raw_request", "raw_response", "sent_at", "body_compaction",
}, recordCaptureStateColumns...)

func recordCaptureIdentityEqual(a, b *HTTPRecord) bool {
	if a.ProjectUUID != b.ProjectUUID {
		return false
	}
	if !a.hasCaptureStates() && !b.hasCaptureStates() {
		return true
	}
	return a.CaptureRequestState == b.CaptureRequestState && a.CaptureResponseState == b.CaptureResponseState &&
		a.Scheme == b.Scheme && a.Hostname == b.Hostname && a.Port == b.Port && a.HasResponse == b.HasResponse &&
		bytes.Equal(a.RawRequest, b.RawRequest) && bytes.Equal(a.RawResponse, b.RawResponse) &&
		// Zero import times retain the existing database default-time contract;
		// when both sides supply a time, the immutable source capture time agrees.
		(a.SentAt.IsZero() || b.SentAt.IsZero() || a.SentAt.Equal(b.SentAt)) &&
		reflect.DeepEqual(a.BodyCompaction, b.BodyCompaction)
}

// Set-based SQLite copies discover columns, so new fidelity fields flow through
// automatically. Validate only rows carrying known metadata, one owned row at a
// time, before copying; neither old source rows nor overlapping UUIDs can conceal
// invalid known states. This is validation, not an alternative receipt reader.
func validateMergeRecordCaptureStates(ctx context.Context, tx *sql.Tx, columns []string) error {
	states := make([]string, len(recordCaptureStateColumns))
	known := make([]string, 0, len(states))
	for i, column := range recordCaptureStateColumns {
		states[i] = "''"
		if slices.Contains(columns, column) {
			states[i] = "COALESCE(" + column + ", '')"
			known = append(known, states[i]+" != ''")
		}
	}
	// Compare bytes in SQL and return only the first conflicting UUID, never a
	// corpus of overlapping bodies. Ownership cannot collide even for legacy
	// rows. With metadata on either side the complete immutable snapshot must
	// agree; states alone do not identify what a UUID describes.
	sourceColumn := func(column, fallback string) string {
		if slices.Contains(columns, column) {
			return "s." + column
		}
		return fallback
	}
	coalescedSource := func(column, fallback string) string {
		return "COALESCE(" + sourceColumn(column, fallback) + ", " + fallback + ")"
	}
	comparisons := make([]string, 0, len(recordCaptureIdentityColumns))
	knownEither := make([]string, 0, 2*len(recordCaptureStateColumns))
	for _, column := range recordCaptureStateColumns {
		source := coalescedSource(column, "''")
		dest := "COALESCE(d." + column + ", '')"
		comparisons = append(comparisons, source+" IS NOT "+dest)
		knownEither = append(knownEither, source+" != ''", dest+" != ''")
	}
	for _, column := range []string{"scheme", "hostname", "port", "has_response", "raw_request", "raw_response", "body_compaction"} {
		fallback := "''"
		switch column {
		case "port", "has_response":
			fallback = "0"
		case "raw_request", "raw_response":
			fallback = "X''"
		}
		comparisons = append(comparisons, coalescedSource(column, fallback)+" IS NOT COALESCE(d."+column+", "+fallback+")")
	}
	sourceTime := sourceColumn("sent_at", "NULL")
	comparisons = append(comparisons, "("+sourceTime+" IS NOT NULL AND d.sent_at IS NOT NULL AND "+sourceTime+" IS NOT d.sent_at)")
	ownershipMismatch := coalescedSource("project_uuid", "''") + " IS NOT COALESCE(d.project_uuid, '')"
	var conflict string
	err := tx.QueryRowContext(ctx, "SELECT s.uuid FROM src.http_records s JOIN main.http_records d ON d.uuid = s.uuid WHERE "+
		ownershipMismatch+" OR (("+strings.Join(knownEither, " OR ")+") AND ("+strings.Join(comparisons, " OR ")+")) LIMIT 1").Scan(&conflict)
	if err == nil {
		return fmt.Errorf("%w: conflicting merged capture fidelity for %s", ErrImmutableRecordExchange, conflict)
	}
	if err != sql.ErrNoRows {
		return err
	}
	if len(known) == 0 {
		return nil
	}
	// Optional historical raw columns are never reconstructed when absent.
	selectColumn := func(column, fallback string) string {
		if slices.Contains(columns, column) {
			return column
		}
		return fallback
	}
	query := "SELECT uuid, " + selectColumn("raw_request", "NULL") + ", " + selectColumn("raw_response", "NULL") + ", " +
		selectColumn("has_response", "false") + ", " + strings.Join(states, ", ") + " FROM src.http_records WHERE " + strings.Join(known, " OR ")
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var record HTTPRecord
		if err := rows.Scan(&record.UUID, &record.RawRequest, &record.RawResponse, &record.HasResponse,
			&record.CaptureRequestState, &record.CaptureResponseState); err != nil {
			return err
		}
		if err := record.ValidateCaptureStates(); err != nil {
			return fmt.Errorf("record %s: %w", record.UUID, err)
		}
	}
	return rows.Err()
}
