package oast

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/oast/planting"
	"go.uber.org/zap"
)

// Ordinary sends retain no bodies. OAST owns at most 64 small receipts in its
// hot cache and at most 64 queued writes (32 MiB of cached/queued raw bytes,
// plus one in-flight write and small metadata). Larger receipts can be
// registered explicitly, synchronously, but never enter these
// buffers. Durable storage is indexed by exact project+nonce, not a corpus load.
const (
	plantingReceiptCacheSize = 64
	maxBufferedPlantingBytes = 256 << 10
	plantingWriteTimeout     = 2 * time.Second
	plantingDrainTimeout     = 5 * time.Second
)

// The central schema owns pending planting storage. Once selected by a finding,
// the same actual execution also persists in the shared evidence store.
type plantingReceiptRow = database.OASTPlantingReceipt

var errPlantingReceiptConflict = database.ErrOASTPlantingReceiptConflict

type plantingJob struct {
	nonce   string
	x       *evidence.Exchange
	barrier chan struct{}
}

func (s *Service) plantingCacheLocked() *lru.Cache[string, *evidence.Exchange] {
	if s.plantingCache == nil {
		s.plantingCache, _ = lru.New[string, *evidence.Exchange](plantingReceiptCacheSize)
	}
	return s.plantingCache
}

// NonceForCallback recovers only a nonce minted by this service. It handles
// fixed path templates as well as interactsh hosts; no URL/hash lookup of an
// HTTP exchange is performed.
func (s *Service) NonceForCallback(callbackURL string) string {
	if s == nil || callbackURL == "" {
		return ""
	}
	nonce := extractNonce(callbackHost(callbackURL))
	if s.template != nil {
		nonce = s.template.nonceOf(callbackURL)
	}
	if _, ok := s.trackerCache().Peek(nonce); !ok {
		return ""
	}
	return nonce
}

// RegisterPlantingReceipt binds ONE known nonce to ONE actual sender-owned
// execution. Call before closing the response chain. A second execution cannot
// replace the first, even at the same URL or with identical content. Mint a new
// callback nonce for a new send. Missing requests and cached observations cannot
// establish planting. Returned errors must not be treated as retained proof.
// Explicit registration persists synchronously with a bounded write deadline;
// the HTTP observer below uses the bounded asynchronous path instead.
func (s *Service) RegisterPlantingReceipt(nonce string, x *evidence.Exchange) error {
	if s == nil {
		return nil
	}
	if err := s.validatePlanting(nonce, x); err != nil {
		return err
	}
	x = x.Clone()
	s.plantingMu.Lock()
	defer s.plantingMu.Unlock()
	if s.plantingStopped {
		return fmt.Errorf("OAST planting receipt service closed")
	}
	if old, ok := s.plantingCacheLocked().Peek(nonce); ok && !samePlantingReceipt(old, x) {
		return fmt.Errorf("OAST nonce %s already owns another planting execution", nonce)
	}
	if s.repo != nil {
		ctx, cancel := context.WithTimeout(context.Background(), plantingWriteTimeout)
		defer cancel()
		if err := s.persistPlantingReceipt(ctx, nonce, x); err != nil {
			return err
		}
	} else if len(x.Request)+len(x.Response) > maxBufferedPlantingBytes {
		return fmt.Errorf("OAST planting receipt exceeds bounded in-memory retention without a database")
	}
	if err := s.sealPlantingNonce(nonce, x, false); err != nil {
		return err
	}
	if len(x.Request)+len(x.Response) <= maxBufferedPlantingBytes {
		s.plantingCacheLocked().Add(nonce, x)
	}
	return nil
}

func (s *Service) validatePlanting(nonce string, x *evidence.Exchange) error {
	if nonce == "" {
		return fmt.Errorf("OAST planting receipt has no nonce")
	}
	pctx, ok := s.trackerCache().Peek(nonce)
	if !ok || !pctx.plantingOwned {
		return fmt.Errorf("OAST planting receipt nonce is not minted by this service")
	}
	if err := x.Validate(); err != nil {
		return err
	}
	if pctx.plantingID != "" && (pctx.plantingID != x.ID || pctx.plantingHash != x.ContentHash || !pctx.plantingAt.Equal(x.CapturedAt)) {
		return fmt.Errorf("OAST nonce %s already owns another planting execution", nonce)
	}
	if x.Provenance != evidence.ProvenanceCaptured || x.RequestState == evidence.StateMissing || len(x.Request) == 0 {
		return fmt.Errorf("OAST planting receipt requires an actual captured emitted request")
	}
	if !containsNonceToken(x.Request, nonce) || !matchesPlantingSlot(x.Request, nonce, pctx) {
		return fmt.Errorf("OAST planting receipt emitted request does not contain its nonce in the declared slot")
	}
	return nil
}

// Called under plantingMu; contextMu also protects RecordPayload updates.
func (s *Service) sealPlantingNonce(nonce string, x *evidence.Exchange, nonblocking bool) error {
	if nonblocking {
		if !s.contextMu.TryLock() {
			return fmt.Errorf("OAST planting context busy; receipt unavailable")
		}
	} else {
		s.contextMu.Lock()
	}
	defer s.contextMu.Unlock()
	pctx, ok := s.trackerCache().Peek(nonce)
	if !ok || !pctx.plantingOwned {
		return fmt.Errorf("OAST minted nonce context unavailable during sender handoff")
	}
	if pctx.plantingID != "" && (pctx.plantingID != x.ID || pctx.plantingHash != x.ContentHash || !pctx.plantingAt.Equal(x.CapturedAt)) {
		return fmt.Errorf("OAST nonce %s already owns another planting execution", nonce)
	}
	pctx.plantingID, pctx.plantingHash, pctx.plantingAt = x.ID, x.ContentHash, x.CapturedAt
	s.trackerCache().Add(nonce, pctx)
	return nil
}

func samePlantingReceipt(a, b *evidence.Exchange) bool {
	return a.ID == b.ID && a.ContentHash == b.ContentHash && a.CapturedAt.Equal(b.CapturedAt)
}

func containsNonceToken(raw []byte, nonce string) bool {
	return planting.ContainsNonceToken(raw, nonce)
}

func (s *Service) plantingNonces(raw []byte) []string {
	if s == nil || len(raw) == 0 {
		return nil
	}
	var nonces []string
	seen := map[string]bool{}
	planting.WalkNonceTokens(raw, func(nonce string) {
		if pctx, ok := s.trackerCache().Peek(nonce); ok && pctx.plantingOwned && !seen[nonce] {
			nonces = append(nonces, nonce)
			seen[nonce] = true
		}
	})
	return nonces
}

// matchesPlantingSlot correlates the known mint context against its declared
// injection field in actual emitted bytes. Incidental nonce references in a
// different header, URL preview or Referer cannot stand in for that field.
func matchesPlantingSlot(raw []byte, nonce string, pctx PayloadContext) bool {
	return planting.MatchesSlot(raw, nonce, pctx.ParameterName, pctx.Payload, isHeaderInjection(pctx))
}

// WantsPlantingReceipt is the opt-in HTTP selector. Intent is used ONLY to
// avoid capturing ordinary traffic; ObservePlantingReceipt rechecks the actual
// current request. RawRequestTarget without captured emitted bytes stays missing.
func (s *Service) WantsPlantingReceipt(input, raw []byte, requestTarget string) bool {
	return len(s.plantingNonces(input)) > 0 || len(s.plantingNonces(raw)) > 0 || len(s.plantingNonces([]byte(requestTarget))) > 0
}

// ObservePlantingReceipt implements the cycle-free HTTP observer contract. It
// owns a snapshot before Execute returns, and queues only bounded small writes.
// The observer never performs network requests or blocks on the database.
func (s *Service) ObservePlantingReceipt(x *evidence.Exchange) error {
	if s == nil || x == nil {
		return nil
	}
	nonces := s.plantingNonces(x.Request)
	for _, nonce := range nonces {
		pctx, known := s.trackerCache().Peek(nonce)
		if !known || !pctx.plantingOwned || !matchesPlantingSlot(x.Request, nonce, pctx) {
			// A token in an incidental Referer/other field is not evidence that
			// this nonce's actual planting slot was sent. Keep it unavailable.
			continue
		}
		if err := s.validatePlanting(nonce, x); err != nil {
			return err
		}
		if len(x.Request)+len(x.Response) > maxBufferedPlantingBytes {
			return fmt.Errorf("OAST planting receipt exceeds bounded observer retention; register explicitly")
		}
		// Explicit synchronous registration and Flush may hold this mutex
		// while waiting. Never make the transport observer wait behind them.
		if !s.plantingMu.TryLock() {
			return fmt.Errorf("OAST planting receipt store busy; receipt unavailable")
		}
		if s.plantingStopped {
			s.plantingMu.Unlock()
			return fmt.Errorf("OAST planting receipt observer closed")
		}
		cache := s.plantingCacheLocked()
		if old, ok := cache.Peek(nonce); ok {
			s.plantingMu.Unlock()
			if !samePlantingReceipt(old, x) {
				return fmt.Errorf("OAST nonce %s already owns another planting execution", nonce)
			}
			continue
		}
		if err := s.sealPlantingNonce(nonce, x, true); err != nil {
			s.plantingMu.Unlock()
			return err
		}
		owned := x.Clone()
		cache.Add(nonce, owned)
		if s.repo != nil {
			s.startPlantingWriterLocked()
			select {
			case s.plantingJobs <- plantingJob{nonce: nonce, x: owned}:
			default:
				s.plantingMu.Unlock()
				return fmt.Errorf("OAST planting persistence queue full; receipt retained only in bounded memory")
			}
		}
		s.plantingMu.Unlock()
	}
	return nil
}

func (s *Service) startPlantingWriterLocked() {
	if s.plantingJobs != nil {
		return
	}
	s.plantingJobs = make(chan plantingJob, plantingReceiptCacheSize)
	s.plantingDone = make(chan struct{})
	writerCtx, cancelWriter := context.WithCancel(context.Background())
	s.plantingCancel = cancelWriter
	go func() {
		defer close(s.plantingDone)
		defer cancelWriter()
		for job := range s.plantingJobs {
			if job.barrier != nil {
				close(job.barrier)
				continue
			}
			// Close cancels remaining work if its drain budget expires, instead
			// of leaving 64 sequential database timeouts running after shutdown.
			if writerCtx.Err() != nil {
				continue
			}
			ctx, cancel := context.WithTimeout(writerCtx, plantingWriteTimeout)
			err := s.persistPlantingReceipt(ctx, job.nonce, job.x)
			cancel()
			if err != nil {
				if errors.Is(err, errPlantingReceiptConflict) {
					// A permanent durable conflict makes correlation ambiguous.
					// Do not continue exposing the conflicting hot-cache receipt.
					s.plantingMu.Lock()
					if old, ok := s.plantingCacheLocked().Peek(job.nonce); ok && samePlantingReceipt(old, job.x) {
						s.plantingCache.Remove(job.nonce)
					}
					s.plantingMu.Unlock()
				}
				zap.L().Warn("OAST: planting receipt persistence failed; late evidence may be unavailable", zap.String("nonce", job.nonce), zap.Error(err))
			}
		}
	}()
}

func (s *Service) drainPlantingReceipts(stop bool) {
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), plantingDrainTimeout)
	defer cancel()
	// Retry a full queue outside plantingMu: the writer may need that mutex
	// to invalidate a durable conflict, and concurrent Close must remain safe.
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	for {
		s.plantingMu.Lock()
		if stop && !s.plantingStopped {
			s.plantingStopped = true
			if s.plantingJobs != nil {
				close(s.plantingJobs)
			}
		}
		var done <-chan struct{}
		full := false
		if s.plantingJobs != nil {
			if s.plantingStopped {
				done = s.plantingDone
			} else {
				barrier := make(chan struct{})
				select {
				case s.plantingJobs <- plantingJob{barrier: barrier}:
					done = barrier
				default:
					full = true
				}
			}
		}
		cancelWriter := s.plantingCancel
		s.plantingMu.Unlock()
		if full {
			select {
			case <-retry.C:
				continue
			case <-ctx.Done():
				zap.L().Warn("OAST: planting receipt drain timed out; late evidence may be unavailable")
				return
			}
		}
		if done == nil {
			return
		}
		select {
		case <-done:
		case <-ctx.Done():
			if stop && cancelWriter != nil {
				cancelWriter()
			}
			zap.L().Warn("OAST: planting receipt drain timed out; late evidence may be unavailable")
		}
		return
	}
}

func oastProject(project string) string {
	if project == "" {
		return database.DefaultProjectUUID
	}
	return project
}

func (s *Service) persistPlantingReceipt(ctx context.Context, nonce string, x *evidence.Exchange) error {
	s.plantingWriteMu.Lock()
	defer s.plantingWriteMu.Unlock()
	encoded, err := json.Marshal(x)
	if err != nil {
		return err
	}
	row := &plantingReceiptRow{ProjectUUID: oastProject(s.projectUUID), Nonce: nonce, ScanUUID: s.scanUUID, Receipt: string(encoded)}
	return s.repo.SaveOASTPlantingReceipt(ctx, row)
}

func (s *Service) readPlantingReceipt(ctx context.Context, nonce string) (*evidence.Exchange, error) {
	row, err := s.repo.GetOASTPlantingReceipt(ctx, oastProject(s.projectUUID), nonce, s.scanUUID)
	if err != nil {
		return nil, err
	}
	return row.Exchange()
}

func (s *Service) plantingReceipt(nonce string) *evidence.Exchange {
	s.plantingMu.Lock()
	if x, ok := s.plantingCacheLocked().Get(nonce); ok {
		s.plantingMu.Unlock()
		return x.Clone()
	}
	s.plantingMu.Unlock()
	if s.repo == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), plantingWriteTimeout)
	defer cancel()
	// Historical stores have no planting table. This is a read-only check, not
	// a migration, and never falls back to a nearby HTTP record or another project.
	var exists int
	query := "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'oast_planting_receipts'"
	if s.repo.DB().Driver() == "postgres" {
		query = "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'oast_planting_receipts'"
	}
	if err := s.repo.DB().NewRaw(query).Scan(ctx, &exists); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		zap.L().Warn("OAST: cannot inspect planting receipt store", zap.Error(err))
		return nil
	}
	x, err := s.readPlantingReceipt(ctx, nonce)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			zap.L().Warn("OAST: planting receipt unavailable", zap.String("nonce", nonce), zap.Error(err))
		}
		return nil
	}
	if pctx, ok := s.trackerCache().Peek(nonce); ok && pctx.plantingID != "" && (pctx.plantingID != x.ID || pctx.plantingHash != x.ContentHash || !pctx.plantingAt.Equal(x.CapturedAt)) {
		zap.L().Warn("OAST: durable planting receipt conflicts with owned nonce seal", zap.String("nonce", nonce))
		return nil
	}
	return x
}

// payloadContextForNonce restores only an exact nonce in this service's project
// and scan after tracker eviction. The original request hash stays baseline
// context; it is never used to select a planting exchange.
func (s *Service) payloadContextForNonce(nonce string) (PayloadContext, bool) {
	if pctx, ok := s.trackerCache().Get(nonce); ok {
		return pctx, true
	}
	if s.repo == nil || strings.TrimSpace(nonce) == "" {
		return PayloadContext{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), plantingWriteTimeout)
	defer cancel()
	rows, err := s.repo.GetOASTPayloadsByNonce(ctx, oastProject(s.projectUUID), []string{nonce})
	if err != nil {
		zap.L().Warn("OAST: late payload correlation unavailable", zap.Error(err))
		return PayloadContext{}, false
	}
	row := rows[nonce]
	if row == nil || row.ScanUUID != s.scanUUID {
		return PayloadContext{}, false
	}
	return payloadContextFromRow(row, nonce), true
}
