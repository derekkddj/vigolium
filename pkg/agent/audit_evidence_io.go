package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/audit"
)

const (
	auditIOTimeout             = 30 * time.Second
	auditTerminalTimeout       = 10 * time.Second
	maxAuditControlBytes int64 = 4 << 20
	maxAuditParseBytes   int64 = 32 << 20
	maxAuditEntries            = 100000
)

// auditRootFS pins a directory and rejects symlinks/special files before and
// after nonblocking open. os.Root additionally prevents resolution outside it.
// This is an in-process read boundary, not a distributed source lease.
type auditRootFS struct {
	root *os.Root
	ctx  context.Context // optional walk budget; standalone reads pass it explicitly
}

func openAuditRoot(dir string) (*auditRootFS, error) {
	if err := validateAuditDir(dir); err != nil {
		return nil, err
	}
	before, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	after, err := r.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = r.Close()
		return nil, fmt.Errorf("audit evidence root changed while opening")
	}
	return &auditRootFS{root: r}, nil
}

func validateAuditDir(dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("audit evidence directory is not a real directory: %s", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func (r *auditRootFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, fs.ErrInvalid
	}
	for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
		info, err := r.root.Lstat(parent)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("unsupported audit evidence directory")
		}
	}
	before, err := r.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() && !before.Mode().IsRegular() {
		return nil, fmt.Errorf("unsupported audit evidence file: %s", name)
	}
	file, err := openAuditInRoot(r.root, name)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || (!after.IsDir() && !after.Mode().IsRegular()) {
		_ = file.Close()
		return nil, fmt.Errorf("audit evidence changed while opening: %s", name)
	}
	return file, nil
}

func (r *auditRootFS) ReadDir(name string) ([]fs.DirEntry, error) {
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return r.readDirContext(ctx, name)
}

func (r *auditRootFS) readDirContext(ctx context.Context, name string) ([]fs.DirEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []fs.DirEntry
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk, err := f.(fs.ReadDirFile).ReadDir(1024)
		entries = append(entries, chunk...)
		if len(entries) > maxAuditEntries {
			return nil, fmt.Errorf("audit evidence directory entry limit exceeded")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func walkAuditTree(ctx context.Context, dir string, fn func(*auditRootFS, string, fs.DirEntry) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r, err := openAuditRoot(dir)
	if err != nil {
		return err
	}
	defer r.root.Close()
	r.ctx = ctx
	n := 0
	return fs.WalkDir(r, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		n++
		if n > maxAuditEntries {
			return fmt.Errorf("audit evidence tree entry limit exceeded")
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("unsupported audit evidence file: %s", name)
		}
		return fn(r, name, d)
	})
}

// copyAuditSnapshot consumes exactly the initial regular-file length. Appenders
// cannot keep a read alive forever; shrink/growth/mtime changes reject the copy.
// Chunk-level context checks bound ordinary filesystem work, not a stuck kernel
// read/fsync on an unavailable filesystem.
func copyAuditSnapshot(ctx context.Context, out io.Writer, f *os.File, limit int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := f.Stat()
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("unsupported audit evidence file")
	}
	if before.Size() < 0 || (limit >= 0 && before.Size() > limit) {
		return fmt.Errorf("audit evidence read limit exceeded")
	}
	remaining := before.Size()
	buf := make([]byte, 64*1024)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := int64(len(buf))
		if remaining < chunk {
			chunk = remaining
		}
		n, err := io.ReadFull(f, buf[:chunk])
		if err != nil {
			return err
		}
		written, err := out.Write(buf[:n])
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
		remaining -= int64(n)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return fmt.Errorf("audit evidence changed during read")
	}
	return nil
}

func readAuditControl(ctx context.Context, dir, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := openAuditRoot(dir)
	if err != nil {
		return nil, err
	}
	defer r.root.Close()
	f, err := r.Open(filepath.ToSlash(name))
	if err != nil {
		return nil, err
	}
	var data bytes.Buffer
	readErr := copyAuditSnapshot(ctx, &data, f.(*os.File), limit)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

func auditHashInRoot(ctx context.Context, r *auditRootFS, name string) (string, error) {
	f, err := r.Open(name)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	readErr := copyAuditSnapshot(ctx, hash, f.(*os.File), -1)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func copyAuditInRoot(ctx context.Context, r *auditRootFS, name, dest string, limit int64) (string, error) {
	f, err := r.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	err = publishAuditArtifact(dest, func(out io.Writer) error {
		return copyAuditSnapshot(ctx, io.MultiWriter(out, hash), f.(*os.File), limit)
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// Keep this projection aligned with audit.ParseFolder's documented layouts.
// Nested evidence/raw traffic is archived in full, not loaded by the parser.
func isAuditParserFile(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) == 1 {
		return name == "audit-state.json" || name == "revisit-audit-state.json" || name == "commit-recon-report.md"
	}
	if parts[0] != "findings" && parts[0] != "findings-draft" && parts[0] != "findings-theoretical" {
		return false
	}
	base := path.Base(name)
	if len(parts) == 2 {
		return strings.HasSuffix(base, ".md")
	}
	return len(parts) == 3 && (base == "draft.md" || base == "report.md" || base == "metadata.json" || strings.HasPrefix(base, "poc."))
}

// The legacy parser uses unrestricted ReadFile. Give it only a private, bounded
// snapshot of the files it consumes, never a mutable/rejected source tree. Raw
// evidence remains complete in the archive/source; exceeding parser limits is a
// visible evidence error, not silent truncation or permission-error skipping.
func parseAuditEvidence(ctx context.Context, dir string) (*audit.Import, error) {
	stage, err := os.MkdirTemp("", "vigolium-audit-parse-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	var total int64
	err = walkAuditTree(ctx, dir, func(r *auditRootFS, name string, d fs.DirEntry) error {
		dest := filepath.Join(stage, filepath.FromSlash(name))
		if d.IsDir() {
			return ensureAuditDir(dest)
		}
		if !isAuditParserFile(name) {
			return nil
		}
		info, err := r.root.Lstat(name)
		if err != nil {
			return err
		}
		if info.Size() > maxAuditControlBytes || total+info.Size() > maxAuditParseBytes {
			return fmt.Errorf("audit parser evidence limit exceeded; retain raw evidence for recovery")
		}
		limit := maxAuditControlBytes
		if remaining := maxAuditParseBytes - total; remaining < limit {
			limit = remaining
		}
		_, err = copyAuditInRoot(ctx, r, name, dest, limit)
		if err != nil {
			return err
		}
		published, err := os.Stat(dest)
		if err != nil {
			return err
		}
		total += published.Size()
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := audit.ParseFolder(stage)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if result.RepoName == filepath.Base(stage) {
		result.RepoName = filepath.Base(dir)
	}
	return result, nil
}
