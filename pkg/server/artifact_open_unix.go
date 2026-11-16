//go:build unix

package server

import (
	"os"
	"syscall"
)

// Opening a FIFO for reading can wait indefinitely before the file-type check.
// Nonblocking open lets us reject special files even when a mutable session
// tree replaces a regular artifact after validation. Regular-file reads are
// unaffected, and the root still enforces containment during resolution.
func openArtifactInRoot(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
