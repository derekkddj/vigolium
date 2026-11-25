//go:build unix

package agent

import (
	"os"
	"syscall"
)

func openAuditInRoot(root *os.Root, name string) (*os.File, error) {
	// Nonblocking open prevents FIFO replacements from hanging before Stat.
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
