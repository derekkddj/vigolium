//go:build unix

package toollog

import (
	"os"
	"syscall"
)

func openFullArtifact(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
