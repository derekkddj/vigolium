//go:build !unix

package toollog

import "os"

func openFullArtifact(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
