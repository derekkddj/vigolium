//go:build !unix

package server

import "os"

func openArtifactInRoot(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
