//go:build !unix

package agent

import "os"

func openAuditInRoot(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
