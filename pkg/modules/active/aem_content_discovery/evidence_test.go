package aem_content_discovery

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestTreeWalkEvidenceRetainsDeepestRecursionAndConfirmations(t *testing.T) {
	// More successful reads than the evidence cap, with a single child per
	// seed to avoid map iteration ordering deciding the deepest primary.
	tree := map[string]string{"/libs.1.json": `{"jcr:primaryType":"nt:folder"}`}
	for _, root := range seeds {
		child := childPath(root, "child")
		grandchild := childPath(child, "grandchild")
		tree[root+".1.json"] = `{"jcr:primaryType":"nt:folder","child":{"jcr:primaryType":"nt:folder"}}`
		tree[child+".1.json"] = `{"jcr:primaryType":"nt:folder","grandchild":{"jcr:primaryType":"nt:folder"}}`
		tree[grandchild+".1.json"] = `{"jcr:primaryType":"nt:folder"}`
	}
	srv := serveTree(t, tree, nil)
	seed, client, m := modtest.Request(t, srv.URL), modtest.Requester(t), New()
	form := readForm{idx: 0, sample: "/libs.1.json"}
	walk := m.walk(seed, client, form)
	require.Greater(t, len(walk.reached), 10)
	require.Equal(t, maxDepth, walk.maxDepth)
	require.True(t, aem.ReproduceMarker(seed, client, form.sample, reproduceRounds, isJCRJSON, walk.treeProof))
	result := m.buildTreeWalk(form, walk, srv.URL)
	primary, err := httpmsg.FromEvidenceExchange(result.Evidence[0].Exchange)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(primary.Request().Path(), "/grandchild.1.json"))
	require.Equal(t, evidence.RoleObservation, result.Evidence[0].Role)
	confirmations := 0
	parentFound := false
	parentPath := strings.TrimSuffix(primary.Request().Path(), "/grandchild.1.json") + ".1.json"
	for _, entry := range result.Evidence[1:] {
		parsed, err := httpmsg.FromEvidenceExchange(entry.Exchange)
		require.NoError(t, err)
		if entry.Role == evidence.RoleConfirmation {
			confirmations++
			require.Equal(t, form.sample, parsed.Request().Path())
		}
		if parsed.Request().Path() == parentPath {
			parentFound = true
			require.Contains(t, string(entry.Exchange.Response), `"grandchild"`)
		}
	}
	require.True(t, parentFound, fmt.Sprintf("missing actual parent %s", parentPath))
	require.Equal(t, reproduceRounds, confirmations)
	require.LessOrEqual(t, len(result.Evidence), 1+maxDepth+minNodesForFinding-1+reproduceRounds)
}
