package httpmsg

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuiltRequestBodyReopensIndependentlyAfterSend(t *testing.T) {
	body := []byte{'p', 0, 0xff, 'z'}
	raw := append([]byte("POST /rpc HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n"), body...)
	rr, err := ParseRawRequest(string(raw))
	require.NoError(t, err)
	req, err := rr.BuildRetryableRequestWithContext(context.Background())
	require.NoError(t, err)
	sent, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, sent)
	require.NoError(t, req.Body.Close())
	// Live input analysis cannot rewrite the transport's owned replay body.
	copy(rr.Request().Body(), bytes.Repeat([]byte{'!'}, len(body)))
	for i := 0; i < 3; i++ {
		reopened, err := req.GetBody()
		require.NoError(t, err)
		got, err := io.ReadAll(reopened)
		require.NoError(t, err)
		require.Equal(t, body, got)
		require.NoError(t, reopened.Close())
	}
}
