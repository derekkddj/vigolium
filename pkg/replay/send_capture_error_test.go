package replay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestReplayCapturePreservesPartialExchangeOnError(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		status         int
		responseState  evidence.State
	}{
		{name: "completed request without response", responseState: evidence.StateMissing},
		{name: "response body read error", response: "HTTP/1.1 206 Partial Content\r\nContent-Length: 12\r\nX-Observed: yes\r\nConnection: close\r\n\r\nprefix", status: http.StatusPartialContent, responseState: evidence.StateTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seenBody := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read sent request: %v", err)
					return
				}
				seenBody <- string(body)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				defer conn.Close()
				if tc.response != "" {
					if _, err := io.WriteString(conn, tc.response); err != nil {
						t.Errorf("write partial response: %v", err)
					}
				}
			}))
			defer srv.Close()
			client := srv.Client()
			client.Timeout = 2 * time.Second
			defer client.CloseIdleConnections()
			host, port := splitAddr(t, srv.Listener.Addr().String())
			result, err := Do(context.Background(), Options{
				RawRequest: []byte("POST /partial?sent=yes HTTP/1.1\r\nHost: original.invalid\r\nContent-Length: 4\r\n\r\nsent"),
				Client:     client, Scheme: "http", Hostname: host, Port: port,
				CaptureExchange: true, NoRedirects: true, ExcerptCap: 4,
			})
			require.NoError(t, err) // execution errors belong to the summary
			require.NotNil(t, result)
			summary := result.Replay
			require.NotNil(t, summary)
			require.Contains(t, summary.Error, "request failed:")
			require.Equal(t, tc.status, summary.Status)
			x := summary.Exchange // send has already closed the returned chain
			require.NotNil(t, x)
			require.NoError(t, x.Validate())
			require.Equal(t, evidence.StateComplete, x.RequestState)
			require.Equal(t, tc.responseState, x.ResponseState)
			require.Equal(t, srv.URL, x.Service)
			require.Equal(t, srv.URL+"/partial?sent=yes", x.URL)
			sent := httpmsg.NewHttpRequest(x.Request)
			require.Equal(t, "POST", sent.Method())
			require.Equal(t, "original.invalid", sent.Header("Host"))
			require.Equal(t, <-seenBody, string(sent.Body()))
			// Replay sends the bytes as given: no default User-Agent is added.
			require.Equal(t, "4", sent.Header("Content-Length"))

			if tc.status == 0 {
				require.Empty(t, x.Response) // no synthetic status-zero HTTP response
				require.Empty(t, summary.RawBody)
				require.Empty(t, summary.Excerpt)
				require.Empty(t, summary.Headers)
				require.Empty(t, summary.ContentHash)
				require.Zero(t, summary.ResponseLen)
				require.False(t, summary.Truncated)
				return
			}
			require.Contains(t, summary.Error, io.ErrUnexpectedEOF.Error())
			require.Equal(t, "yes", summary.Headers.Get("X-Observed"))
			require.Equal(t, "12", summary.Headers.Get("Content-Length"))
			require.Equal(t, "prefix", string(summary.RawBody))
			require.Equal(t, 6, summary.ResponseLen)
			require.Equal(t, "pref", summary.Excerpt)
			require.True(t, summary.Truncated) // excerpt clipped, not whole-body completeness
			prefixHash := sha256.Sum256([]byte("prefix"))
			require.Equal(t, hex.EncodeToString(prefixHash[:8]), summary.ContentHash)
			response := httpmsg.NewHttpResponse(x.Response)
			require.Equal(t, http.StatusPartialContent, response.StatusCode())
			require.Equal(t, "prefix", string(response.Body()))
			// The summary's partial body is owned independently of the receipt.
			summary.RawBody[0] = 'X'
			require.Equal(t, "prefix", string(httpmsg.NewHttpResponse(x.Response).Body()))
			require.NoError(t, x.Validate())
		})
	}
}
