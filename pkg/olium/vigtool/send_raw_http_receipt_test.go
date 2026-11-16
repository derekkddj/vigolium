package vigtool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

type rawSocketRead struct {
	data []byte
	err  error
}

type rawSocketWrite struct {
	n   int
	err error
}

type receiptSocket struct {
	reads   []rawSocketRead
	writes  []rawSocketWrite
	calls   []string
	written [][]byte
}

func (c *receiptSocket) Read(b []byte) (int, error) {
	c.calls = append(c.calls, "read")
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	r := c.reads[0]
	c.reads = c.reads[1:]
	n := copy(b, r.data)
	if n < len(r.data) {
		c.reads = append([]rawSocketRead{{data: r.data[n:], err: r.err}}, c.reads...)
		return n, nil
	}
	return n, r.err
}

func (c *receiptSocket) Write(b []byte) (int, error) {
	c.calls = append(c.calls, "write")
	n, err := len(b), error(nil)
	if len(c.writes) > 0 {
		w := c.writes[0]
		c.writes = c.writes[1:]
		n, err = w.n, w.err
	}
	c.written = append(c.written, bytes.Clone(b[:n]))
	return n, err
}

func (*receiptSocket) Close() error                     { return nil }
func (*receiptSocket) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*receiptSocket) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*receiptSocket) SetDeadline(time.Time) error      { return nil }
func (*receiptSocket) SetReadDeadline(time.Time) error  { return nil }
func (*receiptSocket) SetWriteDeadline(time.Time) error { return nil }

type rawIdleTimeout struct{}

func (rawIdleTimeout) Error() string   { return "idle timeout" }
func (rawIdleTimeout) Timeout() bool   { return true }
func (rawIdleTimeout) Temporary() bool { return true }

func rawReceiptTool(c *receiptSocket) *sendRawHTTPTool {
	return &sendRawHTTPTool{dial: func(context.Context, string, string) (net.Conn, error) { return c, nil }}
}

func TestRawHTTPDialFailureReceiptsContainNoSentIntent(t *testing.T) {
	tool := &sendRawHTTPTool{dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("dial failed") }}
	res := tool.exchange(context.Background(), "example.invalid", 80, false, "", []byte("first"), []byte("second"), false, time.Second, time.Second, 1024)
	require.Contains(t, res.Error, "dial failed")
	require.Zero(t, res.SentBytes)
	require.Empty(t, res.SentEcho)
	require.Empty(t, res.SecondSentEcho)
	require.Equal(t, len("firstsecond"), res.IntendedBytes)
	require.Equal(t, "first", res.IntendedRequest)
	require.Equal(t, "second", res.IntendedSecondRequest)
	require.Len(t, res.Transcript.Writes, 2)
	require.Empty(t, res.Transcript.Reads)
	for _, w := range res.Transcript.Writes {
		require.Equal(t, evidence.StateMissing, w.State)
		x, err := tool.SelectHTTPReceipt(w.Receipt.Ref)
		require.NoError(t, err)
		require.Empty(t, x.Request)
		require.Empty(t, x.Response)
		require.Equal(t, evidence.StateMissing, x.RequestState)
		require.NoError(t, x.Validate())
	}
	require.False(t, res.Persisted)
	require.Equal(t, "execution_scoped_only", res.PersistenceStatus)
}

func TestRawHTTPPartialWritesAccountActualPrefixAndDoNotSendSecond(t *testing.T) {
	for _, writeErr := range []error{errors.New("broken write"), nil} {
		t.Run("partial", func(t *testing.T) {
			c := &receiptSocket{writes: []rawSocketWrite{{n: 3, err: writeErr}}}
			tool := rawReceiptTool(c)
			res := tool.exchange(context.Background(), "example.invalid", 80, false, "", []byte("abcdef"), []byte("second"), true, time.Second, time.Second, 1024)
			require.NotEmpty(t, res.Error)
			require.Equal(t, []string{"write"}, c.calls) // no retries/extra requests or reads
			require.Equal(t, 3, res.SentBytes)
			require.Equal(t, "abc", res.SentEcho)
			require.Equal(t, evidence.StateTruncated, res.Transcript.Writes[0].State)
			require.Equal(t, evidence.StateMissing, res.Transcript.Writes[1].State)
			x, err := tool.SelectHTTPReceipt(res.Transcript.Writes[0].Receipt.Ref)
			require.NoError(t, err)
			require.Equal(t, []byte("abc"), x.Request)
			require.Equal(t, evidence.StateTruncated, x.RequestState)
			require.Empty(t, x.Response)
			require.NoError(t, x.Validate())
		})
	}
}

func TestRawHTTPTwoPhasePreservesBothWritesAndUnpairedReadWindows(t *testing.T) {
	first, second := []byte("GET /one HTTP/1.1\r\n\r\n"), []byte("GET /two HTTP/1.1\r\n\r\n")
	c := &receiptSocket{reads: []rawSocketRead{{data: []byte("first response")}, {err: rawIdleTimeout{}}, {data: []byte("second response"), err: io.EOF}}}
	tool := rawReceiptTool(c)
	res := tool.exchange(context.Background(), "example.invalid", 80, false, "", first, second, false, time.Second, time.Second, 1024)
	require.Empty(t, res.Error)
	require.Equal(t, []string{"write", "read", "read", "write", "read"}, c.calls)
	require.Equal(t, len(first)+len(second), res.SentBytes)
	require.Equal(t, len(second), res.SecondSentBytes)
	require.Equal(t, string(first), res.SentEcho)
	require.Equal(t, string(second), res.SecondSentEcho)
	require.Len(t, res.Transcript.Reads, 2)
	require.Equal(t, evidence.StateUnknown, res.Transcript.ResponseAttribution)
	require.Equal(t, evidence.StateUnknown, res.Transcript.Reads[0].State)
	require.Equal(t, evidence.StateComplete, res.Transcript.Reads[1].State) // EOF completes window only
	for i, expected := range [][]byte{first, second} {
		x, err := tool.SelectHTTPReceipt(res.Transcript.Writes[i].Receipt.Ref)
		require.NoError(t, err)
		require.Equal(t, expected, x.Request)
		require.Equal(t, evidence.StateComplete, x.RequestState)
		require.Equal(t, evidence.StateMissing, x.ResponseState)
	}
	for _, read := range res.Transcript.Reads {
		x, err := tool.SelectHTTPReceipt(read.Receipt.Ref)
		require.NoError(t, err)
		require.Empty(t, x.Request)
		require.Equal(t, evidence.StateMissing, x.RequestState)
		require.Equal(t, evidence.StateUnknown, x.ResponseState) // no HTTP framing/pair inferred
	}
	selected, err := tool.SelectRawHTTPTranscript(res.Transcript.Ref)
	require.NoError(t, err)
	selected.Writes[0].SentBytes = 0
	selected, err = tool.SelectRawHTTPTranscript(res.Transcript.Ref)
	require.NoError(t, err)
	require.Equal(t, len(first), selected.Writes[0].SentBytes)
}

func TestRawHTTPPipelineNeverConcatenatesRequestsIntoResponsePair(t *testing.T) {
	combined := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nb")
	c := &receiptSocket{reads: []rawSocketRead{{data: combined, err: io.EOF}}}
	tool := rawReceiptTool(c)
	first, second := []byte{0, 255, 1}, []byte("second")
	res := tool.exchange(context.Background(), "example.invalid", 80, false, "", first, second, true, time.Second, time.Second, 1024)
	require.Empty(t, res.Error)
	require.Equal(t, []string{"write", "write", "read"}, c.calls)
	require.Equal(t, string(combined), res.Response)
	require.Empty(t, res.SecondResponse)
	require.Len(t, res.Transcript.Reads, 1)
	require.Equal(t, "pipeline_read", res.Transcript.Reads[0].Window)
	require.Equal(t, evidence.StateUnknown, res.Transcript.ResponseAttribution)
	x, err := tool.SelectHTTPReceipt(res.Transcript.Reads[0].Receipt.Ref)
	require.NoError(t, err)
	require.Equal(t, combined, x.Response)
	require.Empty(t, x.Request)
	require.Equal(t, evidence.StateUnknown, x.ResponseState)
	x, err = tool.SelectHTTPReceipt(res.Transcript.Writes[0].Receipt.Ref)
	require.NoError(t, err)
	require.Equal(t, first, x.Request) // exact binary bytes despite JSON preview rendering
	x.Request[1] = 0
	x, err = tool.SelectHTTPReceipt(res.Transcript.Writes[0].Receipt.Ref)
	require.NoError(t, err)
	require.Equal(t, byte(255), x.Request[1])
	encoded, err := json.Marshal(res.Transcript)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "Content-Length") // manifest only
}

func TestRawHTTPCapsReportOmittedBytesForBothWindowsWithoutExtraRead(t *testing.T) {
	c := &receiptSocket{reads: []rawSocketRead{{data: []byte(strings.Repeat("a", 80))}, {data: []byte(strings.Repeat("b", 90))}}}
	tool := rawReceiptTool(c)
	res := tool.exchange(context.Background(), "example.invalid", 80, false, "", []byte("first"), []byte("second"), false, time.Second, time.Second, 16)
	require.Equal(t, []string{"write", "read", "write", "read"}, c.calls)
	require.True(t, res.ResponseTruncated)
	require.True(t, res.SecondResponseTruncated)
	require.Equal(t, 16, res.ResponseBytesTotal)
	require.Equal(t, 16, res.SecondResponseBytes)
	require.Equal(t, 170, res.ResponseBytesReadTotal)
	for i, read := range res.Transcript.Reads {
		require.Equal(t, []int{80, 90}[i], read.BytesRead)
		require.Equal(t, evidence.StateTruncated, read.State)
		require.Equal(t, "cap", read.Termination)
		x, err := tool.SelectHTTPReceipt(read.Receipt.Ref)
		require.NoError(t, err)
		require.Len(t, x.Response, 16)
		require.Equal(t, evidence.StateTruncated, x.ResponseState)
		require.Empty(t, x.Request)
	}
}

func TestRawHTTPClosedFirstWindowLeavesSecondWriteMissing(t *testing.T) {
	c := &receiptSocket{reads: []rawSocketRead{{data: []byte("closed"), err: io.EOF}}}
	tool := rawReceiptTool(c)
	res := tool.exchange(context.Background(), "example.invalid", 80, false, "", []byte("first"), []byte("second"), false, time.Second, time.Second, 1024)
	require.Contains(t, res.Error, "closed before second")
	require.Equal(t, 5, res.SentBytes)
	require.Equal(t, evidence.StateMissing, res.Transcript.Writes[1].State)
	require.Empty(t, res.SecondSentEcho)
	x, err := tool.SelectHTTPReceipt(res.Transcript.Writes[1].Receipt.Ref)
	require.NoError(t, err)
	require.Empty(t, x.Request)
}

func TestRawHTTPPartialSecondWritePreservesFirstAndSecondAcceptedPrefixes(t *testing.T) {
	c := &receiptSocket{writes: []rawSocketWrite{{n: 5}, {n: 2, err: errors.New("second write failed")}}}
	tool := rawReceiptTool(c)
	res := tool.exchange(context.Background(), "example.invalid", 80, false, "", []byte("first"), []byte("second"), true, time.Second, time.Second, 1024)
	require.Contains(t, res.Error, "second write failed")
	require.Equal(t, []string{"write", "write"}, c.calls)
	require.Equal(t, 7, res.SentBytes)
	require.Equal(t, 2, res.SecondSentBytes)
	require.Equal(t, "first", res.SentEcho)
	require.Equal(t, "se", res.SecondSentEcho)
	require.Empty(t, res.Transcript.Reads)
	for i, expected := range []string{"first", "se"} {
		x, err := tool.SelectHTTPReceipt(res.Transcript.Writes[i].Receipt.Ref)
		require.NoError(t, err)
		require.Equal(t, expected, string(x.Request))
		require.Equal(t, []evidence.State{evidence.StateComplete, evidence.StateTruncated}[i], x.RequestState)
		require.Empty(t, x.Response)
	}
}

func TestRawHTTPExactReadCapNeedsEOFToCompleteWindowAndNeverEstablishesPair(t *testing.T) {
	for _, readErr := range []error{nil, io.EOF} {
		t.Run("exact_cap", func(t *testing.T) {
			c := &receiptSocket{reads: []rawSocketRead{{data: []byte("12345678"), err: readErr}}}
			tool := rawReceiptTool(c)
			res := tool.exchange(context.Background(), "example.invalid", 80, false, "", []byte("first"), nil, false, time.Second, time.Second, 8)
			require.Equal(t, []string{"write", "read"}, c.calls) // never add a sentinel read
			require.Equal(t, 8, res.ResponseBytesReadTotal)
			read := res.Transcript.Reads[0]
			x, err := tool.SelectHTTPReceipt(read.Receipt.Ref)
			require.NoError(t, err)
			if readErr == nil {
				require.Equal(t, "cap", read.Termination)
				require.Equal(t, evidence.StateTruncated, read.State)
				require.Equal(t, evidence.StateTruncated, x.ResponseState)
				require.True(t, res.ResponseTruncated)
			} else {
				require.Equal(t, "eof", read.Termination)
				require.Equal(t, evidence.StateComplete, read.State)
				require.Equal(t, evidence.StateUnknown, x.ResponseState)
				require.False(t, res.ResponseTruncated)
			}
			require.Empty(t, x.Request)
			require.Equal(t, evidence.StateUnknown, res.Transcript.ResponseAttribution)
		})
	}
}

func TestRawHTTPTranscriptSelectionRefreshesExpiredReceiptAvailability(t *testing.T) {
	c := &receiptSocket{reads: []rawSocketRead{{data: []byte("response"), err: io.EOF}}}
	tool := rawReceiptTool(c)
	res := tool.exchange(context.Background(), "example.invalid", 80, false, "", []byte("request"), nil, false, time.Second, time.Second, 1024)
	for i := 0; i < 256; i++ {
		_, err := tool.RetainHTTPReceipt(evidence.NewExchange("http://example.invalid", "", nil, nil, evidence.ProvenanceCaptured), "socket_application_bytes")
		require.NoError(t, err)
	}
	selected, err := tool.SelectRawHTTPTranscript(res.Transcript.Ref)
	require.NoError(t, err) // metadata may outlive individual byte receipts
	require.False(t, selected.Writes[0].Receipt.Available)
	require.Equal(t, "expired", selected.Writes[0].Receipt.Availability)
	require.False(t, selected.Reads[0].Receipt.Available)
	require.Equal(t, "expired", selected.Reads[0].Receipt.Availability)
	for _, ref := range []string{selected.Writes[0].Receipt.Ref, selected.Reads[0].Receipt.Ref} {
		_, err := tool.SelectHTTPReceipt(ref)
		require.Error(t, err)
	}
}
