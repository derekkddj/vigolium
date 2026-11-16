package aem_xss

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

func TestBrowserConfirmationMissingCaptureIsSeparateFromHTTPReflection(t *testing.T) {
	srv := mergeMetadataServer(t, false)
	m := New()
	var browserURL string
	m.Probe = func(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		browserURL = cfg.URL
		decoded, err := url.QueryUnescape(cfg.URL)
		require.NoError(t, err)
		return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: markerFromURL(decoded)}}}, nil
	}
	var selectedSink *sink
	for i := range sinks {
		if strings.Contains(sinks[i].build("test"), "/libs/dam/merge/metadata.html") {
			selectedSink = &sinks[i]
			break
		}
	}
	require.NotNil(t, selectedSink)
	result := m.probeSink(modtest.Request(t, srv.URL), modtest.Requester(t), *selectedSink, srv.URL)
	require.NotNil(t, result)
	require.Equal(t, "missing", result.Metadata["browser_confirmation_capture"])
	require.Equal(t, "ProbeURL exposes dialogs, not raw HTTP exchanges", result.Metadata["browser_confirmation_capture_reason"])
	require.Len(t, result.Evidence, reflectRounds)
	primary, err := httpmsg.FromEvidenceExchange(result.Evidence[0].Exchange)
	require.NoError(t, err)
	require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	decodedPath, err := url.QueryUnescape(primary.Request().Path())
	require.NoError(t, err)
	require.Contains(t, decodedPath, result.Payload)
	require.Contains(t, result.Response, result.Payload)
	browserPath, err := url.Parse(browserURL)
	require.NoError(t, err)
	require.NotEqual(t, primary.Request().Path(), browserPath.RequestURI(), "fresh browser marker must not be spliced into the HTTP reflection receipt")
}
