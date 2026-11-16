package jsext

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/jsext/api/parse"
)

// httpAuthTestFuncDefs returns JSFuncDefs for vigolium.http.authTest.
func httpAuthTestFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsHTTP, Name: "authTest",
			Effect:   EffectNetwork,
			Category: CatHTTP, Signature: ".authTest(opts)", Returns: "AuthTestResult[]",
			Description: "Test authorization by replaying requests with different sessions to detect IDOR/BOLA vulnerabilities.",
			Example:     `var results = vigolium.http.authTest({sessions: [adminSess, userSess], records: [record1, record2]})`,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				httpClient := opts.HTTPClient
				return func(call sobek.FunctionCall) sobek.Value {
					optsVal := call.Argument(0)
					if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
						return vm.NewArray()
					}
					o := optsVal.ToObject(vm)

					// Parse sessions array
					sessionsVal := o.Get("sessions")
					if sessionsVal == nil || sobek.IsUndefined(sessionsVal) || sobek.IsNull(sessionsVal) {
						return vm.NewArray()
					}
					sessionsArr := sessionsVal.ToObject(vm)
					numSessions := int(sessionsArr.Get("length").ToInteger())
					if numSessions == 0 {
						return vm.NewArray()
					}

					// Each session is a JS object with get/post/request/send + a label
					type sessionEntry struct {
						obj   *sobek.Object
						label string
					}
					sessions := make([]sessionEntry, numSessions)
					for i := range numSessions {
						sObj := sessionsArr.Get(fmt.Sprintf("%d", i)).ToObject(vm)

						label := fmt.Sprintf("session_%d", i)
						if v := sObj.Get("label"); v != nil && !sobek.IsUndefined(v) {
							label = v.String()
						}
						sessions[i] = sessionEntry{obj: sObj, label: label}
					}

					// Parse records - can be string UUIDs or objects with raw request
					recordsVal := o.Get("records")
					if recordsVal == nil || sobek.IsUndefined(recordsVal) || sobek.IsNull(recordsVal) {
						return vm.NewArray()
					}
					recordsArr := recordsVal.ToObject(vm)
					numRecords := int(recordsArr.Get("length").ToInteger())
					if numRecords == 0 {
						return vm.NewArray()
					}

					// Parse method - replay (default) or swap
					method := "replay"
					if v := o.Get("method"); v != nil && !sobek.IsUndefined(v) {
						method = v.String()
					}
					_ = method // swap mode is a future enhancement

					// Build raw requests from records
					type recordInfo struct {
						uuid   string
						url    string
						rawReq string
					}
					records := make([]recordInfo, 0, numRecords)
					for i := range numRecords {
						item := recordsArr.Get(fmt.Sprintf("%d", i))
						if sobek.IsUndefined(item) || sobek.IsNull(item) {
							continue
						}

						itemStr := item.String()
						itemObj := item.ToObject(vm)

						// Check if it's a string (UUID) or object (DBRecord with request data)
						uuid := ""
						rawReq := ""
						recordURL := ""

						if v := itemObj.Get("uuid"); v != nil && !sobek.IsUndefined(v) {
							uuid = v.String()
						} else {
							uuid = itemStr
						}

						if v := itemObj.Get("url"); v != nil && !sobek.IsUndefined(v) {
							recordURL = v.String()
						}

						// Try to get raw request from the record
						if v := itemObj.Get("request"); v != nil && !sobek.IsUndefined(v) {
							rawReq = v.String()
						} else if v := itemObj.Get("raw_request"); v != nil && !sobek.IsUndefined(v) {
							rawReq = v.String()
						}

						// Build request from record fields if no raw request
						if rawReq == "" && recordURL != "" {
							reqMethod := "GET"
							if v := itemObj.Get("method"); v != nil && !sobek.IsUndefined(v) {
								reqMethod = v.String()
							}
							var sb strings.Builder
							host := extractHost(recordURL)
							fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", reqMethod, recordURL, host)
							rawReq = sb.String()
						}

						if rawReq != "" {
							if recordURL == "" {
								recordURL = extractURLFromRaw(rawReq)
							}
							records = append(records, recordInfo{uuid: uuid, url: recordURL, rawReq: rawReq})
						}
					}

					if len(records) == 0 {
						return vm.NewArray()
					}

					// For each record, replay with each session and collect results
					results := make([]interface{}, len(records))

					for ri, rec := range records {
						// Get original response first (send without auth modification)
						origResp := doRawRequestBytes(httpClient, rec.rawReq)
						origBody := ""
						origStatus := 0
						var original sobek.Value = sobek.Undefined()
						if !origResp.err && len(origResp.raw) > 0 {
							builtResp := buildResponseObject(vm, origResp.raw, origResp.elapsed, origResp.exchange)
							original = builtResp
							if !sobek.IsUndefined(builtResp) {
								respObj := builtResp.ToObject(vm)
								if v := respObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
									origBody = v.String()
								}
								if v := respObj.Get("status"); v != nil && !sobek.IsUndefined(v) {
									origStatus = int(v.ToInteger())
								}
							}
						}

						// Like sessionPool.broadcast, all session JS calls happen on the
						// VM thread. Workers only send prepared Go requests into owned slots.
						preparedReqs := make([]string, numSessions)
						for si, sess := range sessions {
							preparedReqs[si] = injectSessionHeaders(vm, rec.rawReq, sess.obj)
						}
						sessionResponses := make([]respSlot, numSessions)
						var wg sync.WaitGroup
						for si, rawReq := range preparedReqs {
							wg.Add(1)
							go func(idx int, raw string) {
								defer wg.Done()
								sessionResponses[idx] = doRawRequestBytes(httpClient, raw)
							}(si, rawReq)
						}
						wg.Wait()

						// Build response objects and register invocation receipts only
						// after workers finish, back on the VM thread.
						sessResultsJS := make([]interface{}, numSessions)
						accessibleCount := 0
						for si, resp := range sessionResponses {
							var response sobek.Value = sobek.Undefined()
							respStatus := 0
							respBody := ""
							sim := 0.0
							accessible := false
							if !resp.err {
								response = buildResponseObject(vm, resp.raw, resp.elapsed, resp.exchange)
								if !sobek.IsUndefined(response) {
									respObj := response.ToObject(vm)
									if v := respObj.Get("status"); v != nil && !sobek.IsUndefined(v) {
										respStatus = int(v.ToInteger())
									}
									if v := respObj.Get("body"); v != nil && !sobek.IsUndefined(v) {
										respBody = v.String()
									}
								}
								sim = jaccardSimilarity(origBody, respBody)
								// Same heuristic and summary fields as before; selection
								// remains the script's explicit decision, not this score.
								if origStatus > 0 && respStatus > 0 {
									accessible = (origStatus/100) == (respStatus/100) && sim > 0.8
								}
							}
							sessResultsJS[si] = map[string]interface{}{
								"session_label":   sessions[si].label,
								"status":          respStatus,
								"body_similarity": sim,
								"accessible":      accessible,
								"response":        response,
							}
							if accessible {
								accessibleCount++
							}
						}

						// Determine vulnerability type and confidence
						vuln := "none"
						confidence := 0.0
						if accessibleCount > 0 && accessibleCount < numSessions {
							// Some sessions can access, some can't — potential IDOR
							vuln = "idor"
							confidence = float64(accessibleCount) / float64(numSessions)
						} else if accessibleCount == numSessions {
							// All sessions can access — could be BOLA if sessions have different privilege levels
							vuln = "bola"
							confidence = 0.5 // moderate — might be a public endpoint
						}

						results[ri] = map[string]interface{}{
							"original":      original,
							"record_uuid":   rec.uuid,
							"url":           rec.url,
							"results":       sessResultsJS,
							"vulnerability": vuln,
							"confidence":    confidence,
						}
					}

					return vm.ToValue(results)
				}
			},
		},
	}
}

// injectSessionHeaders extracts headers from a session JS object and injects them into a raw request.
func injectSessionHeaders(vm *sobek.Runtime, rawReq string, sessObj *sobek.Object) string {
	// Call getHeaders() on the session
	getHeadersFn, ok := sobek.AssertFunction(sessObj.Get("getHeaders"))
	if !ok {
		return rawReq
	}

	headersVal, err := getHeadersFn(sessObj)
	if err != nil || sobek.IsUndefined(headersVal) || sobek.IsNull(headersVal) {
		return rawReq
	}

	headersObj := headersVal.ToObject(vm)
	keys := headersObj.Keys()
	if len(keys) == 0 {
		return rawReq
	}

	// Parse existing request
	headerSection, body := parse.SplitHTTPMessage(rawReq)
	lines := parse.SplitHeaderLines(headerSection)
	if len(lines) == 0 {
		return rawReq
	}

	// Build header map from session (case-insensitive override)
	overrides := make(map[string]string, len(keys))
	for _, key := range keys {
		overrides[strings.ToLower(key)] = headersObj.Get(key).String()
	}
	overrideOrigKeys := make(map[string]string, len(keys))
	for _, key := range keys {
		overrideOrigKeys[strings.ToLower(key)] = key
	}

	var sb strings.Builder
	sb.WriteString(lines[0])
	sb.WriteString("\r\n")

	applied := make(map[string]bool)
	for _, line := range lines[1:] {
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			lower := strings.ToLower(name)
			if val, ok := overrides[lower]; ok {
				fmt.Fprintf(&sb, "%s: %s\r\n", name, val)
				applied[lower] = true
				continue
			}
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}

	// Add new headers that weren't in the original request
	for _, key := range keys {
		lower := strings.ToLower(key)
		if !applied[lower] && !strings.EqualFold(key, "host") {
			fmt.Fprintf(&sb, "%s: %s\r\n", key, headersObj.Get(key).String())
		}
	}

	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// jaccardSimilarity computes word-level Jaccard similarity between two strings.
func jaccardSimilarity(a, b string) float64 {
	wordRe := regexp.MustCompile(`\w+`)
	tokensA := wordRe.FindAllString(a, -1)
	tokensB := wordRe.FindAllString(b, -1)

	setA := make(map[string]bool, len(tokensA))
	for _, t := range tokensA {
		setA[strings.ToLower(t)] = true
	}
	setB := make(map[string]bool, len(tokensB))
	for _, t := range tokensB {
		setB[strings.ToLower(t)] = true
	}

	intersection := 0
	for t := range setA {
		if setB[t] {
			intersection++
		}
	}

	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}
