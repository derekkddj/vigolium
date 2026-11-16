// Package planting validates declared OAST slots in captured request bytes.
// It never sends requests, reconstructs messages, or synthesizes a decoded nonce.
package planting

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func NonceByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func PercentByte(raw []byte) (byte, bool) {
	if len(raw) != 3 || raw[0] != '%' {
		return 0, false
	}
	var decoded [1]byte
	_, err := hex.Decode(decoded[:], raw[1:])
	return decoded[0], err == nil
}

// TokenBounds recognizes literal nonce bytes next to an encoded separator,
// never encoded alphanumeric adjacency (%41nonce or nonce%41).
func TokenBounds(raw []byte, start, end int) bool {
	if start > 0 && NonceByte(raw[start-1]) {
		if start < 3 {
			return false
		}
		b, ok := PercentByte(raw[start-3 : start])
		if !ok || NonceByte(b) {
			return false
		}
	}
	if end < len(raw) {
		if NonceByte(raw[end]) {
			return false
		}
		if end+3 <= len(raw) {
			if b, ok := PercentByte(raw[end : end+3]); ok && NonceByte(b) {
				return false
			}
		}
	}
	return true
}

func ContainsNonceToken(raw []byte, nonce string) bool {
	if nonce == "" {
		return false
	}
	needle := []byte(nonce)
	for off := 0; off < len(raw); {
		i := bytes.Index(raw[off:], needle)
		if i < 0 {
			return false
		}
		i += off
		end := i + len(needle)
		if TokenBounds(raw, i, end) {
			return true
		}
		off = i + 1
	}
	return false
}

// WalkNonceTokens visits complete, bounded literal alphanumeric runs. An encoded
// separator may precede the token, but nonce characters are never decoded and
// substrings of larger runs are never returned. Only candidate tokens allocate.
func WalkNonceTokens(raw []byte, visit func(string)) {
	for off := 0; off < len(raw); {
		if !NonceByte(raw[off]) {
			off++
			continue
		}
		start := off
		for off < len(raw) && NonceByte(raw[off]) {
			off++
		}
		end := off
		if start > 0 && end-start >= 2 {
			if b, ok := PercentByte(raw[start-1 : start+2]); ok && !NonceByte(b) {
				start += 2
			}
		}
		if end-start >= 20 && end-start <= 128 && TokenBounds(raw, start, end) {
			visit(string(raw[start:end]))
		}
	}
}

// MatchesSlot checks only the declared field. Header is supplied from explicit
// mint context, never guessed from a header containing the nonce. Query/form
// values are decoded exactly once for comparison; captured bytes stay unchanged.
func MatchesSlot(raw []byte, nonce, name, payload string, header bool) bool {
	matches := func(value []byte) bool {
		return ContainsNonceToken(value, nonce) && (payload == "" || bytes.Contains(value, []byte(payload)))
	}
	switch {
	case strings.EqualFold(name, "request-line"):
		line, _, _ := bytes.Cut(raw, []byte("\n"))
		return matches(line)
	case header:
		req := httpmsg.NewHttpRequest(raw)
		return req != nil && matches([]byte(req.Header(name)))
	case strings.EqualFold(name, "body") || strings.EqualFold(name, "request-body"):
		_, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
		if !ok {
			_, body, ok = bytes.Cut(raw, []byte("\n\n"))
		}
		return ok && matches(body)
	case name != "":
		info, err := httpmsg.AnalyzeRequest(raw)
		if err != nil || info == nil {
			return false
		}
		for _, param := range info.Parameters {
			if param == nil || param.Name() != name {
				continue
			}
			start, end := param.ValueStart(), param.ValueEnd()
			if start < 0 || end <= start || end > len(raw) {
				continue
			}
			// Param.Value()/InsertionPoint.BaseValue() are decoded display
			// values. Only the declared field's ORIGINAL byte span can certify
			// a literal nonce; never borrow one from a Referer or another field.
			value := raw[start:end]
			if !ContainsNonceToken(value, nonce) {
				continue
			}
			switch param.Type() {
			case httpmsg.ParamURL, httpmsg.ParamBody:
				// Decode precisely one query/form layer, from the captured span,
				// only after the literal-token check in that same span succeeds.
				decoded, err := url.QueryUnescape(string(value))
				if err != nil {
					continue
				}
				if matches([]byte(decoded)) {
					return true
				}
			case httpmsg.ParamJSON:
				// Keep captured JSON escaped. Encode only expected intent for
				// comparison, never decode or substitute the captured value.
				encoded, err := json.Marshal(payload)
				if err == nil && (payload == "" || bytes.Contains(value, encoded[1:len(encoded)-1])) {
					return true
				}
			case httpmsg.ParamCookie, httpmsg.ParamXML, httpmsg.ParamXMLAttr,
				httpmsg.ParamMultipartAttr, httpmsg.ParamBodyMultipart:
				if matches(value) {
					return true
				}
			}
		}
	}
	return false
}
