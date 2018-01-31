package signedexchange

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/WICG/webpackage/go/signedexchange/cbor"
	"github.com/WICG/webpackage/go/signedexchange/mice"
)

type Input struct {
	// Request
	RequestUri *url.URL

	// Response
	ResponseStatus int
	ResponseHeader http.Header

	// Payload
	Payload []byte
}

func NewInput(uri *url.URL, status int, headers http.Header, payload []byte, miRecordSize int) (*Input, error) {
	i := &Input{
		RequestUri:     uri,
		ResponseStatus: status,
		ResponseHeader: headers,
		Payload:        payload,
	}
	if err := i.miEncode(miRecordSize); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *Input) miEncode(recordSize int) error {
	var buf bytes.Buffer
	mi, err := mice.Encode(&buf, i.Payload, recordSize)
	if err != nil {
		return err
	}
	i.Payload = buf.Bytes()
	i.ResponseHeader.Add("Content-Encoding", "mi-sha256")
	i.ResponseHeader.Add("MI", mi)
	return nil
}

// AddSignedHeaderHeader adds 'signed-headers' header to the response.
//
// Signed-Headers is a Structured Header as defined by
// [I-D.ietf-httpbis-header-structure]. Its value MUST be a list (Section 4.8
// of [I-D.ietf-httpbis-header-structure]) of lowercase strings (Section 4.2 of
// [I-D.ietf-httpbis-header-structure]) naming HTTP response header fields.
// Pseudo-header field names (Section 8.1.2.1 of [RFC7540]) MUST NOT appear in
// this list.
func (i *Input) AddSignedHeadersHeader(ks ...string) {
	strs := []string{}
	for _, k := range ks {
		strs = append(strs, fmt.Sprintf(`"%s"`, strings.ToLower(k)))
	}
	s := strings.Join(strs, ", ")
	i.ResponseHeader.Add("signed-headers", s)
}

func (i *Input) parseSignedHeadersHeader() []string {
	unparsed := i.ResponseHeader.Get("signed-headers")

	rawks := strings.Split(unparsed, ",")
	ks := make([]string, 0, len(rawks))
	for _, k := range rawks {
		k = strings.TrimPrefix(k, "\"")
		k = strings.TrimSuffix(k, "\"")
		ks = append(ks, k)
	}
	return ks
}

func encodeCanonicalRequest(e *cbor.Encoder, i *Input) error {
	mes := []*cbor.MapEntryEncoder{
		cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
			keyE.EncodeByteString([]byte(":method"))
			valueE.EncodeByteString([]byte("GET"))
		}),
		cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
			keyE.EncodeByteString([]byte(":url"))
			valueE.EncodeByteString([]byte(i.RequestUri.String()))
		}),
	}
	return e.EncodeMap(mes)
}

func encodeResponseHeader(e *cbor.Encoder, i *Input, filter func(string) bool) error {
	mes := []*cbor.MapEntryEncoder{
		cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
			keyE.EncodeByteString([]byte(":status"))
			valueE.EncodeByteString([]byte(strconv.Itoa(i.ResponseStatus)))
		}),
	}
	for name, value := range i.ResponseHeader {
		if !filter(name) {
			continue
		}

		mes = append(mes,
			cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
				keyE.EncodeByteString([]byte(strings.ToLower(name)))
				valueE.EncodeByteString([]byte(value[0]))
			}))
	}
	return e.EncodeMap(mes)
}

func allKeys(string) bool { return true }

// Write draft-yasskin-http-origin-signed-responses.html#rfc.section.3.4
func encodeCanonicalExchangeHeaders(e *cbor.Encoder, i *Input) error {
	if err := e.EncodeArrayHeader(2); err != nil {
		return fmt.Errorf("signedexchange: failed to encode top-level array header: %v", err)
	}
	if err := encodeCanonicalRequest(e, i); err != nil {
		return err
	}

	// Only encode response headers which are specified in "signed-headers" header.
	ks := i.parseSignedHeadersHeader()
	m := map[string]bool{}
	for _, k := range ks {
		m[k] = true
	}
	hf := func(k string) bool { return m[k] }
	if err := encodeResponseHeader(e, i, hf); err != nil {
		return err
	}
	return nil
}

// Write draft-yasskin-http-origin-signed-responses.html#application-http-exchange
func WriteExchangeFile(w io.Writer, i *Input) error {
	e := cbor.NewEncoder(w)
	if err := e.EncodeArrayHeader(7); err != nil {
		return err
	}
	if err := e.EncodeTextString("htxg"); err != nil {
		return err
	}

	if err := e.EncodeTextString("request"); err != nil {
		return err
	}
	// FIXME: This may diverge in future.
	if err := encodeCanonicalRequest(e, i); err != nil {
		return err
	}

	// FIXME: Support "request payload"

	if err := e.EncodeTextString("response"); err != nil {
		return err
	}
	if err := encodeResponseHeader(e, i, allKeys); err != nil {
		return err
	}

	if err := e.EncodeTextString("payload"); err != nil {
		return err
	}
	if err := e.EncodeByteString(i.Payload); err != nil {
		return err
	}

	// FIXME: Support "trailer"

	return nil
}
