package signedexchange

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/WICG/webpackage/go/signedexchange/cbor"
)

type ResponseHeader struct {
	Name  string
	Value string
}

type Input struct {
	// * Request
	RequestUri *url.URL

	// * Response
	ResponseStatus  int
	ResponseHeaders []ResponseHeader

	// * Payload
	Payload []byte

	Date    time.Time
	Expires time.Time
}

func (i *Input) AddSignedHeadersHeader(ks []string) {
	/*
	  Signed-Headers is a Structured Header as defined by [I-D.ietf-httpbis-header-structure]. Its value MUST be a list (Section 4.8 of [I-D.ietf-httpbis-header-structure]) of lowercase strings (Section 4.2 of [I-D.ietf-httpbis-header-structure]) naming HTTP response header fields. Pseudo-header field names (Section 8.1.2.1 of [RFC7540]) MUST NOT appear in this list.
	*/
	s := ""
	for _, k := range ks {
		s += fmt.Sprintf("\"%s\", ", strings.ToLower(k))
	}
	// omit last ", "
	s = s[:len(s)-2]

	i.ResponseHeaders = append(i.ResponseHeaders, ResponseHeader{
		Name:  "signed-headers",
		Value: s,
	})
}

func (i *Input) ResponseHeaderValue(k string) string {
	k = strings.ToLower(k)
	for _, rh := range i.ResponseHeaders {
		if strings.ToLower(rh.Name) == k {
			return rh.Value
		}
	}

	return ""
}

func (i *Input) ParseSignedHeadersHeader() []string {
	unparsed := i.ResponseHeaderValue("signed-headers")

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
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeByteString([]byte(":method"))
			valueE.EncodeByteString([]byte("GET"))
		}),
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeByteString([]byte(":url"))
			valueE.EncodeByteString([]byte(i.RequestUri.String()))
		}),
	}
	sort.Sort(cbor.MapEntryEncoderSorter(mes))

	return e.EncodeMap(mes)
}

func encodeResponseHeader(e *cbor.Encoder, i *Input, filter func(string) bool) error {
	mes := make([]*cbor.MapEntryEncoder, 0, len(i.ResponseHeaders)+1)
	mes = append(mes,
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeByteString([]byte(":status"))
			valueE.EncodeByteString([]byte(strconv.Itoa(i.ResponseStatus)))
		}))
	for _, rh := range i.ResponseHeaders {
		if !filter(rh.Name) {
			continue
		}

		mes = append(mes,
			cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
				keyE.EncodeByteString([]byte(strings.ToLower(rh.Name)))
				valueE.EncodeByteString([]byte(rh.Value))
			}))
	}

	return e.EncodeMap(mes)
}

func allKeys(string) bool { return true }

// Write draft-yasskin-http-origin-signed-responses.html#rfc.section.3.4
func encodeCanonicalExchangeHeaders(e *cbor.Encoder, i *Input) error {
	if err := e.EncodeArrayHeader(2); err != nil {
		return fmt.Errorf("Failed to encode top-level array header: %v", err)
	}
	if err := encodeCanonicalRequest(e, i); err != nil {
		return err
	}

	// Only encode response headers which are specified in "signed-headers" header.
	ks := i.ParseSignedHeadersHeader()
	m := make(map[string]bool)
	for _, k := range ks {
		m[k] = true
	}
	hf := func(k string) bool { return m[k] }
	if err := encodeResponseHeader(e, i, hf); err != nil {
		return err
	}
	return nil
}

func SerializeSignedMessage(i *Input) ([]byte, error) {
	/*
	  "Let message be the concatenation of the following byte strings. This matches the [I-D.ietf-tls-tls13] format to avoid cross-protocol attacks when TLS certificates are used to sign manifests." [spec text]
	*/

	var buf bytes.Buffer

	// "1. A string that consists of octet 32 (0x20) repeated 64 times." [spec text]
	for i := 0; i < 64; i++ {
		buf.WriteByte(0x20)
	}

	// "2. A context string: the ASCII encoding of "HTTP Exchange"." [spec text]
	buf.WriteString("HTTP Exchange")

	// "3. A single 0 byte which serves as a separator." [spec text]
	buf.WriteByte(0)

	// "4. The bytes of the canonical CBOR serialization (Section 3.5) of a CBOR map mapping:" [spec text]
	mes := make([]*cbor.MapEntryEncoder, 0, 4)

	// "4.1. If certSha256 is set: The text string "certSha256" to the byte string certSha256." [spec text]
	certSha256 := []byte("FIXMEFIXME")
	mes = append(mes,
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeTextString("certSha256")
			valueE.EncodeByteString(certSha256)
		}))

	mes = append(mes,
		// "4.2. The text string "date" to the integer value of date." [spec text]
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeTextString("date")
			valueE.EncodeInt(i.Date.Unix())
		}),
		// "4.3. The text string "expires" to the integer value of expires." [spec text]
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeTextString("expires")
			valueE.EncodeInt(i.Expires.Unix())
		}),
	)

	// "4.4. The text string "headers" to the CBOR representation (Section 3.4) of exchange's headers."
	meHeaders := cbor.NewMapEntry()
	meHeaders.KeyE.EncodeTextString("headers")
	if err := encodeCanonicalExchangeHeaders(&meHeaders.ValueE, i); err != nil {
		return nil, err
	}
	mes = append(mes, meHeaders)

	e := &cbor.Encoder{&buf}
	if err := e.EncodeMap(mes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Write draft-yasskin-http-origin-signed-responses.html#application-http-exchange
func WriteExchangeFile(w io.Writer, i *Input) error {
	e := &cbor.Encoder{w}
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
