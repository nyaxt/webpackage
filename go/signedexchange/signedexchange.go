package signedexchange

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

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

func encodeCanonicalResponseHeader(e *cbor.Encoder, i *Input) error {
	mes := make([]*cbor.MapEntryEncoder, 0, len(i.ResponseHeaders)+1)
	mes = append(mes,
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeByteString([]byte(":status"))
			valueE.EncodeByteString([]byte(strconv.Itoa(i.ResponseStatus)))
		}))
	for _, rh := range i.ResponseHeaders {
		mes = append(mes,
			cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
				keyE.EncodeByteString([]byte(strings.ToLower(rh.Name)))
				valueE.EncodeByteString([]byte(rh.Value))
			}))
	}

	return e.EncodeMap(mes)
}

func WriteCanonicalExchangeHeaders(w io.Writer, i *Input) error {
	e := &cbor.Encoder{w}
	if err := e.EncodeArrayHeader(2); err != nil {
		return fmt.Errorf("Failed to encode top-level array header: %v", err)
	}
	if err := encodeCanonicalRequest(e, i); err != nil {
		return err
	}
	if err := encodeCanonicalResponseHeader(e, i); err != nil {
		return err
	}
	return nil
}
