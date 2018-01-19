package signedexchange

import (
	"fmt"
	"io"
	"net/url"
	"sort"

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

type headersSorter []ResponseHeader

var _ = sort.Interface(headersSorter{})

func (s headersSorter) Len() int           { return len(s) }
func (s headersSorter) Less(i, j int) bool { return s[i].Name < s[j].Name }
func (s headersSorter) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type requestE struct {
	_struct bool `codec:",toarray"`

	MethodTag []byte
	Method    []byte
	UrlTag    []byte
	Url       []byte
}

func encodeRequest(e cbor.Encoder, i *Input) error {
	mes := []cbor.MapEntryEncoder{
		GenerateMapEntry(func(keyE Encoder, valueE Encoder) {
			keyE.EncodeByteString([]byte(":method"))
			valueE.EncodeByteString([]byte("GET"))
		}),
		GenerateMapEntry(func(keyE Encoder, valueE Encoder) {
			keyE.EncodeByteString([]byte(":method"))
			valueE.EncodeByteString([]byte("GET"))
		}),
	}
	sort.Sort(cbor.MapEntryEncoderSorter(mes))
}

func WriteExchange(w io.Writer, i *Input) error {
	sort.Sort(headersSorter(i.ResponseHeaders))

	statusStr := fmt.Sprintf("%03d", i.ResponseStatus)

	e := &cbor.Encoder{w}
	if err := e.EncodeArrayHeader(6); err != nil {
		return fmt.Errorf("Failed to encode top-level array header: %v", err)
	}
	if err := e.EncodeTextString("request"); err != nil {
		return fmt.Errorf("Failed to encode top-level array item \"request\": %v", err)
	}
	if err := encodeRequest(e, i); err != nil {
		return err
	}
	if err := e.EncodeTextString("response"); err != nil {
		return fmt.Errorf("Failed to encode top-level array item \"request\": %v", err)
	}
	if err := encodeResponseHeader(w, i); err != nil {
		return err
	}
	if err := e.EncodeTextString("payload"); err != nil {
		return fmt.Errorf("Failed to encode top-level array item \"request\": %v", err)
	}
	if err := e.EncodeByteString(i.Payload); err != nil {
		return fmt.Errorf("Failed to encode payload: %v", err)
	}

	respary := [][]byte{
		[]byte(statusStr),
	}
	for _, rh := range i.ResponseHeaders {
		respary = append(respary, []byte(rh.Name), []byte(rh.Value))
	}

	exc := &exchangeE{
		Request: &requestE{
			MethodTag: []byte(":method"),
			Method:    []byte("GET"),
			UrlTag:    []byte(":url"),
			Url:       []byte(i.RequestUri.String()),
		},
		ResponseArray: respary,
	}
	return nil
}
