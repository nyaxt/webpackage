package bundle

import (
	"github.com/WICG/webpackage/go/signedexchange"
)

var HeaderMagicBytes = []byte{0x84, 0x48, 0xf0, 0x9f, 0x8c, 0x90, 0xf0, 0x9f, 0x93, 0xa6}

type Input struct {
	exchanges []signedexchange.Exchange
}

func WriteBundle(w io.Writer, i *Input) error {
	responsesSection := NewResponsesSection()

	responsesSection

	sections := []*Section{}
	indexSection := NewIndexSection()
	sections = append(sections, indexSection)

	if _, err := w.Write(HeaderMagicBytes); err != nil {
		return err
	}

}
