package bundle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/cbor"
)

var HeaderMagicBytes = []byte{0x84, 0x48, 0xf0, 0x9f, 0x8c, 0x90, 0xf0, 0x9f, 0x93, 0xa6}

type Bundle struct {
	Exchanges []*signedexchange.Exchange
}

var _ = io.WriterTo(&Bundle{})

// staging area for writing index section
type indexSection struct {
	mes   []*cbor.MapEntryEncoder
	bytes []byte
}

func (is *indexSection) addExchange(e *signedexchange.Exchange, offset, length int) error {
	me := cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
		if err := e.EncodeRequestWithHeaders(keyE); err != nil {
			panic(err) // fixme
		}
		if err := valueE.EncodeArrayHeader(2); err != nil {
			panic(err)
		}
		if err := valueE.EncodeUInt(uint64(offset)); err != nil {
			panic(err)
		}
		if err := valueE.EncodeUInt(uint64(length)); err != nil {
			panic(err)
		}
	})
	is.mes = append(is.mes, me)
	return nil
}

func (is *indexSection) Finalize() error {
	if is.bytes != nil {
		panic("indexSection must be Finalize()-d only once.")
	}

	var b bytes.Buffer
	enc := cbor.NewEncoder(&b)
	if err := enc.EncodeMap(is.mes); err != nil {
		return err
	}

	is.bytes = b.Bytes()
	return nil
}

func (is *indexSection) Len() int {
	if is.bytes == nil {
		panic("indexSection must be Finalize()-d before calling Len()")
	}
	return len(is.bytes)
}

func (is *indexSection) Bytes() []byte {
	if is.bytes == nil {
		panic("indexSection must be Finalize()-d before calling Bytes()")
	}
	return is.bytes
}

// staging area for writing responses section
type responsesSection struct {
	buf bytes.Buffer
}

func newResponsesSection(n int) *responsesSection {
	ret := &responsesSection{}

	enc := cbor.NewEncoder(&ret.buf)
	if err := enc.EncodeArrayHeader(n); err != nil {
		panic(err)
	}

	return ret
}

func (rs *responsesSection) addExchange(e *signedexchange.Exchange) (int, int, error) {
	offset := rs.buf.Len()

	var resHdrBuf bytes.Buffer
	if err := signedexchange.WriteResponseHeaders(&resHdrBuf, e); err != nil {
		return 0, 0, err
	}

	enc := cbor.NewEncoder(&rs.buf)
	if err := enc.EncodeArrayHeader(2); err != nil {
		return 0, 0, fmt.Errorf("bundle: failed to encode response array header: %v", err)
	}
	if err := enc.EncodeByteString(resHdrBuf.Bytes()); err != nil {
		return 0, 0, fmt.Errorf("bundle: failed to encode response header cbor bytestring: %v", err)
	}
	if err := enc.EncodeByteString(e.Payload()); err != nil {
		return 0, 0, fmt.Errorf("bundle: failed to encode response payload bytestring: %v", err)
	}

	length := rs.buf.Len() - offset
	return offset, length, nil
}

func (rs *responsesSection) Len() int      { return rs.buf.Len() }
func (rs *responsesSection) Bytes() []byte { return rs.buf.Bytes() }

func addExchange(is *indexSection, rs *responsesSection, e *signedexchange.Exchange) error {
	offset, length, err := rs.addExchange(e)
	if err != nil {
		return err
	}

	if err := is.addExchange(e, offset, length); err != nil {
		return err
	}
	return nil
}

type sectionOffset struct {
	Name   string
	Offset uint64
	Length uint64
}

type sectionOffsets []sectionOffset

func (so *sectionOffsets) AddSectionOrdered(name string, length uint64) {
	offset := uint64(0)
	if len(*so) > 0 {
		last := (*so)[len(*so)-1]
		offset = last.Offset + last.Length
	}
	*so = append(*so, sectionOffset{name, offset, length})
}

func (so *sectionOffsets) FindSection(name string) (sectionOffset, bool) {
	for _, e := range *so {
		if name == e.Name {
			return e, true
		}
	}
	return sectionOffset{}, false
}

// https://wicg.github.io/webpackage/draft-yasskin-dispatch-bundled-exchanges.html#load-metadata
// Steps 3-7.
func writeSectionOffsets(w io.Writer, so sectionOffsets) error {
	mes := []*cbor.MapEntryEncoder{}
	for _, e := range so {
		me := cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
			// TODO(kouhei): error plumbing
			keyE.EncodeTextString(e.Name)
			valueE.EncodeArrayHeader(2)
			valueE.EncodeUInt(uint64(e.Offset))
			valueE.EncodeUInt(uint64(e.Length))
		})

		mes = append(mes, me)
	}

	var b bytes.Buffer
	nestedEnc := cbor.NewEncoder(&b)
	if err := nestedEnc.EncodeMap(mes); err != nil {
		return err
	}

	enc := cbor.NewEncoder(w)
	if err := enc.EncodeByteString(b.Bytes()); err != nil {
		return err
	}
	return nil
}

func writeSectionHeader(w io.Writer, numSections int) error {
	enc := cbor.NewEncoder(w)
	return enc.EncodeArrayHeader(numSections)
}

func writeFooter(w io.Writer, offset int) error {
	const footerLength = 9

	bundleSize := uint64(offset) + footerLength

	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, bundleSize); err != nil {
		return err
	}
	if b.Len() != 8 {
		panic("assert")
	}

	enc := cbor.NewEncoder(w)
	if err := enc.EncodeByteString(b.Bytes()); err != nil {
		return err
	}
	return nil
}

type meta struct {
	sectionOffsets
	sectionsStart uint64
}

func decodeSectionOffsetsCBOR(bs []byte) (sectionOffsets, error) {
	// section-offsets = {* tstr => [ offset: uint, length: uint] },

	so := make(sectionOffsets, 0)
	dec := cbor.NewDecoder(bytes.NewBuffer(bs))

	n, err := dec.DecodeMapHeader()
	if err != nil {
		return nil, fmt.Errorf("bundle: Failed to decode sectionOffset map header: %v", err)
	}

	for i := uint64(0); i < n; i++ {
		name, err := dec.DecodeTextString()
		if err != nil {
			return nil, fmt.Errorf("bundle: Failed to decode sectionOffset map key: %v", err)
		}
		if _, exists := so.FindSection(name); exists {
			return nil, fmt.Errorf("bundle: Duplicated section in sectionOffset map: %q", name)
		}

		m, err := dec.DecodeArrayHeader()
		if err != nil {
			return nil, fmt.Errorf("bundle: Failed to decode sectionOffset map value: %v", err)
		}
		if m != 2 {
			return nil, fmt.Errorf("bundle: Failed to decode sectionOffset map value. Array of invalid length %d", m)
		}

		offset, err := dec.DecodeUInt()
		if err != nil {
			return nil, fmt.Errorf("bundle: Failed to decode sectionOffset[%q].offset: %v", name, err)
		}
		length, err := dec.DecodeUInt()
		if err != nil {
			return nil, fmt.Errorf("bundle: Failed to decode sectionOffset[%q].length: %v", name, err)
		}

		so = append(so, sectionOffset{Name: name, Offset: offset, Length: length})
	}

	return so, nil
}

// https://wicg.github.io/webpackage/draft-yasskin-dispatch-bundled-exchanges.html#index-section
func parseIndexSection(sectionContents []byte, sectionsStart uint64, sectionOffsets sectionOffsets, meta *meta) error {

}

var knownSections = map[string]struct{}{
	"index":     struct{}{},
	"responses": struct{}{},
}

// https://wicg.github.io/webpackage/draft-yasskin-dispatch-bundled-exchanges.html#load-metadata
func loadMetadata(bs []byte) (*meta, error) {
	// Step 1. Seek to offset 0 in stream. Assert: this operation doesn't fail.

	r := bytes.NewBuffer(bs)

	// Step 2. If reading 10 bytes from stream returns an error or doesn't return the bytes with hex encoding "84 48 F0 9F 8C 90 F0 9F 93 A6" (the CBOR encoding of the 4-item array initial byte and 8-byte bytestring initial byte, followed by 🌐📦 in UTF-8), return an error.
	magic := make([]byte, len(HeaderMagicBytes))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	if bytes.Compare(magic, HeaderMagicBytes) != 0 {
		return nil, errors.New("bundle: Header magic mismatch.")
	}

	// Step 3. Let sectionOffsetsLength be the result of getting the length of the CBOR bytestring header from stream (Section 3.4.2). If this is an error, return that error.
	// Step 4. If sectionOffsetsLength is TBD or greater, return an error.
	// TODO(kouhei): Not Implemented
	// Step 5. Let sectionOffsetsBytes be the result of reading sectionOffsetsLength bytes from stream. If sectionOffsetsBytes is an error, return that error.
	dec := cbor.NewDecoder(r)
	sobytes, err := dec.DecodeByteString()
	if err != nil {
		return nil, fmt.Errorf("bundle: Failed to read sectionOffset byte string: %v", err)
	}

	// Step 6. Let sectionOffsets be the result of parsing one CBOR item (Section 3.4) from sectionOffsetsBytes, matching the section-offsets rule in the CDDL ([I-D.ietf-cbor-cddl]) above. If sectionOffsets is an error, return an error.
	so, err := decodeSectionOffsetsCBOR(sobytes)
	if err != nil {
		return nil, err
	}

	// Step 7. Let sectionsStart be the current offset within stream. For example, if sectionOffsetsLength were 52, sectionsStart would be 64.
	sectionsStart := 12 + uint64(len(sobytes))

	// Step 8. Let knownSections be the subset of the Section 6.2 that this client has implemented.
	// Step 9. Let ignoredSections be an empty set.
	// Step 10. For each "name" key in sectionOffsets, if "name"'s specification in knownSections says not to process other sections, add those sections' names to ignoredSections.

	// Step 11. Let metadata be an empty map
	// Note: We use a struct rather than a map here.
	meta := &meta{
		sectionOffsets: so,
		sectionsStart:  sectionsStart,
	}

	// Step 12. For each "name"/[offset, length] triple in sectionOffsets:
	for _, e := range so {
		// Step 12.1. If "name" isn't in knownSections, continue to the next triple.
		if _, exists := knownSections[e.Name]; !exists {
			continue
		}
		// Step 12.2. If "name"’s Metadata field is "No", continue to the next triple.
		// Note: the "responses" section is currently the only section with its Metadata field "No".
		if e.Name == "responses" {
			continue
		}
		// Step 12.3. If "name" is in ignoredSections, continue to the next triple.
		// TODO

		// Step 12.4. Seek to offset sectionsStart + offset in stream. If this fails, return an error.
		offset := sectionsStart + e.Offset
		if uint64(len(bs)) <= offset {
			return nil, fmt.Errorf("bundle: section %q's computed offset %q out-of-range.", e.Name, offset)
		}
		end := offset + e.Length
		if uint64(len(bs)) <= end {
			return nil, fmt.Errorf("bundle: section %q's end %q out-of-range.", e.Name, end)
		}

		// Step 12.5. Let sectionContents be the result of reading length bytes from stream. If sectionContents is an error, return that error.
		sectionContents := bs[offset:end]

		// Step 12.6. Follow "name"'s specification from knownSections to process the section, passing sectionContents, stream, sectionOffsets, sectionsStart, and metadata. If this returns an error, return it.
		switch e.Name {
		case "index":
			if err := parseIndexSection(sectionContents, sectionsStart, so, meta); err != nil {
				return nil, err
			}
		case "responses":
			// FIXME
		default:
			panic("aaa")
		}
	}

	// Step 13. If metadata doesn't have entries with keys "requests" and "manifest", return an error.

	// Step 14. Return metadata.
	return meta, nil
}

func Read(r io.Reader) (*Bundle, error) {
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	m, err := loadMetadata(bytes)
	if err != nil {
		return nil, err
	}

	log.Printf("meta: %+v", m)

	b := &Bundle{}
	return b, nil
}

func (b *Bundle) WriteTo(w io.Writer) (int64, error) {
	cw := NewCountingWriter(w)

	is := &indexSection{}
	rs := newResponsesSection(len(b.Exchanges))

	for _, e := range b.Exchanges {
		if err := addExchange(is, rs, e); err != nil {
			return cw.Written, err
		}
	}
	if err := is.Finalize(); err != nil {
		return cw.Written, err
	}

	var so sectionOffsets
	so.AddSectionOrdered("index", uint64(is.Len()))
	so.AddSectionOrdered("responses", uint64(rs.Len()))

	if _, err := cw.Write(HeaderMagicBytes); err != nil {
		return cw.Written, err
	}
	if err := writeSectionOffsets(cw, so); err != nil {
		return cw.Written, err
	}
	if err := writeSectionHeader(cw, len(so)); err != nil {
		return cw.Written, err
	}
	if _, err := cw.Write(is.Bytes()); err != nil {
		return cw.Written, err
	}
	if _, err := cw.Write(rs.Bytes()); err != nil {
		return cw.Written, err
	}
	if err := writeFooter(cw, int(cw.Written)); err != nil {
		return cw.Written, err
	}

	return cw.Written, nil
}
