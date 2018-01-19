package signedexchange

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/WICG/webpackage/go/signedexchange/cbor"
)

type Signer struct {
	Date    time.Time
	Expires time.Time
	Certs   []*x509.Certificate
	CertUrl *url.URL
	PrivKey crypto.PrivateKey
}

func (s *Signer) certSha256() []byte {
	// Binary content (Section 4.5 of [I-D.ietf-httpbis-header-structure])
	// holding the SHA-256 hash of the first certificate found at "certUrl".
	if len(s.Certs) == 0 {
		return nil
	}

	c := s.Certs[0]
	sum := sha256.Sum256(c.Raw)
	return sum[:]
}

func (s *Signer) serializeSignedMessage(i *Input) ([]byte, error) {
	// "Let message be the concatenation of the following byte strings.
	// This matches the [I-D.ietf-tls-tls13] format to avoid cross-protocol
	// attacks when TLS certificates are used to sign manifests." [spec text]
	var buf bytes.Buffer

	// "1. A string that consists of octet 32 (0x20) repeated 64 times." [spec text]
	for i := 0; i < 64; i++ {
		buf.WriteByte(0x20)
	}

	// "2. A context string: the ASCII encoding of "HTTP Exchange"." [spec text]
	buf.WriteString("HTTP Exchange")

	// "3. A single 0 byte which serves as a separator." [spec text]
	buf.WriteByte(0)

	// "4. The bytes of the canonical CBOR serialization (Section 3.5) of a CBOR map
	// mapping:" [spec text]
	mes := []*cbor.MapEntryEncoder{}

	// "4.1. If certSha256 is set: The text string "certSha256" to the byte string
	// certSha256." [spec text]
	//if b := s.certSha256(); len(b) != 0 {
	if b := s.certSha256(); len(b) > 0 {
		mes = append(mes,
			cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
				keyE.EncodeTextString("certSha256")
				valueE.EncodeByteString(b)
			}))
	}

	mes = append(mes,
		// "4.2. The text string "date" to the integer value of date."
		// [spec text]
		cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
			keyE.EncodeTextString("date")
			valueE.EncodeInt(s.Date.Unix())
		}),
		// "4.3. The text string "expires" to the integer value of expires."
		// [spec text]
		cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
			keyE.EncodeTextString("expires")
			valueE.EncodeInt(s.Expires.Unix())
		}),
		// "4.4. The text string "headers" to the CBOR representation (Section
		// 3.4) of exchange's headers."
		cbor.GenerateMapEntry(func(keyE *cbor.Encoder, valueE *cbor.Encoder) {
			keyE.EncodeTextString("headers")
			encodeCanonicalExchangeHeaders(valueE, i)
		}),
	)

	e := cbor.NewEncoder(&buf)
	if err := e.EncodeMap(mes); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Signer) sign(i *Input) ([]byte, error) {
	alg, err := signerForPrivateKey(s.PrivKey)
	if err != nil {
		return nil, err
	}

	msg, err := s.serializeSignedMessage(i)
	if err != nil {
		return nil, err
	}

	return alg.sign(msg)
}

func (s *Signer) SignatureHeaderValue(i *Input) (string, error) {
	sig, err := s.sign(i)
	if err != nil {
		return "", err
	}

	sigb64 := base64.RawStdEncoding.EncodeToString(sig)
	integrityStr := "mi"
	certUrl := s.CertUrl.String()
	certSha256b64 := base64.RawStdEncoding.EncodeToString(s.certSha256())
	dateUnix := s.Date.Unix()
	expiresUnix := s.Expires.Unix()

	// FIXME: validityURL
	return fmt.Sprintf("sig=*%s; integrity=\"%s\"; certUrl=\"%s\"; certSha256=*%s; date=%d; expires=%d", sigb64, integrityStr, certUrl, certSha256b64, dateUnix, expiresUnix), nil
}
