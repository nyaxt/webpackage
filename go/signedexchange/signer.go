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

func (signer *Signer) CertSha256() []byte {
	/* Binary content (Section 4.5 of [I-D.ietf-httpbis-header-structure]) holding the SHA-256 hash of the first certificate found at "certUrl". */
	if len(signer.Certs) == 0 {
		return []byte{}
	}

	c := signer.Certs[0]
	s := sha256.Sum256(c.Raw)
	return s[:]
}

func (signer *Signer) SerializeSignedMessage(i *Input) ([]byte, error) {
	/*
		"Let message be the concatenation of the following byte strings.
		This matches the [I-D.ietf-tls-tls13] format to avoid cross-protocol
		attacks when TLS certificates are used to sign manifests." [spec text]
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
	if b := signer.CertSha256(); len(b) != 0 {
		mes = append(mes,
			cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
				keyE.EncodeTextString("certSha256")
				valueE.EncodeByteString(b)
			}))
	}

	mes = append(mes,
		// "4.2. The text string "date" to the integer value of date." [spec text]
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeTextString("date")
			valueE.EncodeInt(signer.Date.Unix())
		}),
		// "4.3. The text string "expires" to the integer value of expires." [spec text]
		cbor.GenerateMapEntry(func(keyE cbor.Encoder, valueE cbor.Encoder) {
			keyE.EncodeTextString("expires")
			valueE.EncodeInt(signer.Expires.Unix())
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

func (signer *Signer) Sign(i *Input) ([]byte, error) {
	alg, err := SigningAlgorithmForPrivateKey(signer.PrivKey)
	if err != nil {
		return nil, err
	}

	msg, err := signer.SerializeSignedMessage(i)
	if err != nil {
		return nil, err
	}

	return alg.Sign(msg)
}

func (signer *Signer) SignatureHeaderValue(i *Input) (string, error) {
	sig, err := signer.Sign(i)
	if err != nil {
		return "", err
	}

	sigb64 := base64.RawStdEncoding.EncodeToString(sig)
	integrityStr := "mi"
	certUrl := signer.CertUrl.String()
	certSha256 := signer.CertSha256()
	certSha256b64 := base64.RawStdEncoding.EncodeToString(certSha256)
	dateUnix := signer.Date.Unix()
	expiresUnix := signer.Expires.Unix()

	// FIXME: validityURL
	return fmt.Sprintf("sig=*%s; integrity=\"%s\"; certUrl=\"%s\"; certSha256=*%s; date=%d; expires=%d", sigb64, integrityStr, certUrl, certSha256b64, dateUnix, expiresUnix), nil
}
