package signedexchange

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
)

type signer interface {
	sign(m []byte) ([]byte, error)
}

type rsaPSSSigner struct {
	privKey *rsa.PrivateKey
	hash    crypto.Hash
}

func (s *rsaPSSSigner) sign(m []byte) ([]byte, error) {
	hash := s.hash.New()
	hash.Write(m)
	return rsa.SignPSS(rand.Reader, s.privKey, s.hash, hash.Sum(nil), nil)
}

type ecdsaSigner struct {
	privKey *ecdsa.PrivateKey
	hash    crypto.Hash
}

// From RFC5480:
type ecdsaSigValue struct {
	r, s *big.Int
}

func (e *ecdsaSigner) sign(m []byte) ([]byte, error) {
	hash := e.hash.New()
	hash.Write(m)
	r, s, err := ecdsa.Sign(rand.Reader, e.privKey, hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSigValue{r, s})
}

func signerForPrivateKey(pk crypto.PrivateKey) (signer, error) {
	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		bits := pk.N.BitLen()
		if bits == 2048 {
			return &rsaPSSSigner{pk, crypto.SHA256}, nil
		}
		return nil, fmt.Errorf("signedexchange: unsupported RSA key size: %v bits", bits)
	case *ecdsa.PrivateKey:
		switch name := pk.Curve.Params().Name; name {
		case elliptic.P256().Params().Name:
			return &ecdsaSigner{pk, crypto.SHA256}, nil
		case elliptic.P384().Params().Name:
			return &ecdsaSigner{pk, crypto.SHA384}, nil
		default:
			return nil, fmt.Errorf("signedexchange: unknown ECDSA curve: %v", name)
		}
	}
	return nil, fmt.Errorf("signedexchange: unknown public key type: %T", pk)
}
