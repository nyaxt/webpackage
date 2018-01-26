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

type SigningAlgorithm interface {
	Sign(m []byte) ([]byte, error)
}

type rsaPSSSigner struct {
	privKey *rsa.PrivateKey
	hash    crypto.Hash
}

var _ = SigningAlgorithm(rsaPSSSigner{})

func (s rsaPSSSigner) Sign(m []byte) ([]byte, error) {
	hash := s.hash.New()
	hash.Write(m)
	return rsa.SignPSS(rand.Reader, s.privKey, s.hash, hash.Sum(nil), nil)
}

type ecdsaSigner struct {
	privKey *ecdsa.PrivateKey
	hash    crypto.Hash
}

var _ = SigningAlgorithm(ecdsaSigner{})

// From RFC5480:
type ecdsaSigValue struct {
	R, S *big.Int
}

func (es ecdsaSigner) Sign(m []byte) ([]byte, error) {
	hash := es.hash.New()
	hash.Write(m)
	r, s, err := ecdsa.Sign(rand.Reader, es.privKey, hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSigValue{r, s})
}

func SigningAlgorithmForPrivateKey(pk crypto.PrivateKey) (SigningAlgorithm, error) {
	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		switch bits := pk.N.BitLen(); bits {
		case 2048:
			return rsaPSSSigner{pk, crypto.SHA256}, nil
		default:
			return nil, fmt.Errorf("unsupported RSA key size: %v bits", bits)
		}
	case *ecdsa.PrivateKey:
		switch name := pk.Curve.Params().Name; name {
		case elliptic.P256().Params().Name:
			return ecdsaSigner{pk, crypto.SHA256}, nil
		case elliptic.P384().Params().Name:
			return ecdsaSigner{pk, crypto.SHA384}, nil
		default:
			return nil, fmt.Errorf("unknown ECDSA curve: %v", name)
		}
	}
	return nil, fmt.Errorf("unknown public key type: %T", pk)
}
