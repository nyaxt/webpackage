package signedexchange

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	p256k1 "github.com/coin-network/curve"
)

type SigningAlgorithm interface {
	Sign(m []byte) ([]byte, error)
}

type rsaPSSSigningAlgorithm struct {
	privKey *rsa.PrivateKey
	hash    crypto.Hash
	rand    io.Reader
}

func (s *rsaPSSSigningAlgorithm) Sign(m []byte) ([]byte, error) {
	hash := s.hash.New()
	hash.Write(m)
	return rsa.SignPSS(
		s.rand, s.privKey, s.hash, hash.Sum(nil),
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

type ecdsaSigningAlgorithm struct {
	privKey *ecdsa.PrivateKey
	hash    crypto.Hash
	rand    io.Reader
}

func (e *ecdsaSigningAlgorithm) Sign(m []byte) ([]byte, error) {
	type ecdsaSigValue struct {
		r, s *big.Int
	}

	hash := e.hash.New()
	hash.Write(m)
	r, s, err := ecdsa.Sign(e.rand, e.privKey, hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSigValue{r, s})
}

type ecdsaSigningAlgorithmS256 struct {
	privKey *ecdsa.PrivateKey
}

func (e *ecdsaSigningAlgorithmS256) Sign(m []byte) ([]byte, error) {
	type ecdsaSigValue struct {
		r, s *big.Int
	}

	hash := crypto.SHA256.New()
	hash.Write(m)
	pkey := p256k1.PrivateKey(*e.privKey)
	s, err := pkey.Sign(hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return s.Serialize(), nil
}

func SigningAlgorithmForPrivateKey(pk crypto.PrivateKey, rand io.Reader) (SigningAlgorithm, error) {
	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		bits := pk.N.BitLen()
		if bits == 2048 {
			return &rsaPSSSigningAlgorithm{pk, crypto.SHA256, rand}, nil
		}
		return nil, fmt.Errorf("signedexchange: unsupported RSA key size: %d bits", bits)
	case *ecdsa.PrivateKey:
		switch name := pk.Curve.Params().Name; name {
		case elliptic.P256().Params().Name:
			return &ecdsaSigningAlgorithm{pk, crypto.SHA256, rand}, nil
		case p256k1.S256().Params().Name:
			return &ecdsaSigningAlgorithmS256{pk}, nil
		case elliptic.P384().Params().Name:
			return &ecdsaSigningAlgorithm{pk, crypto.SHA384, rand}, nil
		default:
			return nil, fmt.Errorf("signedexchange: unknown ECDSA curve: %s", name)
		}
	}
	return nil, fmt.Errorf("signedexchange: unknown public key type: %T", pk)
}
