package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func ParseCertificates(text []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}
	for len(text) > 0 {
		var block *pem.Block
		block, text = pem.Decode(text)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("Found a block that contains %q.", block.Type)
		}
		if len(block.Headers) != 0 {
			return nil, fmt.Errorf("Unexpected certificate headers: %v", block.Headers)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func ParsePrivateKey(text []byte) (crypto.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(text)
	if block == nil {
		return nil, errors.New("No PEM data found.")
	}

	derKey := block.Bytes

	// Try each of 3 key formats and take the first one that successfully parses.
	if key, err := x509.ParsePKCS1PrivateKey(derKey); err == nil {
		return key, nil
	}
	if keyInterface, err := x509.ParsePKCS8PrivateKey(derKey); err == nil {
		switch typedKey := keyInterface.(type) {
		case *rsa.PrivateKey:
			return typedKey, nil
		case *ecdsa.PrivateKey:
			return typedKey, nil
		default:
			return nil, fmt.Errorf("Unknown private key type in PKCS#8: %T", typedKey)
		}
	}
	if key, err := x509.ParseECPrivateKey(derKey); err == nil {
		return key, nil
	}
	return nil, errors.New("Couldn't parse private key.")
}
