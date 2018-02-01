package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/WICG/webpackage/go/signedexchange"
)

var (
	flagUri            = flag.String("uri", "https://example.com/index.html", "The URI of the resource represented in the exchange")
	flagResponseStatus = flag.Int("status", 200, "The status of the response represented in the exchange")
	flagContent        = flag.String("content", "index.html", "Source file to be used as the exchange payload")
	flagCertificate    = flag.String("certificate", "cert.pem", "Certificate chain PEM file of the origin")
	flagCertificateUrl = flag.String("certUrl", "https://example.com/cert.msg", "The URL where the certificate chain is hosted at.")
	flagPrivateKey     = flag.String("privateKey", "cert-key.pem", "Private key PEM file of the origin")
	flagOutput         = flag.String("o", "out.htxg", "Signed exchange output file")
	flagMIRecordSize   = flag.Int("miRecordSize", 4096, "The record size of Merkle Integrity Content Encoding")
)

func run() error {
	payload, err := ioutil.ReadFile(*flagContent)
	if err != nil {
		return fmt.Errorf("failed to read content from payload source file \"%s\". err: %v", *flagContent, err)
	}

	certtext, err := ioutil.ReadFile(*flagCertificate)
	if err != nil {
		return fmt.Errorf("failed to read certificate file \"%s\". err: %v", *flagCertificate, err)

	}
	certs, err := signedexchange.ParseCertificates(certtext)
	if err != nil {
		return fmt.Errorf("failed to parse certificate file \"%s\". err: %v", *flagCertificate, err)
	}

	certUrl, err := url.Parse(*flagCertificateUrl)
	if err != nil {
		return fmt.Errorf("failed to parse certificate URL \"%s\". err: %v", *flagCertificateUrl, err)
	}

	privkeytext, err := ioutil.ReadFile(*flagPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read private key file \"%s\". err: %v", *flagPrivateKey, err)
	}

	parsedPrivKey, _ := pem.Decode(privkeytext)
	if parsedPrivKey == nil {
		return fmt.Errorf("invalid private key")
	}
	privkey, err := signedexchange.ParsePrivateKey(parsedPrivKey.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key file \"%s\". err: %v", *flagPrivateKey, err)
	}

	f, err := os.OpenFile(*flagOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file \"%s\" for writing. err: %v", *flagOutput, err)
		os.Exit(1)
	}
	defer f.Close()

	parsedUrl, err := url.Parse(*flagUri)
	if err != nil {
		return fmt.Errorf("failed to parse URL \"%s\". err: %v", *flagUri, err)
	}

	i, err := signedexchange.NewInput(parsedUrl, *flagResponseStatus, []signedexchange.ResponseHeader{
		// FIXME
		{Name: "Content-Type", Value: "text/html; charset=utf-8"},
	}, payload, *flagMIRecordSize)
	if err != nil {
		return err
	}

	s := &signedexchange.Signer{
		Date:    time.Now(),
		Expires: time.Now().Add(1 * time.Hour),
		Certs:   certs,
		CertUrl: certUrl,
		PrivKey: privkey,
	}
	sigHdr, err := s.SignatureHeaderValue(i)
	if err != nil {
		return fmt.Errorf("failed to compute Signature header value. err: %v", err)
	}

	i.ResponseHeaders = append(i.ResponseHeaders,
		signedexchange.ResponseHeader{Name: "Signature", Value: sigHdr})

	if err := signedexchange.WriteExchangeFile(f, i); err != nil {
		return fmt.Errorf("failed to write exchange. err: %v", err)
	}
	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
