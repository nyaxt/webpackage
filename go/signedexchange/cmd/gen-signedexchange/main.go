package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"time"

	se "github.com/WICG/webpackage/go/signedexchange"
)

var (
	flagUri            = flag.String("uri", "https://example.com/index.html", "The URI of the resource represented in the exchange")
	flagResponseStatus = flag.Int("status", 200, "The status of the response represented in the exchange")
	flagContent        = flag.String("content", "index.html", "Source file to be used as the exchange payload")
	flagCertificate    = flag.String("certificate", "cert.pem", "Certificate chain PEM file of the origin")
	flagCertificateUrl = flag.String("certUrl", "https://example.com/cert.msg", "The URL where the certificate chain is hosted at.")
	flagPrivateKey     = flag.String("privateKey", "cert-key.pem", "Private key PEM file of the origin")
	flagOutput         = flag.String("o", "out.htxg", "Signed exchange output file")
)

func main() {
	flag.Parse()

	payload, err := ioutil.ReadFile(*flagContent)
	if err != nil {
		log.Printf("Failed to read content from payload source file \"%s\". err: %v", *flagContent, err)
		os.Exit(1)
	}

	certtext, err := ioutil.ReadFile(*flagCertificate)
	if err != nil {
		log.Printf("Failed to read certificate file \"%s\". err: %v", *flagCertificate, err)
		os.Exit(1)
	}
	certs, err := ParseCertificates(certtext)
	if err != nil {
		log.Printf("Failed to parse certificate file \"%s\". err: %v", *flagCertificate, err)
		os.Exit(1)
	}

	certUrl, err := url.Parse(*flagCertificateUrl)
	if err != nil {
		log.Printf("Failed to parse certificate URL \"%s\". err: %v", *flagCertificateUrl, err)
		os.Exit(1)
	}

	privkeytext, err := ioutil.ReadFile(*flagPrivateKey)
	if err != nil {
		log.Printf("Failed to read private key file \"%s\". err: %v", *flagPrivateKey, err)
		os.Exit(1)
	}
	privkey, err := ParsePrivateKey(privkeytext)
	if err != nil {
		log.Printf("Failed to parse private key file \"%s\". err: %v", *flagPrivateKey, err)
		os.Exit(1)
	}

	f, err := os.OpenFile(*flagOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Failed to open output file \"%s\" for writing. err: %v", *flagOutput, err)
		os.Exit(1)
	}
	defer f.Close()

	parsedUrl, err := url.Parse(*flagUri)
	if err != nil {
		log.Printf("Failed to parse URL \"%s\". err: %v", *flagUri, err)
		os.Exit(1)
	}
	i := &se.Input{
		RequestUri:     parsedUrl,
		ResponseStatus: *flagResponseStatus,
		ResponseHeaders: []se.ResponseHeader{
			// FIXME
			se.ResponseHeader{Name: "Content-Type", Value: "text/html; charset=utf-8"},
		},
		Payload: payload,
	}
	i.AddSignedHeadersHeader([]string{"Content-Type"})

	s := &se.Signer{
		Date:    time.Now(),
		Expires: time.Now().Add(1 * time.Hour),
		Certs:   certs,
		CertUrl: certUrl,
		PrivKey: privkey,
	}
	sigHdr, err := s.SignatureHeaderValue(i)
	if err != nil {
		log.Printf("Failed to compute Signature header value. err: %v", err)
		os.Exit(1)
	}
	log.Printf("Signature: %v", sigHdr)
	i.ResponseHeaders = append(i.ResponseHeaders,
		se.ResponseHeader{Name: "Signature", Value: sigHdr})

	if err := se.WriteExchangeFile(f, i); err != nil {
		log.Printf("Failed to write exchange. err: %v", err)
		os.Exit(1)
	}
	log.Println("Done!")
}
