package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/WICG/webpackage/go/bundle"
	"github.com/WICG/webpackage/go/signedexchange"
)

var (
	flagUri    = flag.String("uri", "https://example.com/index.html", "The URI of the resource represented in the exchange")
	flagOutput = flag.String("o", "out.webbundle", "Webbundle output file")
)

func run() error {
	parsedUrl, err := url.Parse(*flagUri)
	if err != nil {
		return fmt.Errorf("failed to parse URL %q. err: %v", *flagUri, err)
	}

	f, err := os.OpenFile(*flagOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file %q for writing. err: %v", *flagOutput, err)
	}
	defer f.Close()

	se, err := signedexchange.NewExchange(parsedUrl, reqHeader, 200, resHeader, payload)
	if err != nil {
		return err
	}

	i := &bundle.Input{
		Exchanges: []*signedexchange.Exchange{se},
	}

	if err := bundle.WriteBundle(f, i); err != nil {
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
