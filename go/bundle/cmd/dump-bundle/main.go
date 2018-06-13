package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/WICG/webpackage/go/bundle"
)

var (
	flagInput = flag.String("i", "in.webbundle", "Webbundle input file")
)

func ReadBundleFromFile(path string) (*bundle.Bundle, error) {
	fi, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to open input file %q for reading. err: %v", path, err)
	}
	defer fi.Close()
	return bundle.Read(fi)
}

func run() error {
	b, err := ReadBundleFromFile(*flagInput)
	if err != nil {
		return err
	}

	for _, e := range b.Exchanges {
		log.Printf("Processing entry: %q", e.RequestURI())
	}

	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
