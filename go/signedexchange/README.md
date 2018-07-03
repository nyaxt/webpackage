# go/bundle
This directory contains a reference implementation of [Signed HTTP Exchanges](https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html) spec.

## Overview
We currently provide two command-line tools: `gen-signedexchange` and `gen-certurl`.

`gen-signedexchange` generates a signed exchange file. The `gen-signedexchange` command constructs HTTP request and response pair from given command line flags, attach a cryptographic signature of the pair, and serializes the result to output file.

`gen-certurl` converts a X.509 certificate chain to `application/cert-chain+cbor` format, which is defined in the [Section 3.3 of the Signed HTTP Exchanges spec](https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#rfc.section.3.3).

You are also welcome to use the code as golang lib (e.g. `import "github.com/WICG/webpackage/go/signedexchange"`), but please be aware that the API is not yet stable and is subject to change any time.

## Getting Started

### Prerequisite
golang environment needs to be set up in prior to using the tool. We are testing the tool on latest golang. Please refer to [Go Getting Started documentation](https://golang.org/doc/install) for the details.

### Installation
We recommend using `go get` to install the command-line tool.

```
go get -u github.com/WICG/webpackage/go/signedexchange/cmd/...
```

### Creating our first signed exchange
In this section, we guide you to create a signed exchange file, signed using self-signed certificate pair. Here, we assume that you have a 

1. First, prepare a file to be enclosed in the signed exchange. This serves as the content of the HTTP response in the signed exchange.
    ```
    echo "<h1>hi</h1>" > payload.html
    ```

2. Next, prepare a certificate and private key pair to use for signing the exchange. As of July 2018, we need to use self-signed certificate for testing, since there are no CA that issues certificate with ["CanSignHttpExchanges" extension](https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#cross-origin-cert-req). To generate a signed exchange compatible self-signed key pair with OpenSSL, invoke:
    ```
    # Generate prime256v1 ecdsa private key.
    openssl ecparam -out priv.key -name prime256v1 -genkey
    # Create a certificate signing request for the private key.
    openssl req -new -sha256 -key priv.key -out cert.csr \
      -subj '/CN=example.org/O=Test/C=US'
    # Self-sign the certificate with "CanSignHttpExchanges" extension.
    openssl x509 -req -days 360 -in cert.csr -signkey priv.key -out cert.pem \
      -extfile <(echo "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:example.org")
    ```

3. Then, convert the PEM certificate to `application/cert-chain+cbor` format using `gen-certurl` tool.
    ```
    # Fill in dummy data for OCSP/SCT, since the certificate is self-signed.
    gen-certurl -pem cert.pem -ocsp <(echo ocsp) -sct <(echo sct) > cert.cbor
    ```

4. Finally, generate the signed exchange using `gen-signedexchange` tool.
    ```
    gen-signedexchange \
      -uri https://example.org/hello.html \
      -content ./payload.html \
      -certificate cert.pem \
      -certUrl https:///cert.msg \
      -validityUrl https://test.example.org/resource.validity.msg \
      -privateKey prime256v1.key \
      -date 2018-03-12T05:53:20Z \
      -o test.example.org_test.htxg \
      -miRecordSize 100
    ```

`gen-signedexchange` generates a signed exchange file. The HTTP request and respose to be enclosed in the signed exchange file is specified via command line flags.

