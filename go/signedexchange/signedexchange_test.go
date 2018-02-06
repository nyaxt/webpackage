package signedexchange_test

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/WICG/webpackage/go/signedexchange"
)

const (
	payload  = `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.`
	pemCerts = `-----BEGIN CERTIFICATE-----
MIIF8jCCBNqgAwIBAgIQDmTF+8I2reFLFyrrQceMsDANBgkqhkiG9w0BAQsFADBw
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz
dXJhbmNlIFNlcnZlciBDQTAeFw0xNTExMDMwMDAwMDBaFw0xODExMjgxMjAwMDBa
MIGlMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxML
TG9zIEFuZ2VsZXMxPDA6BgNVBAoTM0ludGVybmV0IENvcnBvcmF0aW9uIGZvciBB
c3NpZ25lZCBOYW1lcyBhbmQgTnVtYmVyczETMBEGA1UECxMKVGVjaG5vbG9neTEY
MBYGA1UEAxMPd3d3LmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAs0CWL2FjPiXBl61lRfvvE0KzLJmG9LWAC3bcBjgsH6NiVVo2dt6u
Xfzi5bTm7F3K7srfUBYkLO78mraM9qizrHoIeyofrV/n+pZZJauQsPjCPxMEJnRo
D8Z4KpWKX0LyDu1SputoI4nlQ/htEhtiQnuoBfNZxF7WxcxGwEsZuS1KcXIkHl5V
RJOreKFHTaXcB1qcZ/QRaBIv0yhxvK1yBTwWddT4cli6GfHcCe3xGMaSL328Fgs3
jYrvG29PueB6VJi/tbbPu6qTfwp/H1brqdjh29U52Bhb0fJkM9DWxCP/Cattcc7a
z8EXnCO+LK8vkhw/kAiJWPKx4RBvgy73nwIDAQABo4ICUDCCAkwwHwYDVR0jBBgw
FoAUUWj/kK8CB3U8zNllZGKiErhZcjswHQYDVR0OBBYEFKZPYB4fLdHn8SOgKpUW
5Oia6m5IMIGBBgNVHREEejB4gg93d3cuZXhhbXBsZS5vcmeCC2V4YW1wbGUuY29t
ggtleGFtcGxlLmVkdYILZXhhbXBsZS5uZXSCC2V4YW1wbGUub3Jngg93d3cuZXhh
bXBsZS5jb22CD3d3dy5leGFtcGxlLmVkdYIPd3d3LmV4YW1wbGUubmV0MA4GA1Ud
DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYDVR0f
BG4wbDA0oDKgMIYuaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItaGEtc2Vy
dmVyLWc0LmNybDA0oDKgMIYuaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTIt
aGEtc2VydmVyLWc0LmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwBATAqMCgGCCsG
AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAECAjCB
gwYIKwYBBQUHAQEEdzB1MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
dC5jb20wTQYIKwYBBQUHMAKGQWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
aWdpQ2VydFNIQTJIaWdoQXNzdXJhbmNlU2VydmVyQ0EuY3J0MAwGA1UdEwEB/wQC
MAAwDQYJKoZIhvcNAQELBQADggEBAISomhGn2L0LJn5SJHuyVZ3qMIlRCIdvqe0Q
6ls+C8ctRwRO3UU3x8q8OH+2ahxlQmpzdC5al4XQzJLiLjiJ2Q1p+hub8MFiMmVP
PZjb2tZm2ipWVuMRM+zgpRVM6nVJ9F3vFfUSHOb4/JsEIUvPY+d8/Krc+kPQwLvy
ieqRbcuFjmqfyPmUv1U9QoI4TQikpw7TZU0zYZANP4C/gj4Ry48/znmUaRvy2kvI
l7gRQ21qJTK5suoiYoYNo3J9T+pXPGU7Lydz/HwW+w0DpArtAaukI8aNX4ohFUKS
wDSiIIWIWJiJGbEeIO0TIFwEVWTOnbNl/faPXpk5IRXicapqiII=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3Vy
YW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2
4C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMIC
Kq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1
itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn
4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0X
sh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcft
bZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEA
MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
NAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
dC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29t
L0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIG
BFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ
UzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7D
aQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwd
aOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNH
E+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly
/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zu
xICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF
0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0Ae
cPUeybQ=
-----END CERTIFICATE-----
`
	// Generated by `openssl genrsa -out privatekey.pem 2048`
	pemPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEoAIBAAKCAQEAoMRYVlgUxlVOvejxDblbIZAg4ZtTbAmI7/YzNqmlKBB7UGik
7t6MCTJRM1PAQoDdRC0H5XI0TS04Lizwet8gEeBMtyHqLcWmOUGYNsYO7nNgT7N2
wbEs6v6KHHPHPMKzmxMPayOWrfE7mRvHvwTtIbE5ar5PNjpypjNH24TddkAmIXbM
YbkS2F43rVgpzOihjbeTQ/A6pxqcplifmoGSI6W26dg5N9yGnmo1ZcLdpHixR9Lr
e3xvunkDxT+B0OlwBRQtTQvZ1YoDWylpq3cOiFqU0Wn9+AG8JpL2yI49KQMVKyBV
7dLtr43LFhtBefkyqSNTxqPZyUAJJ2SNkJgwIQIDAQABAoIBAFJz4QqHqj/+SKBF
9DuhsQeJsBOFYkeqrDzF/IYwg7AEo/odcVnBcfjVgafdcGGrTdBFeCNJa2GZq5Kj
IcMi5IPGkhHqpvxKvnHnHnYZJldNfTvjQykcAXmUiqkFCE41XYBPSj0cx472hiaE
hPGHSUdaaaRBbsbVOy/aZSRFBIA8ngxyrW6B94Q/uLVZBn6axqoj8xT1YFVBgH5G
/lVxfkpjUD2im9r3w+7ofSmMKa6CyJ/bBdRf8p0ACyzDbkfyXjwUxSj/ZFrpLg66
amEXgauqxKEAhF8MP8oKir9aEwl7EaYFIRFpzQ6LT6edD5vcieov6hDi1f8xxdty
5lL4HkECgYEA01+pVvn2VqANu9tgpcX3srY6QKnqViBSXr6GX+XpcCJlxR2S4FVD
gdEwMHJK9137krvzIek57BFQXd4bTpeUW3Da8rX73tUnqKrQ5pmEqpghRyCqo0kT
V1ObepNUcQVmK6VnqIuckHNV7sjYnSCgY4P4WiPBRJCG3jTI2LUpo/UCgYEAwrV9
MtwsV9HlVHNrd8hqqaXnDvY1InFCfFxyR0m5KMTiwvcswBbwpTYtKZXWnz2HRVbO
aMmh2RQKk9Swpwb/q2TjVnPPUqH14++OwyR0k/0L4KBZMY736GqyWnfod6G5KQD2
f5MtwRFCYoJ6Tts4KtMzxxaV4TeRQA0EES7rK/0CgYBVztbi7TSYs/7/TS6t/XDx
xtJdH912u0ZVGglY8u/SStR/seLHWTW/hJmIgU13oFqZld083f5anCjBAoKZZCWg
/W6U61XlfyjLaxTFGHtn+bxAsL007lyArftHRnoYK7XvcAVlwc98QKYY+sYc+3rB
C3kNtsglunpVyJ3kg5705QJ/cVMwi2maZYLE92I2KoF7k0H8ObkTM/i3uaoU2WkP
W6s8UD2MzkCLz5y4rHuJbyVglfrwKA0zJiWEAobISm7IX/lYV/kPsgiSFRhY/zs4
numpABRT1YRgxeVT6VPg+cAnBLaKwbXn63cgLDXE+iCdkE9c04NRuMOexqjMtTOZ
rQKBgDSCTKwnbJUqN94WdBYjinFN/bR6E0wW640jkB/3e8Y4a+W4OVHWlxoEu4Tm
s5B6gZsV/ojttR+aaeRknfrhQwEIA/k2r2oZE9yp8djzyiiqGswgw8yO0WSJztbx
GRqzPwjon7ESIVpKLrVuh5qlMhUkOFUeF9wvViWX4qnV5Fvg
-----END RSA PRIVATE KEY-----
`

	base64Result = `h2RodHhnZ3JlcXVlc3SiRDp1cmxUaHR0cHM6Ly9leGFtcGxlLmNvbS9HOm1ldGhvZENHRVRocmVzcG9uc2WmQm1pWDVtaS1zaGEyNTY9RFJ5QkdQYjdDQVcydWt6YjlzVDFTMWlhbHNzdGhpdjZRVzdLcy1Ucmc0WUc6c3RhdHVzQzIwMElzaWduYXR1cmVZAiZzaWc9KmFnQlNNbzNEV25XcjVJck9tMmFkZFM1ZFJJNVAyWnZLaytENFVHMGtIYi9DNDJSd3NKeTMzR2hHVTBKZnJWYmVtNnpIWXVrWGdzU1IwbTl6cXlRN3gzcXBTVkZaNUR0SXJYMEpWMG05YlNYMnBicS9MbHlBaUZKNlNtVnpTeEk5MExSNjltdHJsNHByMFQrZzBxYjVxTUJLMWd3Vko1Ry9PQ253R01Fc1JVUStzTk1CaGVKYXFFNjhPYVVCbDZ0VFBRLytlKy8vaVZ3b1hMRDVBalV2VVNyOU5HbkVtenRKc3FVZGxyTytuOHI0T0kxTmdrb1M4SjN3b2hRd05LYWc3Q2F5TmNXY0xjZzNrbGdlMXIzZ1ZQaTBtWklaMXhzZEd2ck52YUJjc1VDdWhoSDhXenNqQk5LRG92amJ3Y0VJamN6ZEZTWDVhaVFQNWpuZ2ZLV1NaUTsgdmFsaWRpdHlVcmw9Imh0dHBzOi8vZXhhbXBsZS5jb20vcmVzb3VyY2UudmFsaWRpdHkiOyBpbnRlZ3JpdHk9Im1pIjsgY2VydFVybD0iaHR0cHM6Ly9leGFtcGxlLmNvbS9jZXJ0Lm1zZyI7IGNlcnRTaGEyNTY9KlpDM2xUWVREQkpRVmYxUDJWNytmaWJUcWJJc1dOUi9YN0NXTlZXK0NFRUE7IGRhdGU9MTUxNzQxODgwMDsgZXhwaXJlcz0xNTE3NDIyNDAwTGNvbnRlbnQtdHlwZVgYdGV4dC9odG1sOyBjaGFyc2V0PXV0Zi04TnNpZ25lZC1oZWFkZXJzWCgiY29udGVudC10eXBlIiwgImNvbnRlbnQtZW5jb2RpbmciLCAibWkiUGNvbnRlbnQtZW5jb2RpbmdJbWktc2hhMjU2Z3BheWxvYWRZBSUAAAAAAAAAEExvcmVtIGlwc3VtIGRvbG8BFGBxZ7/qmc5iCIunAuyOPLaSa5oKgY96ASefEgB223Igc2l0IGFtZXQsIGNvbnPpcxszG73y5vSV72X7KnXIxKcG/qrGbt0fHAICv76M1WVjdGV0dXIgYWRpcGlzY2lq1IZaYvkGQnF5F057rGuzceI7G+5YTks9K+M8XUMaEW5nIGVsaXQsIHNlZCBkbyAWFN+S60IyCze7uJPhmqAmC+KUmPmxNAiZvm71qQiODGVpdXNtb2QgdGVtcG9yIGk1xgMs0YPicUEQcGe27ymzjS9ciDjw93Dg9JwqenpcQ25jaWRpZHVudCB1dCBsYWIo5tgXihrYA6sqS0xCD+1ECzmytTrGTG/3B1CTis8zdG9yZSBldCBkb2xvcmUgbWHxbZgkZ1sn8ysuxFpQ68bgA5Fpcopokv1sQfx0ZI7V42duYSBhbGlxdWEuIFV0IGXACS4X26L5fufCQqPoIyPtq+6kXdyeKJr5lct65eptkG5pbSBhZCBtaW5pbSB2ZW6IMCq0tV5tAnqSzvtFAs5/g4yJI/TZ4PoXp6Yv50f9vWlhbSwgcXVpcyBub3N0cnUP3uTxbra410m6O2E9TDaKxTdD0TB0LqN2Ee2yZqAgLmQgZXhlcmNpdGF0aW9uIHUzeavCtJdam77fMHGNDYbVLcQ163eWQhGdf/n8mbwoH2xsYW1jbyBsYWJvcmlzIG4bIGneIz4YUSB/b0Cg8YvfrhK0r4wweneZCmQJ8jVaGGlzaSB1dCBhbGlxdWlwIGVaUp8ia/7PKqN3gQSQIAY8lUwKiatmrDjpvhiqyJEgT3ggZWEgY29tbW9kbyBjb275I1RKLB5GVrwsP8F88T44duZRpyBPJgydLw6l3ZSSYXNlcXVhdC4gRHVpcyBhdXQolVCxp+F1Acefod81PIPN8pkiu9YY3kPRRli1eu7shWUgaXJ1cmUgZG9sb3IgaW7c+vvp/tp6DHN0xxPxxTkPLMLHFpSHOjdKuehII7jFsSByZXByZWhlbmRlcml0IGkICRFEkZaU9lOLCMZHVilt5kj8rqjCQAEPYVddFjgVe24gdm9sdXB0YXRlIHZlbGmH2y3eZLc31ZxkddFHlb+mgiyND3sHMIw9ifIBHzaHHXQgZXNzZSBjaWxsdW0gZG/CSNmgbwWoQXvd5muV1iw+hjkWkK4VcNwgpY3lxsXromxvcmUgZXUgZnVnaWF0IG695//baygvzVeS73jXBjE2suPa4pvYmaVjgco2h1EqiXVsbGEgcGFyaWF0dXIuIEUqiTk7bEVOxaxZb33vyTZHsNWsUCHrWEoValmYcXEnAHhjZXB0ZXVyIHNpbnQgb2O6HMwlmFP5cYMB1Kg7zcb12JqqnKmgHCuTBHh+o2YDa2NhZWNhdCBjdXBpZGF0YXT+FWp3KYNw3FdiaywdC7J/LsqxCl3bsosVUIcf8/2E1CBub24gcHJvaWRlbnQsIHP9gohggpngaCirjhwibbqbgsiSaCV12/x9X1jB2J+YoHVudCBpbiBjdWxwYSBxdWkRNNALZAnw3BxVNehYbnA7XDUbBejP1JaXIjCsfQTVbCBvZmZpY2lhIGRlc2VydW72RDi/M9aTecBqd67ojSMk0zjVkukDObEpA6HUMCZxSnQgbW9sbGl0IGFuaW0gaWRC5zY94ZqykToiRK07damvwmYsDusXYV+53vLNrdgGRyBlc3QgbGFib3J1bS4=`
)

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func TestSignedExchange(t *testing.T) {
	u, _ := url.Parse("https://example.com/")
	header := http.Header{}
	header.Add("Content-Type", "text/html; charset=utf-8")
	i, err := signedexchange.NewInput(u, 200, header, []byte(payload), 16)
	if err != nil {
		t.Fatal(err)
	}
	i.AddSignedHeadersHeader()

	now := time.Date(2018, 1, 31, 17, 13, 20, 0, time.UTC)
	certs, err := signedexchange.ParseCertificates([]byte(pemCerts))
	if err != nil {
		t.Fatal(err)
	}

	derPrivateKey, _ := pem.Decode([]byte(pemPrivateKey))
	privKey, err := signedexchange.ParsePrivateKey(derPrivateKey.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certUrl, _ := url.Parse("https://example.com/cert.msg")
	validityUrl, _ := url.Parse("https://example.com/resource.validity")
	s := &signedexchange.Signer{
		Date:        now,
		Expires:     now.Add(1 * time.Hour),
		Certs:       certs,
		CertUrl:     certUrl,
		ValidityUrl: validityUrl,
		PrivKey:     privKey,
		Rand:        zeroReader{},
	}
	if err := i.AddSignatureHeader(s); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	signedexchange.WriteExchangeFile(&buf, i)
	got := strings.TrimSpace(base64.StdEncoding.EncodeToString(buf.Bytes()))
	want := strings.TrimSpace(base64Result)
	if len(got) != len(want) {
		t.Errorf("len(got) vs len(want): got: %v, want: %v", len(got), len(want))
	}
	if got != want {
		t.Errorf("WriteExchangeFile:\ngot %v\nwant %v", got, want)
	}
}
