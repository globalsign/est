/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package est

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDecodeMultipartRequestTransferEncoding checks that part headers do not alter base64 data.
func TestDecodeMultipartRequestTransferEncoding(t *testing.T) {
	t.Parallel()

	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Jane Doe"},
	}, key)
	if err != nil {
		t.Fatalf("failed to create certificate request: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(der)
	if !strings.HasSuffix(encoded, "=") {
		t.Fatal("test requires base64 padding, which quoted-printable would alter")
	}

	for _, encoding := range []string{"", "base64", "quoted-printable"} {
		t.Run(encoding, func(t *testing.T) {
			body := "--parts\r\nContent-Type: application/pkcs10\r\n"
			if encoding != "" {
				body += "Content-Transfer-Encoding: " + encoding + "\r\n"
			}
			body += "\r\n" + encoded + "\r\n--parts--\r\n"
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			r.Header.Set(contentTypeHeader, "multipart/mixed; boundary=parts")

			var csr *x509.CertificateRequest
			_, err := decodeMultipartRequest(r, []multipartPart{{contentType: mimeTypePKCS10, data: &csr}})
			if err != nil {
				t.Fatalf("failed to decode multipart request: %v", err)
			}
			if csr == nil || !bytes.Equal(csr.Raw, der) {
				t.Fatal("decoded certificate request differs from input")
			}
		})
	}
}

func TestVerifyResponseType(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		r    *http.Response
		t    string
		e    string
		err  error
	}{
		{
			name: "Good",
			r: &http.Response{
				Header: http.Header{
					"Content-Type":              []string{"application/pkcs7; smime-type=certs-only"},
					"Content-Transfer-Encoding": []string{"BasE64"},
				},
			},
			t: "application/pkcs7",
			e: "bASe64",
		},
		{
			name: "WrongType",
			r: &http.Response{
				Header: http.Header{
					"Content-Type":              []string{"application/pkcs7; smime-type=certs-only"},
					"Content-Transfer-Encoding": []string{"base64"},
				},
			},
			t:   "application/pkcs10",
			e:   "base64",
			err: errors.New("unexpected Content-Type: application/pkcs7"),
		},
		{
			name: "MissingType",
			r: &http.Response{
				Header: http.Header{
					"Content-Transfer-Encoding": []string{"base64"},
				},
			},
			t:   "application/pkcs7",
			e:   "base64",
			err: errors.New("missing or malformed Content-Type header: mime: no media type"),
		},
		{
			name: "BadTypeParameter",
			r: &http.Response{
				Header: http.Header{
					"Content-Type":              []string{"application/pkcs7; smime-type:certs-only"},
					"Content-Transfer-Encoding": []string{"base64"},
				},
			},
			t:   "application/pkcs7",
			e:   "base64",
			err: errors.New("missing or malformed Content-Type header: mime: invalid media parameter"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := verifyResponseType(tc.r, tc.t, tc.e)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if err != nil && err.Error() != tc.err.Error() {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}
		})
	}

}

func TestParseHTTPTime(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		str  string
		want time.Time
		err  error
	}{
		{
			name: "IMF-fixdate",
			str:  "Sun, 06 Nov 1994 08:49:37 GMT",
			want: time.Date(1994, 11, 6, 8, 49, 37, 0, time.UTC),
		},
		{
			name: "RFC850",
			str:  "Sunday, 06-Nov-94 08:49:37 GMT",
			want: time.Date(1994, 11, 6, 8, 49, 37, 0, time.UTC),
		},
		{
			name: "ANSIC",
			str:  "Sun Nov  6 08:49:37 1994",
			want: time.Date(1994, 11, 6, 8, 49, 37, 0, time.UTC),
		},
		{
			name: "Invalid",
			str:  "not a valid time string",
			err:  errors.New("invalid time"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseHTTPTime(tc.str)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
