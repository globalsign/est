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

package est_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"go.mozilla.org/pkcs7"

	"github.com/arlotito/est"
	"github.com/arlotito/est/internal/basiclogger"
	"github.com/arlotito/est/internal/mockca"
	"github.com/arlotito/est/internal/tpm"
)

// Test constants.
const (
	authorizationHeader  = "Authorization"
	authorizationValue   = "Basic dGVzdHVzZXI6eHl6enk="
	cacertsEndpoint      = "/.well-known/est/cacerts"
	csrattrsEndpoint     = "/.well-known/est/csrattrs"
	encodingBase64       = "base64"
	encodingBinary       = "binary"
	encodingHeader       = "Content-Transfer-Encoding"
	enrollEndpoint       = "/.well-known/est/simpleenroll"
	hostHeader           = "Host"
	mimeTypePKCS10       = "application/pkcs10"
	mimeTypeText         = "text/plain"
	reenrollEndpoint     = "/.well-known/est/simplereenroll"
	serverKeyGenPassword = "pseudohistorical"
	testDomain           = "est.fake.domain"
	testTimeout          = time.Second * 10
	triggerErrorsAPS     = "triggererrors"
	typeHeader           = "Content-Type"
)

var (
	// The "alternate CA" is used to generate certificates from a CA other than
	// the one backing the test EST server.
	altCA *mockca.MockCA
)

var (
	fLog = flag.Bool("log", false, "")
)

func init() {
	var err error
	if altCA, err = mockca.NewTransient(); err != nil {
		panic(fmt.Sprintf("failed to create alternate CA: %v", err))
	}
}

func TestCSRAttrs(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		aps  string
		want est.CSRAttrs
	}{
		{
			name: "Empty",
		},
		{
			name: "Full",
			aps:  "csrattrs",
			want: est.CSRAttrs{
				OIDs: []asn1.ObjectIdentifier{
					{1, 2, 840, 113549, 1, 9, 7},
					{1, 2, 840, 10045, 4, 3, 3},
				},
				Attributes: []est.Attribute{
					{
						Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
						Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 6, 1, 1, 1, 1, 22}},
					},
					{
						Type:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
						Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create test EST server and client.
			s, newTestClient := newTestServer(t)
			defer s.Close()

			client := newTestClient()
			client.AdditionalPathSegment = tc.aps

			// Get CSR attributes.
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			got, err := client.CSRAttrs(ctx)
			if err != nil {
				t.Fatalf("failed to get CSR attributes: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEnroll(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name       string
		commonName string
		key        interface{}
		aps        string
		status     int
		errText    string
		retryAfter int
	}{
		{
			name:       "OK/ECDSA",
			commonName: "John Doe",
			key:        mustGenerateECPrivateKey(t),
			status:     http.StatusOK,
		},
		{
			name:       "OK/RSA",
			commonName: "Jane Doe",
			key:        mustGenerateRSAPrivateKey(t),
			status:     http.StatusOK,
		},
		{
			name:       "TriggerError/Deferred",
			aps:        triggerErrorsAPS,
			commonName: "Trigger Error Deferred",
			key:        mustGenerateECPrivateKey(t),
			status:     http.StatusAccepted,
			errText:    "202 triggered deferred response\n",
			retryAfter: 600,
		},
		{
			name:       "TriggerError/Forbidden",
			aps:        triggerErrorsAPS,
			commonName: "Trigger Error Forbidden",
			key:        mustGenerateECPrivateKey(t),
			status:     http.StatusForbidden,
			errText:    "403 triggered forbidden response\n",
		},
		{
			name:       "TriggerError/Unknown",
			aps:        triggerErrorsAPS,
			commonName: "Trigger Error Unknown",
			key:        mustGenerateECPrivateKey(t),
			status:     http.StatusInternalServerError,
			errText:    "500 internal server error\n",
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create test EST server and client.
			s, newTestClient := newTestServer(t)
			defer s.Close()

			client := newTestClient()

			// Get CA certificates before setting additional path segment,
			// which may otherwise trigger errors.
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			cacerts, err := client.CACerts(ctx)
			if err != nil {
				t.Fatalf("failed to get CA certificates: %v", err)
			}

			// Enroll for a certificate.
			client.AdditionalPathSegment = tc.aps
			csr := mustCreateCertificateRequest(t, tc.key, tc.commonName, nil)

			cert, err := client.Enroll(ctx, csr)
			if err == nil {
				// If there is no error, verify we were expecting success.
				if tc.status != http.StatusOK {
					t.Fatalf("no error returned when %d expected", tc.status)
				}
			} else {
				// If there is an error, verify it's the one we were expecting.
				var estErr est.Error
				if !errors.As(err, &estErr) {
					t.Fatalf("unexpected error: %v", err)
				}

				if got := estErr.StatusCode(); got != tc.status {
					t.Fatalf("got status code %d, want %d", got, tc.status)
				}

				if got := estErr.Error(); got != tc.errText {
					t.Fatalf("got error text %q, want %q", got, tc.errText)
				}

				if got := estErr.RetryAfter(); got != tc.retryAfter {
					t.Fatalf("got retry after %d seconds, want %d", got, tc.retryAfter)
				}

				// Don't perform any more tests for error cases.
				return
			}

			// Verify received certificate against CA certificates previously
			// obtained.
			opts := x509.VerifyOptions{
				Intermediates: x509.NewCertPool(),
				Roots:         x509.NewCertPool(),
				CurrentTime:   time.Now(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}

			for i, cacert := range cacerts {
				if i == len(cacerts)-1 {
					opts.Roots.AddCert(cacert)
				} else {
					opts.Intermediates.AddCert(cacert)
				}
			}

			if _, err := cert.Verify(opts); err != nil {
				t.Fatalf("failed to verify certificate: %v", err)
			}

			// Verify certificate contents.
			if got := cert.Subject.CommonName; got != csr.Subject.CommonName {
				t.Fatalf("got common name %q, want %q", got, csr.Subject.CommonName)
			}

			verifyPublicKey(t, cert.PublicKey, tc.key)
		})
	}
}

func TestReenroll(t *testing.T) {
	t.Parallel()

	// Create test EST server and client.
	s, newTestClient := newTestServer(t)
	defer s.Close()

	client := newTestClient()

	altKey := mustGenerateECPrivateKey(t)

	var testcases = []struct {
		name    string
		aps     string
		ecsr    *x509.CertificateRequest
		rcsr    *x509.CertificateRequest
		key     interface{}
		certs   []*x509.Certificate
		status  int
		errText string
	}{
		{
			name: "OK/ECDSA",
			ecsr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "Jane Doe"},
				DNSNames: []string{"jane-doe.domain"},
			},
			rcsr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "Jane Doe"},
				DNSNames: []string{"jane-doe.domain"},
			},
			key:    mustGenerateECPrivateKey(t),
			status: http.StatusOK,
		},
		{
			name: "OK/RSA",
			ecsr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "John Doe"},
				DNSNames: []string{"john-doe.domain"},
			},
			rcsr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "John Doe"},
				DNSNames: []string{"john-doe.domain"},
			},
			key:    mustGenerateRSAPrivateKey(t),
			status: http.StatusOK,
		},
		{
			name: "SubjectChanged",
			ecsr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "Jackie Doe"},
				DNSNames: []string{"jackie-doe.domain"},
			},
			rcsr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "Jackie Q. Doe"},
				DNSNames: []string{"jackie-doe.domain"},
			},
			key:     mustGenerateECPrivateKey(t),
			status:  http.StatusForbidden,
			errText: "403 Subject and SubjectAltName fields in CSR must be identical to certificate being renewed\n",
		},
		{
			name: "SubjectAltNameChanged",
			ecsr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "Jefferson Doe"},
				DNSNames: []string{"jefferson-doe.domain"},
			},
			rcsr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "Jefferson Doe"},
				DNSNames: []string{"jefferson-q-doe.domain"},
			},
			key:     mustGenerateECPrivateKey(t),
			status:  http.StatusForbidden,
			errText: "403 Subject and SubjectAltName fields in CSR must be identical to certificate being renewed\n",
		},
		{
			name: "InvalidCertificate",
			ecsr: &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "Juan Doe"},
			},
			rcsr: &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "Juan Doe"},
			},
			key:     altKey,
			certs:   mustMakeAlternateCertChain(t, altKey, "Juan Doe"),
			status:  http.StatusForbidden,
			errText: "403 invalid client certificate\n",
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// Create test EST server and client.

			// Get CA certificates before setting additional path segment,
			// which may otherwise trigger errors.
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			cacerts, err := client.CACerts(ctx)
			if err != nil {
				t.Fatalf("failed to get CA certificates: %v", err)
			}

			// Enroll for a certificate.
			client.AdditionalPathSegment = tc.aps
			csr := mustCreateCertificateRequest(t, tc.key, tc.ecsr.Subject.CommonName, tc.ecsr.DNSNames)

			got, err := client.Enroll(ctx, csr)
			if err != nil {
				t.Fatalf("failed to enroll: %v", err)
			}

			// Reenroll.
			client.PrivateKey = tc.key
			client.Certificates = append([]*x509.Certificate{got}, cacerts...)
			if tc.certs != nil {
				client.Certificates = tc.certs
			}
			csr = mustCreateCertificateRequest(t, tc.key, tc.rcsr.Subject.CommonName, tc.rcsr.DNSNames)

			_, err = client.Reenroll(ctx, csr)
			if err == nil {
				// If there is no error, verify we were expecting success.
				if tc.status != http.StatusOK {
					t.Fatalf("unexpectedly reenrolled: %v", err)
				}
			} else {
				// If there is an error, verify it's the one we were expecting.
				var estErr est.Error
				if !errors.As(err, &estErr) {
					t.Fatalf("unexpected error: %v", err)
				}

				if got := estErr.StatusCode(); got != tc.status {
					t.Fatalf("got status %d, want %d", got, tc.status)
				}

				if got := estErr.Error(); got != tc.errText {
					t.Fatalf("got error text %q, want %q", got, tc.errText)
				}

				// Don't perform any more tests for error cases.
				return
			}
		})
	}
}

func TestServerKeyGen(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name       string
		commonName string
		aps        string
		bitsize    int
		key        interface{}
		status     int
		errText    string
	}{
		{
			name:       "OK/PKCS8",
			commonName: "John Doe",
			key:        mustGenerateECPrivateKey(t),
			status:     http.StatusOK,
		},
		{
			name:       "OK/PKCS7",
			commonName: "Jane Doe",
			aps:        "pkcs7",
			bitsize:    3072,
			key:        mustGenerateRSAPrivateKey(t),
			status:     http.StatusOK,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create test EST server and client.
			s, newTestClient := newTestServer(t)
			defer s.Close()

			client := newTestClient()

			// Request certificate and private key.
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			client.AdditionalPathSegment = tc.aps
			csr := mustCreateCertificateRequest(t, tc.key, tc.commonName, nil)

			if tc.bitsize != 0 {
				client.AdditionalHeaders = map[string]string{
					"Bit-Size": strconv.Itoa(tc.bitsize),
				}
			}

			cert, key, err := client.ServerKeyGen(ctx, csr)
			if err == nil {
				// If there is no error, verify we were expecting success.
				if tc.status != http.StatusOK {
					t.Fatalf("no error returned when %d expected", tc.status)
				}
			} else {
				// If there is an error, verify it's the one we were expecting.
				var estErr est.Error
				if !errors.As(err, &estErr) {
					t.Fatalf("unexpected error: %v", err)
				}

				if got := estErr.StatusCode(); got != tc.status {
					t.Fatalf("got status code %d, want %d", got, tc.status)
				}

				if got := estErr.Error(); got != tc.errText {
					t.Fatalf("got error text %q, want %q", got, tc.errText)
				}

				// Don't perform any more tests for error cases.
				return
			}

			// Verify certificate contents.
			if got := cert.Subject.CommonName; got != csr.Subject.CommonName {
				t.Fatalf("got common name %q, want %q", got, csr.Subject.CommonName)
			}

			// Parse the returned private key, and verify that the associated
			// public key matches the one in the returned certificate.
			var pk interface{}
			if pk, err = x509.ParsePKCS8PrivateKey(key); err == nil {
				verifyPublicKey(t, cert.PublicKey, pk)
			} else if p7, err := pkcs7.Parse(key); err == nil {
				der, err := p7.DecryptUsingPSK([]byte(serverKeyGenPassword))
				if err != nil {
					t.Fatalf("failed to decrypt CMS EnvelopedData: %v", err)
				}

				sd, err := pkcs7.Parse(der)
				if err != nil {
					t.Fatalf("failed to parse CMS SignedData: %v", err)
				}

				pk, err = x509.ParsePKCS8PrivateKey(sd.Content)
				if err != nil {
					t.Fatalf("failed to parse private key: %v", err)
				}

				verifyPublicKey(t, cert.PublicKey, pk)
			} else {
				t.Fatalf("failed to parse server generated private key")
			}

			// Verify bit size of returned key.
			wantBitsize := 2048
			if tc.bitsize != 0 {
				wantBitsize = tc.bitsize
			}

			if got := pk.(*rsa.PrivateKey).PublicKey.Size() * 8; got != wantBitsize {
				t.Fatalf("got bit size %d, want %d", got, wantBitsize)
			}
		})
	}
}

func TestTPMEnroll(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		aps string
		cn  string
		err error
	}{
		{
			aps: "anything",
			cn:  "John Doe",
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.aps, func(t *testing.T) {
			t.Parallel()

			// Create test EST server and client.
			s, newTestClient := newTestServer(t)
			defer s.Close()

			client := newTestClient()

			// Get CA certificates before setting additional path segment,
			// which may otherwise trigger errors.
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			cacerts, err := client.CACerts(ctx)
			if err != nil {
				t.Fatalf("failed to get CA certificates: %v", err)
			}

			client.AdditionalPathSegment = tc.aps

			// Request an EK certificate via normal enrollment.
			ek := mustGenerateRSAPrivateKey(t)
			csr := mustCreateCertificateRequest(t, ek, "Test TPM Device", nil)
			ekcert, err := client.Enroll(ctx, csr)
			if err != nil {
				t.Fatalf("failed to enroll for EK certificate: %v", err)
			}

			// Request an AK certificate with the TPM privacy-preserving protocol.
			ak := mustGenerateRSAPrivateKey(t)
			csr = mustCreateCertificateRequest(t, ak, tc.cn, nil)
			ekPub := makeRSAStoragePublicArea(t, ek)
			akPub := makeRSASignerPublicArea(t, ak)
			ekchain := append([]*x509.Certificate{ekcert}, cacerts...)

			blob, seed, enc, err := client.TPMEnroll(ctx, csr, ekchain, ekPub, akPub)
			if err != nil {
				t.Fatalf("failed to enroll for AK certificate: %v", err)
			}

			// Extract, parse, and decrypt the returned certificate.
			psk, err := tpm.ExtractCredential(ek, blob, seed, ekPub, akPub)
			if err != nil {
				t.Fatalf("failed to extract credential: %v", err)
			}

			p7, err := pkcs7.Parse(enc)
			if err != nil {
				t.Fatalf("failed to parse CMS EnvelopedData: %v", err)
			}

			der, err := p7.DecryptUsingPSK(psk)
			if err != nil {
				t.Fatalf("failed to decrypt CMS EnvelopedData: %v", err)
			}

			// Sanity-check the returned certificate.
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}

			if got := cert.Subject.CommonName; got != tc.cn {
				t.Fatalf("got common name %q, want %q", got, tc.cn)
			}

			verifyPublicKey(t, cert.PublicKey, ak)
		})
	}
}

func TestServerErrors(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t)
	defer s.Close()

	var testcases = []struct {
		name    string
		path    string
		method  string
		headers http.Header
		body    []byte
		status  int
		errText string
	}{
		{
			name:   "CACerts/BadMethod",
			path:   cacertsEndpoint,
			method: http.MethodPost,
			headers: http.Header{
				hostHeader: []string{testDomain},
			},
			status: http.StatusMethodNotAllowed,
		},
		{
			name:   "CACerts/TriggeredError",
			path:   "/.well-known/est/triggererrors/cacerts",
			method: http.MethodGet,
			headers: http.Header{
				hostHeader: []string{testDomain},
			},
			status:  http.StatusInternalServerError,
			errText: "500 internal server error\n",
		},
		{
			name:   "CSRAttrs/TriggeredError",
			path:   "/.well-known/est/triggererrors/csrattrs",
			method: http.MethodGet,
			headers: http.Header{
				hostHeader: []string{testDomain},
			},
			status:  http.StatusInternalServerError,
			errText: "500 internal server error\n",
		},
		{
			name:   "NotFound",
			path:   "/.well-known/est/nosuchoperation",
			method: http.MethodPost,
			headers: http.Header{
				hostHeader: []string{testDomain},
			},
			status:  http.StatusNotFound,
			errText: "404 page not found\n",
		},
		{
			name:   "Enroll/BadContentType",
			path:   enrollEndpoint,
			method: http.MethodPost,
			headers: http.Header{
				typeHeader:          []string{mimeTypeText},
				encodingHeader:      []string{encodingBase64},
				authorizationHeader: []string{authorizationValue},
				hostHeader:          []string{testDomain},
			},
			status:  http.StatusUnsupportedMediaType,
			errText: "415 Content-Type must be application/pkcs10\n",
		},
		{
			name:   "Enroll/MissingContentType",
			path:   enrollEndpoint,
			method: http.MethodPost,
			headers: http.Header{
				encodingHeader: []string{encodingBase64},
				hostHeader:     []string{testDomain},
			},
			status:  http.StatusUnsupportedMediaType,
			errText: "415 malformed or missing Content-Type header\n",
		},
		{
			name:   "Enroll/BadContentTransferEncoding",
			path:   enrollEndpoint,
			method: http.MethodPost,
			headers: http.Header{
				typeHeader:          []string{mimeTypePKCS10},
				encodingHeader:      []string{encodingBinary},
				authorizationHeader: []string{authorizationValue},
				hostHeader:          []string{testDomain},
			},
			status:  http.StatusUnsupportedMediaType,
			errText: "415 Content-Transfer-Encoding must be base64\n",
		},
		{
			name:   "Enroll/MissingContentTransferEncoding",
			path:   enrollEndpoint,
			method: http.MethodPost,
			headers: http.Header{
				typeHeader:          []string{mimeTypePKCS10},
				authorizationHeader: []string{authorizationValue},
				hostHeader:          []string{testDomain},
			},
			status:  http.StatusUnsupportedMediaType,
			errText: "415 missing Content-Transfer-Encoding header\n",
		},
		{
			name:   "Enroll/BadBase64",
			path:   enrollEndpoint,
			method: http.MethodPost,
			headers: http.Header{
				typeHeader:          []string{mimeTypePKCS10},
				encodingHeader:      []string{encodingBase64},
				authorizationHeader: []string{authorizationValue},
				hostHeader:          []string{testDomain},
			},
			body:    []byte(`not a base64 encoding`),
			status:  http.StatusBadRequest,
			errText: "400 invalid base64 encoding\n",
		},
		{
			name:   "Enroll/CAError",
			path:   "/.well-known/est/triggererrors/simpleenroll",
			method: http.MethodPost,
			headers: http.Header{
				typeHeader:          []string{mimeTypePKCS10},
				encodingHeader:      []string{encodingBase64},
				authorizationHeader: []string{authorizationValue},
				hostHeader:          []string{testDomain},
			},
			body:    mustMakeBase64CSR(t, "Trigger Error Unknown"),
			status:  http.StatusInternalServerError,
			errText: "500 internal server error\n",
		},
		{
			name:   "HealthCheck/NoAuth",
			path:   "/healthcheck",
			method: http.MethodGet,
			headers: http.Header{
				authorizationHeader: []string{"baad"},
				hostHeader:          []string{testDomain + ":666"},
			},
			status:  http.StatusUnauthorized,
			errText: "401 authorization required\n",
		},
		{
			name:   "HealthCheck/BadHost",
			path:   "/healthcheck",
			method: http.MethodGet,
			headers: http.Header{
				authorizationHeader: []string{authorizationValue},
				hostHeader:          []string{"some.wrong.domain"},
			},
			status:  http.StatusBadRequest,
			errText: "400 host not allowed\n",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(tc.method, s.URL+tc.path, ioutil.NopCloser(bytes.NewBuffer(tc.body)))
			if err != nil {
				t.Fatalf("failed to create new HTTP request: %v", err)
			}

			for key, values := range tc.headers {
				for _, value := range values {
					if key == hostHeader {
						r.Host = value
					}
					r.Header.Set(key, value)
				}
			}

			resp, err := s.Client().Do(r)
			if err != nil {
				t.Fatalf("failed to execute HTTP request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.status {
				t.Fatalf("got status code %d, want %d", resp.StatusCode, tc.status)
			}

			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read HTTP response body: %s", err)
			}

			if got := string(data); got != tc.errText {
				t.Fatalf("got error text %q, want %q", got, tc.errText)
			}
		})
	}
}

func newTestServer(t *testing.T) (*httptest.Server, func() *est.Client) {
	t.Helper()

	// Create new transient CA.
	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create new mock CA: %v", err)
	}

	// Obtain a TLS certificate for the server.
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "Test EST Server"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EST server private key: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, serverKey)
	if err != nil {
		t.Fatalf("failed to create EST server certificate request: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("failed to parse EST server certificate request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	serverCert, err := ca.Enroll(ctx, csr, "", nil)
	if err != nil {
		t.Fatalf("failed to enroll for EST server certificate: %v", err)
	}

	caCerts, err := ca.CACerts(ctx, "", nil)
	if err != nil {
		t.Fatalf("failed to obtain CA certificates: %v", err)
	}

	altCACerts, err := altCA.CACerts(ctx, "", nil)
	if err != nil {
		t.Fatalf("failed to obtain alternate CA certificates: %v", err)
	}

	var logger est.Logger

	if *fLog {
		logger = basiclogger.New(os.Stderr)
	}

	checkBasicAuth := func(
		ctx context.Context,
		r *http.Request,
		aps, username, password string,
	) error {
		if username != "testuser" || password != "xyzzy" {
			return errors.New("bad credentials")
		}
		return nil
	}

	// Create the EST server.
	cfg := &est.ServerConfig{
		CA:             ca,
		Timeout:        testTimeout,
		Logger:         logger,
		AllowedHosts:   []string{testDomain},
		RateLimit:      1000,
		CheckBasicAuth: checkBasicAuth,
	}

	r, err := est.NewRouter(cfg)
	if err != nil {
		t.Fatalf("failed to create new router: %v", err)
	}

	s := httptest.NewUnstartedServer(r)

	var clientCAs = x509.NewCertPool()
	clientCAs.AddCert(caCerts[len(caCerts)-1])
	clientCAs.AddCert(altCACerts[len(altCACerts)-1])

	tlsCerts := [][]byte{serverCert.Raw}
	for i, cert := range caCerts {
		if i != len(caCerts)-1 {
			tlsCerts = append(tlsCerts, cert.Raw)
		}
	}

	s.TLS = &tls.Config{
		ClientCAs:  clientCAs,
		ClientAuth: tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCerts,
				PrivateKey:  serverKey,
				Leaf:        serverCert,
			},
		},
	}

	s.StartTLS()

	return s, func() *est.Client {
		var rootCAs = x509.NewCertPool()
		rootCAs.AddCert(caCerts[len(caCerts)-1])

		c := est.Client{
			Host:           strings.TrimPrefix(s.URL, "https://"),
			ExplicitAnchor: rootCAs,
			HostHeader:     testDomain + ":" + strings.Split(s.URL, ":")[2],
			Username:       "testuser",
			Password:       "xyzzy",
		}

		return &c
	}
}

func mustGenerateECPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	return key
}

func mustGenerateRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	return key
}

func verifyPublicKey(t *testing.T, pub, priv interface{}) {
	t.Helper()

	var wantPublic interface{}

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		wantPublic = k.Public()

	case *ecdsa.PrivateKey:
		wantPublic = k.Public()

	default:
		t.Fatalf("unexpected private key type: %T", k)
	}

	if !reflect.DeepEqual(pub, wantPublic) {
		t.Fatalf("public key not as expected")
	}
}

func mustCreateCertificateRequest(
	t *testing.T,
	key interface{},
	commonName string,
	dnsNames []string,
) *x509.CertificateRequest {
	t.Helper()

	der, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: commonName},
			DNSNames: dnsNames,
		},
		key,
	)
	if err != nil {
		t.Fatalf("failed to create certificate request: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("failed to parse certificate request: %v", err)
	}

	return csr
}

func mustMakeAlternateCertChain(t *testing.T, key interface{}, cn string) []*x509.Certificate {
	t.Helper()

	csr := mustCreateCertificateRequest(t, key, cn, nil)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cert, err := altCA.Enroll(ctx, csr, "", nil)
	if err != nil {
		t.Fatalf("failed to enroll for alternate certificate: %v", err)
	}

	altCACerts, err := altCA.CACerts(ctx, "", nil)
	if err != nil {
		t.Fatalf("failed to obtain alternate CA certificates: %v", err)
	}

	return append([]*x509.Certificate{cert}, altCACerts...)
}

func mustMakeBase64CSR(t *testing.T, cn string) []byte {
	t.Helper()

	key := mustGenerateECPrivateKey(t)
	csr := mustCreateCertificateRequest(t, key, cn, nil)

	enc := make([]byte, base64.StdEncoding.EncodedLen(len(csr.Raw)))
	base64.StdEncoding.Encode(enc, csr.Raw)

	return enc
}

func makeRSAStoragePublicArea(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()

	pub := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: uint32(key.PublicKey.E),
			ModulusRaw:  key.PublicKey.N.Bytes(),
		},
	}

	b, err := pub.Encode()
	if err != nil {
		t.Fatalf("failed to encode public area: %v", err)
	}

	return b
}

func makeRSASignerPublicArea(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()

	pub := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			KeyBits:     2048,
			ExponentRaw: uint32(key.PublicKey.E),
			ModulusRaw:  key.PublicKey.N.Bytes(),
		},
	}

	b, err := pub.Encode()
	if err != nil {
		t.Fatalf("failed to encode public area: %v", err)
	}

	return b
}
