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

package mockca_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/arlotito/est"
	"github.com/arlotito/est/internal/mockca"
	"github.com/arlotito/est/internal/tpm"
	"github.com/google/go-tpm/tpm2"
	"go.mozilla.org/pkcs7"
)

const (
	testTimeout          = time.Second * 60
	serverKeyGenPassword = "pseudohistorical"
)

func TestCACerts(t *testing.T) {
	t.Parallel()

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}

	var testcases = []struct {
		aps    string
		length int
		err    error
	}{
		{
			aps:    "anything",
			length: 2,
		},
		{
			aps: "triggererrors",
			err: errors.New("triggered error"),
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.aps, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			got, err := ca.CACerts(ctx, tc.aps, nil)
			if !reflect.DeepEqual(err, tc.err) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if length := len(got); length != tc.length {
				t.Fatalf("got %d certificates, want %d", length, tc.length)
			}

			// Return with no further tests for error test cases.
			if err != nil {
				return
			}

			// Ensure the issuing CA can be verified against the rest of the
			// chain (or against itself, if it's self-signed).
			roots := x509.NewCertPool()
			inters := x509.NewCertPool()

			for i, cert := range got {
				if i == len(got)-1 {
					roots.AddCert(cert)
				} else if i != 0 {
					inters.AddCert(cert)
				}
			}

			if _, err := got[0].Verify(x509.VerifyOptions{
				Intermediates: inters,
				Roots:         roots,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}); err != nil {
				t.Fatalf("failed to verify issuing certificate: %v", err)
			}
		})
	}
}

func TestCSRAttrs(t *testing.T) {
	t.Parallel()

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}

	var testcases = []struct {
		aps  string
		want est.CSRAttrs
		err  error
	}{
		{
			aps:  "anything",
			want: est.CSRAttrs{},
		},
		{
			aps: "csrattrs",
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
		{
			aps: "triggererrors",
			err: errors.New("triggered error"),
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.aps, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			got, err := ca.CSRAttrs(ctx, tc.aps, nil)
			if !reflect.DeepEqual(err, tc.err) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEnrollReenroll(t *testing.T) {
	t.Parallel()

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}

	var testcases = []struct {
		aps string
		cn  string
		err error
	}{
		{
			aps: "anything",
			cn:  "John Doe",
		},
		{
			aps: "triggererrors",
			cn:  "Trigger Error Forbidden",
			err: errors.New("triggered forbidden response"),
		},
		{
			aps: "triggererrors",
			cn:  "Trigger Error Deferred",
			err: errors.New("triggered deferred response"),
		},
		{
			aps: "triggererrors",
			cn:  "Trigger Error Unknown",
			err: errors.New("triggered error"),
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.aps, func(t *testing.T) {
			t.Parallel()

			// Build CSR.
			tmpl := &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: tc.cn},
				DNSNames: []string{"john.doe.domain"},
			}

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate private key: %v", err)
			}

			der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
			if err != nil {
				t.Fatalf("failed to create certificate request: %v", err)
			}

			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatalf("failed to parse certificate request: %v", err)
			}

			// Enroll.
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			got, err := ca.Enroll(ctx, csr, tc.aps, nil)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Fatalf("got error text %q, want %q", err.Error(), tc.err.Error())
				}

				return
			}

			// Verify received certificate against CA certificates.
			opts := x509.VerifyOptions{
				Intermediates: x509.NewCertPool(),
				Roots:         x509.NewCertPool(),
				CurrentTime:   time.Now(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}

			cacerts, err := ca.CACerts(ctx, tc.aps, nil)
			if err != nil {
				t.Fatalf("failed to get CA certificates: %v", err)
			}

			for i, cert := range cacerts {
				if i == len(cacerts)-1 {
					opts.Roots.AddCert(cert)
				} else {
					opts.Intermediates.AddCert(cert)
				}
			}

			if _, err := got.Verify(opts); err != nil {
				t.Fatalf("failed to verify certificate: %v", err)
			}

			// Check subject and SAN agree with CSR.
			if !bytes.Equal(got.RawSubject, csr.RawSubject) {
				t.Fatalf("got subject %s, want %s", got.Subject.String(), csr.Subject.String())
			}

			if !reflect.DeepEqual(got.DNSNames, csr.DNSNames) {
				t.Fatalf("got DNS names %v, want %v", got.DNSNames, csr.DNSNames)
			}

			// Reenroll with received certificate.
			_, err = ca.Reenroll(ctx, got, csr, tc.aps, nil)
			if err != nil {
				t.Fatalf("failed to reenroll: %v", err)
			}
		})
	}
}

func TestServerKeyGen(t *testing.T) {
	t.Parallel()

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}

	var testcases = []struct {
		aps     string
		cn      string
		bitsize int
		err     error
	}{
		{
			aps: "anything",
			cn:  "John Doe",
		},
		{
			aps:     "pkcs7",
			bitsize: 3072,
			cn:      "Jane Doe",
		},
		{
			aps: "triggererrors",
			cn:  "Trigger Error Unknown",
			err: errors.New("triggered error"),
		},
		{
			aps:     "anything",
			cn:      "Try this on for size",
			bitsize: 42,
			err:     errors.New("invalid bit size value"),
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.aps, func(t *testing.T) {
			t.Parallel()

			// Build CSR.
			tmpl := &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: tc.cn},
				DNSNames: []string{"john.doe.domain"},
			}

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate private key: %v", err)
			}

			der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
			if err != nil {
				t.Fatalf("failed to create certificate request: %v", err)
			}

			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatalf("failed to parse certificate request: %v", err)
			}

			var r *http.Request
			if tc.bitsize != 0 {
				r = &http.Request{
					Header: map[string][]string{
						"Bit-Size": {strconv.Itoa(tc.bitsize)},
					},
				}
			}

			// Request certificate and private key.
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			got, keyDER, err := ca.ServerKeyGen(ctx, csr, tc.aps, r)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Fatalf("got error text %q, want %q", err.Error(), tc.err.Error())
				}

				return
			}

			// Retrieve private key from returned bytes.
			var privKey interface{}

			if p8, err := x509.ParsePKCS8PrivateKey(keyDER); err == nil {
				privKey = p8
			} else if p7, err := pkcs7.Parse(keyDER); err == nil {
				der, err := p7.DecryptUsingPSK([]byte(serverKeyGenPassword))
				if err != nil {
					t.Fatalf("failed to decrypt CMS EnvelopedData: %v", err)
				}

				sd, err := pkcs7.Parse(der)
				if err != nil {
					t.Fatalf("failed to parse CMS SignedData: %v", err)
				}

				privKey, err = x509.ParsePKCS8PrivateKey(sd.Content)
				if err != nil {
					t.Fatalf("failed to parse private key: %v", err)
				}
			} else {
				t.Fatalf("failed to parse server generated private key")
			}

			// Extract public key from private key.
			var pubKey interface{}
			var bitsize int
			var wantBitsize int
			switch k := privKey.(type) {
			case *rsa.PrivateKey:
				pubKey = k.Public()
				bitsize = k.PublicKey.Size() * 8
				wantBitsize = 2048

			case *ecdsa.PrivateKey:
				pubKey = k.Public()
				bitsize = k.PublicKey.Curve.Params().BitSize
				wantBitsize = 256

			default:
				t.Fatalf("unexpected private key type: %T", k)
			}

			// Ensure public key corresponding with server generated private
			// key was the one included in the certificate.
			if !reflect.DeepEqual(pubKey, got.PublicKey) {
				t.Fatalf("received public keys doesn't match certificate")
			}

			// Verify the bit size of the returned key.
			if tc.bitsize != 0 {
				wantBitsize = tc.bitsize
			}

			if bitsize != wantBitsize {
				t.Fatalf("got bit size %d, want %d", bitsize, wantBitsize)
			}
		})
	}
}

func TestTPMEnroll(t *testing.T) {
	t.Parallel()

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}

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

			// Build CSR for EK certificate.
			ek, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate endorsement private key: %v", err)
			}

			tmpl := &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "Test TPM Device"},
			}

			der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, ek)
			if err != nil {
				t.Fatalf("failed to create EK certificate request: %v", err)
			}

			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatalf("failed to parse EK certificate request: %v", err)
			}

			// Request EK certificate.
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			ekcert, err := ca.Enroll(ctx, csr, tc.aps, nil)
			if err != nil {
				t.Fatalf("failed to enroll for EK certificate: %v", err)
			}

			cacerts, err := ca.CACerts(ctx, tc.aps, nil)
			if err != nil {
				t.Fatalf("failed to get CA certificates: %v", err)
			}

			var ekchain = append([]*x509.Certificate{ekcert}, cacerts...)

			// Build CSR for AK certificate.
			ak, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate attestation private key: %v", err)
			}

			tmpl = &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: tc.cn},
			}

			der, err = x509.CreateCertificateRequest(rand.Reader, tmpl, ak)
			if err != nil {
				t.Fatalf("failed to create AK certificate request: %v", err)
			}

			csr, err = x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatalf("failed to parse AK certificate request: %v", err)
			}

			// TPM-enroll for certificate.
			ekPub := makeRSAStoragePublicArea(t, ek)
			akPub := makeRSASignerPublicArea(t, ak)

			blob, secret, p7Bytes, err := ca.TPMEnroll(ctx, csr, ekchain, ekPub, akPub, tc.aps, nil)
			if err != nil {
				t.Fatalf("failed to enroll for AK certificate: %v", err)
			}

			// Extract, parse, and decrypt the returned certificate.
			cred, err := tpm.ExtractCredential(ek, blob, secret, ekPub, akPub)
			if err != nil {
				t.Fatalf("failed to extract credential: %v", err)
			}

			p7, err := pkcs7.Parse(p7Bytes)
			if err != nil {
				t.Fatalf("failed to parse CMS EnvelopedData: %v", err)
			}

			der, err = p7.DecryptUsingPSK(cred)
			if err != nil {
				t.Fatalf("failed to decrypt CMS EnvelopedData: %v", err)
			}

			// Sanity-check the returned certificate.
			got, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}

			if cn := got.Subject.CommonName; cn != tc.cn {
				t.Fatalf("got common name %q, want %q", cn, tc.cn)
			}
		})
	}
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
