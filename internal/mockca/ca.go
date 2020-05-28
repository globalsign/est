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

package mockca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"go.mozilla.org/pkcs7"

	"github.com/globalsign/pemfile"

	"github.com/globalsign/est"
	"github.com/globalsign/est/internal/tpm"
)

// MockCA is a mock, non-production certificate authority useful for testing
// purposes only.
type MockCA struct {
	certs []*x509.Certificate
	key   interface{}
}

// Global constants.
const (
	alphanumerics              = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	bitSizeHeader              = "Bit-Size"
	csrAttrsAPS                = "csrattrs"
	defaultCertificateDuration = time.Hour * 24 * 90
	serverKeyGenPassword       = "pseudohistorical"
	rootCertificateDuration    = time.Hour * 24
	triggerErrorsAPS           = "triggererrors"
)

// Global variables.
var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func init() {
	// Set default content encryption algorithm for PKCS7 package, which
	// otherwise defaults to 3DES.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128GCM
}

// CACerts returns the CA certificates, unless the additional path segment is
// "triggererrors", in which case an error is returned for testing purposes.
func (ca *MockCA) CACerts(
	ctx context.Context,
	aps string,
	r *http.Request,
) ([]*x509.Certificate, error) {
	if aps == triggerErrorsAPS {
		return nil, errors.New("triggered error")
	}

	return ca.certs, nil
}

// CSRAttrs returns an empty sequence of CSR attributes, unless the additional
// path segment is:
//  - "csrattrs", in which case it returns the same example sequence described
//    in RFC7030 4.5.2; or
//  - "triggererrors", in which case an error is returned for testing purposes.
func (ca *MockCA) CSRAttrs(
	ctx context.Context,
	aps string,
	r *http.Request,
) (attrs est.CSRAttrs, err error) {
	switch aps {
	case csrAttrsAPS:
		attrs = est.CSRAttrs{
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
		}

	case triggerErrorsAPS:
		err = errors.New("triggered error")
	}

	return attrs, err
}

// Enroll issues a new certificate with:
//   - a 90 day duration from the current time
//   - a randomly generated 128-bit serial number
//   - a subject and subject alternative name copied from the provided CSR
//   - a default set of key usages and extended key usages
//   - a basic constraints extension with cA flag set to FALSE
//
// unless the additional path segment is "triggererrors", in which case the
// following errors will be returned for testing purposes, depending on the
// common name in the CSR:
//
//   - "Trigger Error Forbidden", HTTP status 403
//   - "Trigger Error Deferred", HTTP status 202 with retry of 600 seconds
//   - "Trigger Error Unknown", untyped error expected to be interpreted as
//     an internal server error.
func (ca *MockCA) Enroll(
	ctx context.Context,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	// Process any requested triggered errors.
	if aps == triggerErrorsAPS {
		switch csr.Subject.CommonName {
		case "Trigger Error Forbidden":
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "triggered forbidden response",
			}

		case "Trigger Error Deferred":
			return nil, caError{
				status:     http.StatusAccepted,
				desc:       "triggered deferred response",
				retryAfter: 600,
			}

		case "Trigger Error Unknown":
			return nil, errors.New("triggered error")
		}
	}

	// Generate certificate template, copying the raw subject and raw
	// SubjectAltName extension from the CSR.
	sn, err := rand.Int(rand.Reader, big.NewInt(1).Exp(big.NewInt(2), big.NewInt(128), nil))
	if err != nil {
		return nil, fmt.Errorf("failed to make serial number: %w", err)
	}

	ski, err := makePublicKeyIdentifier(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to make public key identifier: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(defaultCertificateDuration)
	if latest := ca.certs[0].NotAfter.Sub(notAfter); latest < 0 {
		// Don't issue any certificates which expire after the CA certificate.
		notAfter = ca.certs[0].NotAfter
	}

	var tmpl = &x509.Certificate{
		SerialNumber:          sn,
		NotBefore:             now,
		NotAfter:              notAfter,
		RawSubject:            csr.RawSubject,
		SubjectKeyId:          ski,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			break
		}
	}

	// Create and return certificate.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.certs[0], csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Reenroll implements est.CA but simply passes the request through to Enroll.
func (ca *MockCA) Reenroll(
	ctx context.Context,
	cert *x509.Certificate,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	return ca.Enroll(ctx, csr, aps, r)
}

// ServerKeyGen creates a new RSA private key and then calls Enroll. It returns
// the key in PKCS8 DER-encoding, unless the additional path segment is set to
// "pkcs7", in which case it is returned wrapped in a CMS SignedData structure
// signed by the CA certificate(s), itself wrapped in a CMS EnvelopedData
// encrypted with the pre-shared key "pseudohistorical". A "Bit-Size" HTTP
// header may be passed with the values 2048, 3072 or 4096.
func (ca *MockCA) ServerKeyGen(
	ctx context.Context,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, []byte, error) {
	bitsize := 2048
	if r != nil && r.Header != nil {
		if v := r.Header.Get(bitSizeHeader); v != "" {
			var err error
			bitsize, err = strconv.Atoi(v)
			if err != nil || (bitsize != 2048 && bitsize != 3072 && bitsize != 4096) {
				return nil, nil, caError{
					status: http.StatusBadRequest,
					desc:   "invalid bit size value",
				}
			}
		}
	}

	// Generate new key.
	key, err := rsa.GenerateKey(rand.Reader, bitsize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Copy raw subject and raw SubjectAltName extension from client CSR into
	// a new CSR signed by the new private key.
	tmpl := &x509.CertificateRequest{
		RawSubject: csr.RawSubject,
	}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			break
		}
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	newCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	// Enroll for certificate using the new CSR signed with the new key.
	cert, err := ca.Enroll(ctx, newCSR, aps, r)
	if err != nil {
		return nil, nil, err
	}

	// Marshal generated private key.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Based on value of additional path segment, return private key either
	// as a DER-encoded PKCS8 PrivateKeyInfo structure, or as that structure
	// wrapped in a CMS SignedData inside a CMS EnvelopedData structure.
	var retDER []byte

	switch aps {
	case "pkcs7":
		// Create the CMS SignedData structure.
		signedData, err := pkcs7.NewSignedData(keyDER)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create CMS SignedData: %w", err)
		}

		for i, cert := range ca.certs {
			if i == 0 {
				err := signedData.AddSigner(cert, ca.key, pkcs7.SignerInfoConfig{})
				if err != nil {
					return nil, nil, fmt.Errorf("failed to add signed to CMS SignedData: %w", err)
				}
			} else {
				signedData.AddCertificate(cert)
			}
		}

		sdBytes, err := signedData.Finish()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to finish CMS SignedData: %w", err)
		}

		// Encrypt the CMS SignedData in a CMS EnvelopedData structure.
		retDER, err = pkcs7.EncryptUsingPSK(sdBytes, []byte(serverKeyGenPassword))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create CMS EnvelopedData: %w", err)
		}

	default:
		retDER = keyDER
	}

	return cert, retDER, nil
}

// TPMEnroll requests a new certificate using the TPM 2.0 privacy-preserving
// protocol. An EK certificate chain with a length of at least one must be
// provided, along with the EK and AK public areas. The return values are an
// encrypted credential, a wrapped encryption key, and the certificate itself
// encrypted with the encrypted credential in AES 128 Galois Counter Mode
// inside a CMS EnvelopedData structure.
func (ca *MockCA) TPMEnroll(
	ctx context.Context,
	csr *x509.CertificateRequest,
	ekcerts []*x509.Certificate,
	ekPub, akPub []byte,
	aps string,
	r *http.Request,
) ([]byte, []byte, []byte, error) {
	cert, err := ca.Enroll(ctx, csr, aps, r)
	if err != nil {
		return nil, nil, nil, err
	}

	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate AES key random bytes: %w", err)
	}

	blob, secret, err := tpm.MakeCredential(key, ekPub, akPub)
	if err != nil {
		return nil, nil, nil, err
	}

	cred, err := pkcs7.EncryptUsingPSK(cert.Raw, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create CMS EnvelopedData: %w", err)
	}

	return blob, secret, cred, err
}

// New creates a new mock certificate authority. If more than one CA certificate
// is provided, they should be in order with the issuing (intermediate) CA
// certificate first, and the root CA certificate last. The private key should
// be associated with the public key in the first, issuing CA certificate.
func New(cacerts []*x509.Certificate, key interface{}) (*MockCA, error) {
	if len(cacerts) < 1 {
		return nil, errors.New("no CA certificates provided")
	} else if key == nil {
		return nil, errors.New("no private key provided")
	}

	for i := range cacerts {
		if !cacerts[i].IsCA {
			return nil, fmt.Errorf("certificate at index %d is not a CA certificate", i)
		}
	}

	return &MockCA{
		certs: cacerts,
		key:   key,
	}, nil
}

// NewFromFiles creates a new mock certificate authority from a PEM-encoded
// CA certificates chain and a (unencrypted) PEM-encoded private key contained
// in files. If more than one certificate is contained in the file, the
// certificates should appear in order with the issuing (intermediate) CA
// certificate first, and the root certificate last. The private key should be
// associated with the public key in the first certificate in certspath.
func NewFromFiles(certspath, keypath string) (*MockCA, error) {
	certs, err := pemfile.ReadCerts(certspath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificates from file: %w", err)
	}

	key, err := pemfile.ReadPrivateKey(keypath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA private key from file: %w", err)
	}

	return New(certs, key)
}

// NewTransient creates a new mock certificate authority with an automatically
// generated and transient CA certificates chain for testing purposes.
func NewTransient() (*MockCA, error) {
	// Generate a random element for the CA subject common names.
	randomSuffix, err := makeRandomIdentifier(8)
	if err != nil {
		return nil, err
	}

	// Generate root CA private key and certificate.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root CA private key: %w", err)
	}

	rootKI, err := makePublicKeyIdentifier(rootKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to make root CA public key identifier: %w", err)
	}

	now := time.Now()

	var tmpl = &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now,
		NotAfter:              now.Add(rootCertificateDuration),
		Subject:               pkix.Name{CommonName: "Non-Production Testing Root CA " + randomSuffix},
		SubjectKeyId:          rootKI,
		AuthorityKeyId:        rootKI,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create root CA certificate: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	// Generate intermediate CA private key and certificate.
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate intermediate CA private key: %w", err)
	}

	interKI, err := makePublicKeyIdentifier(interKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to make intermediate CA public key identifier: %w", err)
	}

	tmpl = &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             now,
		NotAfter:              now.Add(rootCertificateDuration),
		Subject:               pkix.Name{CommonName: "Non-Production Testing Intermediate CA " + randomSuffix},
		SubjectKeyId:          interKI,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	interDER, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, interKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate CA certificate: %w", err)
	}

	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}

	return New([]*x509.Certificate{interCert, rootCert}, interKey)
}

// makePublicKeyIdentifier builds a public key identifier in accordance with the
// first method described in RFC5280 section 4.2.1.2.
func makePublicKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	id := sha1.Sum(keyBytes)

	return id[:], nil
}

// makeRandomIdentifier makes a random alphanumeric identifier of length n.
func makeRandomIdentifier(n int) (string, error) {
	var id = make([]byte, n)

	for i := range id {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumerics))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}

		id[i] = alphanumerics[idx.Int64()]
	}

	return string(id), nil
}
