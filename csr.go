package est

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
)

func NewCSR(subjectCN string, key interface{}) (*x509.CertificateRequest, error) {
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "cn-field"},
		},
		key)

	if err != nil {
		return nil, err
	}

	os.WriteFile("./test.der", csr, os.ModePerm)

	return x509.ParseCertificateRequest(csr)
}

func NewCSRWithTlsUnique(subjectCN string, tlsUnique []byte, key interface{}) (*x509.CertificateRequest, error) {
	tlsUnique64 := base64Encode(tlsUnique)
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "cn-field"},
			ExtraExtensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, Critical: true, Value: tlsUnique64},
			},
		},
		key)

	if err != nil {
		return nil, err
	}

	os.WriteFile("./test-cp.der", csr, os.ModePerm)

	return x509.ParseCertificateRequest(csr)
}
