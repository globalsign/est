package est

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
