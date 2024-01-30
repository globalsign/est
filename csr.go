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

// Adds challenge password as an extension (and not as an attribute). Very likely to be rejected by the CA
func NewCSRWithTlsUnique(subjectCN string, tlsUnique []byte, key interface{}) (*x509.CertificateRequest, error) {
	tlsUnique64 := base64Encode(tlsUnique)
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "cn-field"},
			ExtraExtensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, Critical: false, Value: tlsUnique64},
			},
		},
		key)

	if err != nil {
		return nil, err
	}

	os.WriteFile("./test-cp.der", csr, os.ModePerm)

	return x509.ParseCertificateRequest(csr)
}

// Go stdlib does not support challenge password attribute. This function is useless.
func NewCSRWithTlsUniqueAttribute(subjectCN string, tlsUnique []byte, key interface{}) (*x509.CertificateRequest, error) {
	tlsUnique64 := base64Encode(tlsUnique)
	cpOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject:    pkix.Name{CommonName: "cn-field"},
			Attributes: []pkix.AttributeTypeAndValueSET{{Type: cpOID, Value: [][]pkix.AttributeTypeAndValue{{pkix.AttributeTypeAndValue{Type: cpOID, Value: tlsUnique64}}}}},
		},
		key)

	if err != nil {
		return nil, err
	}

	os.WriteFile("./test-cp.der", csr, os.ModePerm)

	return x509.ParseCertificateRequest(csr)
}
