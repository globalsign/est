package est

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

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

// Not working either, can't read the file and challenge password does not appear after parsing the CSR
func NewCSRWithChallengePassword(subjectCN string, tlsUnique []byte, key interface{}) (*x509.CertificateRequest, error) {
	// https://github.com/micromdm/scep/blob/4a4f8bc7f7bc34083b0737060db8ef7b55005472/scep/scep.go#L285
	cpOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	tlsUnique64 := base64Encode(tlsUnique)

	csrWithoutCp, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "cn-field"},
		},
		key)

	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrWithoutCp)

	if err != nil {
		return nil, err
	}

	var req certificateRequest

	rest, err := asn1.Unmarshal(csr.Raw, &req)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return nil, err
	}

	challengePasswordAttribute := pkix.AttributeTypeAndValue{
		Type:  cpOID,
		Value: tlsUnique64,
	}

	cpBs, err := asn1.Marshal(challengePasswordAttribute)

	if err != nil {
		return nil, err
	}

	var rawAttribute asn1.RawValue
	rest, err = asn1.Unmarshal(cpBs, &rawAttribute)

	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return nil, err
	}
	// append attribute
	req.TBSCSR.RawAttributes = append(req.TBSCSR.RawAttributes, rawAttribute)

	// recreate request
	tbsCSR := tbsCertificateRequest{
		Version:       0,
		Subject:       req.TBSCSR.Subject,
		PublicKey:     req.TBSCSR.PublicKey,
		RawAttributes: req.TBSCSR.RawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return nil, err
	}
	tbsCSR.Raw = tbsCSRContents

	// marshal csr with challenge password
	req2 := certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: req.SignatureAlgorithm,
		SignatureValue:     req.SignatureValue,
	}

	csrBytes, err := asn1.Marshal(req2)
	if err != nil {
		return nil, err
	}

	x509.ParseCertificateRequest(csrBytes)

	os.WriteFile("./test-cp.der", csrBytes, os.ModePerm)

	return x509.ParseCertificateRequest(csrBytes)
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
