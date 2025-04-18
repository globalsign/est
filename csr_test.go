package est

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"strings"
	"testing"
)

func TestCreateCertificateRequest(t *testing.T) {
	// arrange
	subjectCN := "cn-field"
	priv := mustGenerateECPrivateKey(t)
	tlsUnique := []byte{84, 109, 241, 191, 39, 122, 251, 247, 30, 221, 0, 205}
	tlsUnique64 := base64Encode(tlsUnique)

	req := &CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject: pkix.Name{CommonName: subjectCN},
		},
		ChallengePassword: string(tlsUnique64),
	}

	tests := map[string]struct {
		reader  io.Reader
		csr     *CertificateRequest
		key     any
		passing bool
	}{
		"NOK nil csr":   {reader: rand.Reader, csr: nil, key: priv, passing: false},
		"NOK nil key":   {reader: rand.Reader, csr: req, key: nil, passing: false},
		"OK ":           {reader: rand.Reader, csr: req, key: priv, passing: true},
		"OK nil reader": {reader: nil, csr: req, key: priv, passing: true},
	}

	for name, ctx := range tests {
		t.Run(name, func(t *testing.T) {
			// act
			csrBs, err := CreateCertificateRequest(ctx.reader, ctx.csr, ctx.key)

			if err != nil && ctx.passing {
				t.Error("Expected to pass but got an error: ", err)
			}
			if err == nil && !ctx.passing {
				t.Error("Expected to fail but did not get any error")
			}

			// assert
			if err == nil && csrBs != nil {
				cp, err := ParseChallengePassword(csrBs)
				if err != nil {
					t.Error(err)
				}
				if !strings.EqualFold(cp, string(tlsUnique64)) {
					t.Errorf("Expected %s, but got %s instead", string(tlsUnique64), cp)
				}
			}
		})
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
