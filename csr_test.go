package est

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"os"
	"strings"
	"testing"
)

func TestCreateCertificateRequest(t *testing.T) {
	// arrange
	csrFilePath := "./test-cp.der"
	subjectCN := "cn-field"
	priv, err := getPrivateKey()
	tlsUnique := []byte{84, 109, 241, 191, 39, 122, 251, 247, 30, 221, 0, 205}
	tlsUnique64 := base64Encode(tlsUnique)

	if err != nil {
		t.Error(err)
	}

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
				os.WriteFile(csrFilePath, csrBs, os.ModePerm)
				if _, err := os.Stat(csrFilePath); err != nil {
					t.Error(err)
				}

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

func getPrivateKey() (*rsa.PrivateKey, error) {
	pemString := `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC1lvKSFP20Z93y
Dnfu9N1O8xret7v4LRRi5GRlIsFbr4oI7yGK55k2TqrzDe/Pqbo6QUPFgu6PKzIm
/2yyGz2vkpma0/3ffyK0yFQ/zLPJy341bgImduyiaUd3W+6gA8a47cjFIXHTA2uO
PaNrOWmINmDSZrzq0+sQudnjlrc1JM18FhyInB3mTHQ+hMdclY3MteRxXhvHmE4F
BgNQwRa5Kab/V0RX6wup98BTjEecjSW6qWYtYegBzk6U1STUHHtMZlQciGRfNoQv
bYcOEc52h9KAu8HTtqGLmNenp1UorrU8+ZG2NMQ7aBO16f9Usz3sSJv6qKkX386x
q0wQFpklAgMBAAECggEAHj2PE+jO/1Y0zfS+4FqC6HzvwptSgFfxhy6F0ZniHYS0
Nhyst1cuWq7rJSLzBuA7FSx9Ps05MTp+VaQ/08FZmn2New1GwAuKGhUqgp1ya26q
C/fP/9vaOInTzvrOWHOIio9+2eVh8UQmiz+UkWy0OGzl3uQhHfJAuT5aHN6ikATS
kgieU8HuOmoiVzG9/lV/i7Z99eOWUu7odj1HVcs5pz8mAZaCLGYEhxkkHbdSZkLL
8ZzB/ENO1B5yY5Sy2PYqq0Dv4M+Swg6uJOrEhByHLlcd1YwsfMyg4YciOnOqxyXl
MTwUMpoCMtH9ulUldli5pV+Fw2ZsvYsTUTkmHqdSwQKBgQD1Va9aAFe6JgNbRLD4
Onfk0Lhw1nwdD+Y+Rc/+OmRPXqaXxnuJjD3PfKeJaHWLyw8HlzUqCJM8L3KL+dM2
6PuJeaP1lKHuL63sVEJeMlZizxmqvgCokLRc2StG69ZUooqcyayBTvOZVQK7XSSA
PleV9SQ8uiBxGtXmULODwjfT3QKBgQC9e9j7kZi8+FZPINs9hBSb3g8lKKmB9zuT
TwzLRC65UNRINAOoVnxIrSgrf6BHEEex2wFPNo6EPcHsT1AHNk4hN91FNETD7YqP
C8uQ15RP9JgLOPMQa1/Fm6zbDWYzc5hKApaKvAUl6GiduOvIGDrpW9XQef7DOYNL
32Kp9OQJ6QKBgEj/UcmJyJCOtvj1G2MAoqPmprqMVymejXeB9j1Cyo4DL7aBTEjE
/a86++6asj8CEFrF1v/GxWhnBcI4d2wjLpTdKLftnbDtZuamu4ijmaiUzqJLHo8J
X2ExDPtxOLi+FFhKeZWQFFNPRBzTvgSaiB0Kb9nR181Pms2IvaE6rLnRAoGAM7Z/
K3k69CfadlIDQ7CuZzOdcoi8akntKnDijv8WuWDD7sizTtf7p2IKmoSEW6Cn0HRy
0QmUr6ajLDkhIDbD7/DtJJv1QHut2whfEDKluYSJklaCj7KeOrIX5NitUdF0eI5o
Q4i45vWcx57WSo/CVDnKCtGgo+soWCapKLU7HzECgYAB6L3XVayDtLNtXB1T2NTO
jwlPTXY6wPN21m8WllT7ChmKiZmV+0VVaeG3wLcNMwggNPOTZ1Ydxowl5rcnpPmp
LYWF7wp95V5gr29g9l9HXJCVLcprekD5nMWHg4S09gotRS6SazjILAlFIeBvvNjo
V3zY7yop7YGf3NxD9bdo3w==
-----END PRIVATE KEY-----
`
	pemBlock, _ := pem.Decode([]byte(pemString))
	private, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key := private.(*rsa.PrivateKey)
	return key, err
}
