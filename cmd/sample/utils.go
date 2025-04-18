package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/globalsign/est"
)

const (
	// est config
	estServerHost            string = "localhost:9443"
	estUsername, estPassword string = "test", "test"

	// csr config
	subjectCN string = "cert-cn-field"
)

type config struct {
	Host               string
	Username           string
	Password           string
	ExplicitAnchor     *x509.Certificate
	InsecureSkipVerify bool
}

func newEstClient(conf config) *est.Client {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	certPool := x509.NewCertPool()

	if conf.ExplicitAnchor != nil {
		certPool.AddCert(conf.ExplicitAnchor)
	}

	return &est.Client{
		Host:               conf.Host,
		Username:           conf.Username,
		Password:           conf.Password,
		ExplicitAnchor:     certPool,
		PrivateKey:         key,
		InsecureSkipVerify: conf.InsecureSkipVerify,
	}
}

func newConfig(explicitAnchor *x509.Certificate) config {
	insecure := true
	if explicitAnchor != nil {
		insecure = false
	}

	return config{
		Host:               estServerHost,
		Username:           estUsername,
		Password:           estPassword,
		ExplicitAnchor:     explicitAnchor,
		InsecureSkipVerify: insecure,
	}
}

func newCSR(commonName string, key any) (*x509.CertificateRequest, error) {
	csrBs, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: commonName},
		},
		key,
	)

	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(csrBs)
}
