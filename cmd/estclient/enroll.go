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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"

	"go.mozilla.org/pkcs7"

	"github.com/globalsign/pemfile"
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// enroll requests a new certificate.
func enroll(w io.Writer, set *flag.FlagSet) error {
	return enrollCommon(w, set, false, false)
}

// reenroll renews an existing certificate.
func reenroll(w io.Writer, set *flag.FlagSet) error {
	return enrollCommon(w, set, true, false)
}

// serverkeygen requests a private key and an associated certificate.
func serverkeygen(w io.Writer, set *flag.FlagSet) error {
	return enrollCommon(w, set, false, true)
}

// enrollCommon services both enroll and reenroll.
func enrollCommon(w io.Writer, set *flag.FlagSet, renew, keygen bool) error {
	cfg, err := newConfig(set)
	if err != nil {
		return fmt.Errorf("failed to get configuration: %v", err)
	}
	defer func() {
		if err := cfg.Close(); err != nil {
			log.Printf("failed to close configuration: %v", err)
		}
	}()

	if renew && len(cfg.certificates) == 0 {
		return errors.New("no client certificate provided")
	}

	client, err := cfg.MakeClient()
	if err != nil {
		return fmt.Errorf("failed to make EST client: %v", err)
	}

	// Get or build CSR.
	var csr *x509.CertificateRequest
	if cfg.FlagWasPassed(csrFlag) {
		csr, err = pemfile.ReadCSR(cfg.FlagValue(csrFlag))
		if err != nil {
			return fmt.Errorf("failed to read CSR from file: %v", err)
		}
	} else {
		if renew {
			// Copy raw Subject field and SubjectAltName extension from
			// certificate to be renewed.
			tmpl := &x509.CertificateRequest{
				RawSubject: cfg.certificates[0].RawSubject,
			}

			for _, ext := range cfg.certificates[0].Extensions {
				if ext.Id.Equal(oidSubjectAltName) {
					tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
					break
				}
			}

			// Construct the certificate request from the template.
			der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, cfg.openPrivateKey)
			if err != nil {
				return fmt.Errorf("failed to create certificate request: %v", err)
			}

			csr, err = x509.ParseCertificateRequest(der)
			if err != nil {
				return fmt.Errorf("failed to parse certificate request: %v", err)
			}
		} else {
			if keygen {
				var csrkey *ecdsa.PrivateKey
				csrkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return fmt.Errorf("failed to generate temporary private key: %v", err)
				}
				csr, err = cfg.GenerateCSR(csrkey)
			} else {
				csr, err = cfg.GenerateCSR(nil)
			}
			if err != nil {
				return fmt.Errorf("failed to create certificate request: %v", err)
			}
		}
	}

	// Request new certificate.
	ctx, cancel := cfg.MakeContext()
	defer cancel()

	var cert *x509.Certificate
	var key []byte
	if renew {
		cert, err = client.Reenroll(ctx, csr.Raw)
	} else if keygen {
		cert, key, err = client.ServerKeyGen(ctx, csr.Raw)
	} else {
		cert, err = client.Enroll(ctx, csr.Raw)
	}
	if err != nil {
		return fmt.Errorf("failed to get certificate: %v", err)
	}

	// Output key if received.
	if key != nil {
		out, closeFunc, err := maybeRedirect(w, cfg.FlagValue(keyOutFlag), 0600)
		if err != nil {
			return err
		}
		defer closeFunc()

		if _, err := x509.ParsePKCS8PrivateKey(key); err == nil {
			pemfile.WriteBlock(out, &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: key,
			})
		} else if _, err := pkcs7.Parse(key); err == nil {
			pemfile.WriteBlock(out, &pem.Block{
				Type:  "PKCS7",
				Bytes: key,
			})
		} else {
			return errors.New("unrecognized private key format")
		}
	}

	// Output certificate.
	out, closeFunc, err := maybeRedirect(w, cfg.FlagValue(outFlag), 0666)
	if err != nil {
		return err
	}
	defer closeFunc()

	if err := pemfile.WriteCert(out, cert); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	return nil
}
