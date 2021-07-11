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
	"bytes"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"log"

	"github.com/globalsign/pemfile"
)

// cacerts requests the current CA certificates.
func cacerts(w io.Writer, set *flag.FlagSet) error {
	cfg, err := newConfig(set)
	if err != nil {
		return fmt.Errorf("failed to get configuration: %v", err)
	}
	defer func() {
		if err := cfg.Close(); err != nil {
			log.Printf("failed to close configuration: %v", err)
		}
	}()

	client, err := cfg.MakeClient()
	if err != nil {
		return fmt.Errorf("failed to make EST client: %v", err)
	}

	ctx, cancel := cfg.MakeContext()
	defer cancel()

	certs, err := client.CACerts(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CA certificates: %v", err)
	}

	// find root CA
	var root *x509.Certificate
	for _, cert := range certs {
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil {
			root = cert
			break
		}
	}

	if prefix := cfg.FlagValue(separateOutFlag); len(prefix) > 0 {
		var filename string
		subca_idx := 1

		// sort by NotBefore to provide a predictable and stable index
		sort.SliceStable(certs, func(i, j int) bool { return certs[i].NotBefore.Before(certs[j].NotBefore) })

		for _, cert := range certs {
			if cert == root {
				filename = fmt.Sprintf("%s-ca-root.pem", prefix)
			} else {
				filename = fmt.Sprintf("%s-ca-%d.pem", prefix, subca_idx)
				subca_idx++
			}

			out, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				return fmt.Errorf("failed to create output file: %v", err)
			}
			defer out.Close()

			if err := pemfile.WriteCert(out, cert); err != nil {
				return fmt.Errorf("failed to write CA certificate: %v", err)
			}
		}
	} else {
		if cfg.FlagWasPassed(rootOutFlag) {
			if root == nil {
				return errors.New("failed to find a root certificate in CA certificates")
			}
			certs = []*x509.Certificate{root}
		}

		out, closeFunc, err := maybeRedirect(w, cfg.FlagValue(outFlag), 0666)
		if err != nil {
			return err
		}
		defer closeFunc()

		if err := pemfile.WriteCerts(out, certs); err != nil {
			return fmt.Errorf("failed to write CA certificates: %v", err)
		}
	}

	return nil
}
