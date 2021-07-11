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

	// make sure adequate set of filtering flags was passed
	numberOfFilterFlagsSet := 0
	filterFlags := []bool{cfg.FlagWasPassed(rootsOnlyFlag), cfg.FlagWasPassed(intermediatesOnlyFlag), cfg.FlagWasPassed(rootOutFlag)}
	for _, flag := range filterFlags {
		if flag {
			numberOfFilterFlagsSet++
		}
	}
	if numberOfFilterFlagsSet > 1 {
		return fmt.Errorf("only one of -%s, -%s and -%s may be specified", rootsOnlyFlag, intermediatesOnlyFlag, rootOutFlag)
	}

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

	// filter certificates if requested
	if numberOfFilterFlagsSet == 1 {
		var roots, intermediates []*x509.Certificate

		for _, cert := range certs {
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil {
				roots = append(roots, cert)
				if cfg.FlagWasPassed(rootOutFlag) {
					break
				}
			} else {
				intermediates = append(intermediates, cert)
			}
		}

		if cfg.FlagWasPassed(rootsOnlyFlag) || cfg.FlagWasPassed(rootOutFlag) {
			certs = roots
		} else if cfg.FlagWasPassed(intermediatesOnlyFlag) {
			certs = intermediates
		}
	}

	if cfg.FlagWasPassed(rootOutFlag) && len(certs) == 0 {
		return errors.New("failed to find a root certificate in CA certificates")
	}

	out, closeFunc, err := maybeRedirect(w, cfg.FlagValue(outFlag), 0666)
	if err != nil {
		return err
	}
	defer closeFunc()

	if err := pemfile.WriteCerts(out, certs); err != nil {
		return fmt.Errorf("failed to write CA certificates: %v", err)
	}

	return nil
}
