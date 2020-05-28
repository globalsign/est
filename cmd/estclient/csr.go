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
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/globalsign/pemfile"
)

// csr generates a PKCS#10 certificate signing request.
func csr(w io.Writer, set *flag.FlagSet) error {
	cfg, err := newConfig(set)
	if err != nil {
		return err
	}
	defer func() {
		if err := cfg.Close(); err != nil {
			log.Printf("failed to close configuration: %v", err)
		}
	}()

	csr, err := cfg.GenerateCSR(nil)
	if err != nil {
		return err
	}

	out, closeFunc, err := maybeRedirect(w, cfg.FlagValue(outFlag), 0666)
	if err != nil {
		return err
	}
	defer closeFunc()

	if err := pemfile.WriteCSR(out, csr); err != nil {
		return fmt.Errorf("failed to write certificate request: %v", err)
	}

	return nil
}
