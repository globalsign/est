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
)

// csrattrs requests a list of CA-desired CSR attributes.
func csrattrs(w io.Writer, set *flag.FlagSet) error {
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

	attrs, err := client.CSRAttrs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CSR attributes: %v", err)
	}

	const fieldWidth = 8

	for _, oid := range attrs.OIDs {
		fmt.Fprintf(w, "%-*s: %v\n", fieldWidth, "OID", oid)
	}

	for _, attr := range attrs.Attributes {
		fmt.Fprintf(w, "%-*s: %v\n", fieldWidth, "Type", attr.Type)

		for i, value := range attr.Values {
			var label = " "
			if i == 0 {
				if len(attr.Values) == 1 {
					label = " Value"
				} else {
					label = " Values"
				}
			}

			fmt.Fprintf(w, "%-*s: %v\n", fieldWidth, label, value)
		}
	}

	return nil
}
