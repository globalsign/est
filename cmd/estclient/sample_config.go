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

const fileSample = `{
    "server": "est.fake.domain:8443",
    "additional_path_segment": "someseg",
    "additional_headers": {
        "Certificate-Template": "my-template",
        "Bit-Size": "3072"
    },
    "host_header": "est.fake.host",
    "username": "someuser",
    "password": "somepass",
    "private_key": "test_key.pem"
}
`

const hsmSample = `{
    "server": "est.fake.domain:8443",
    "additional_path_segment": "someseg",
    "additional_headers": {
        "Certificate-Template": "my-template",
        "Bit-Size": "3072"
    },
    "host_header": "est.fake.host",
    "username": "someuser",
    "password": "somepass",
    "private_key": {
        "hsm": {
            "pkcs11_library_path": "/usr/local/lib/softhsm/libsofthsm2.so",
            "token_label": "Testing Token",
            "token_pin": "1234",
            "key_id": 1
        }
    }
}
`

const tpmSample = `{
    "server": "est.fake.domain:8443",
    "additional_path_segment": "someseg",
    "additional_headers": {
        "Certificate-Template": "my-template",
        "Bit-Size": "3072"
    },
    "host_header": "est.fake.host",
    "username": "someuser",
    "password": "somepass",
    "private_key": {
        "tpm": {
            "device": "/dev/tpmrm0",
            "persistent_handle": 2164391936,
            "storage_handle": 2164260865,
            "ek_handle": 2164326401,
            "key_password": "xyzzy",
            "storage_password": "opensesame",
            "ek_password": "abracadabra",
            "ek_certs": "/path/to/ek/certs/chain.pem",
            "public_area": "signing_key.pub",
            "private_area": "signing_key.priv"
        }
    }
}
`

// sampleconfig outputs a sample configuration file.
func sampleconfig(w io.Writer, set *flag.FlagSet) error {
	cfg, err := newConfig(set)
	if err != nil {
		return fmt.Errorf("failed to get configuration: %v", err)
	}
	defer func() {
		if err := cfg.Close(); err != nil {
			log.Printf("failed to close configuration: %v", err)
		}
	}()

	out, closeFunc, err := maybeRedirect(w, cfg.FlagValue(outFlag), 0666)
	if err != nil {
		return err
	}
	defer closeFunc()

	if cfg.FlagWasPassed(hsmFlag) {
		fmt.Fprint(out, hsmSample)
	} else if cfg.FlagWasPassed(tpmFlag) {
		fmt.Fprint(out, tpmSample)
	} else {
		fmt.Fprint(out, fileSample)
	}

	return nil
}
