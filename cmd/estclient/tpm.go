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
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"go.mozilla.org/pkcs7"

	"github.com/globalsign/pemfile"
)

var (
	errNoTPMPrivateKey         = errors.New("private key in configuration file is not a TPM private key")
	errNoTPMDevice             = errors.New("no TPM device in configuration file")
	errNoTPMEKCerts            = errors.New("no endorsement key certificate(s) provided")
	errNoTPMEK                 = errors.New("no endorsement key in configuration file")
	errNoTPMSK                 = errors.New("no storage key in configuration file")
	errNoTPMHandleOrPublicArea = errors.New("no key handle or public/private areas in configuration file")
)

// tpmenroll requests a new certificate.
func tpmenroll(w io.Writer, set *flag.FlagSet) error {
	cfg, err := newConfig(set)
	if err != nil {
		return fmt.Errorf("failed to get configuration: %v", err)
	}
	defer func() {
		if err := cfg.Close(); err != nil {
			log.Printf("failed to close configuration: %v", err)
		}
	}()

	// Ensure all required TPM fields are present.
	if cfg.PrivateKey.TPM == nil {
		return errNoTPMPrivateKey
	} else if len(cfg.ekcerts) == 0 {
		return errNoTPMEKCerts
	} else if cfg.PrivateKey.TPM.EK == nil {
		return errNoTPMEK
	} else if cfg.PrivateKey.TPM.Device == "" {
		return errNoTPMDevice
	}

	// Get EK and AK public areas.
	ekpub, err := readEKPublic(&cfg)
	if err != nil {
		return err
	}

	akpub, err := readAKPublic(&cfg)
	if err != nil {
		return err
	}

	// Get or build CSR.
	var csr *x509.CertificateRequest
	if cfg.FlagWasPassed(csrFlag) {
		csr, err = pemfile.ReadCSR(cfg.FlagValue(csrFlag))
		if err != nil {
			return fmt.Errorf("failed to read CSR from file: %v", err)
		}
	} else {
		csr, err = cfg.GenerateCSR(nil)
		if err != nil {
			return fmt.Errorf("failed to create certificate request: %v", err)
		}
	}

	// Request new certificate protected with the privacy preserving protocol
	// for distributing credentials for keys on a TPM.
	ctx, cancel := cfg.MakeContext()
	defer cancel()

	client, err := cfg.MakeClient()
	if err != nil {
		return fmt.Errorf("failed to make EST client: %v", err)
	}

	blob, seed, p7der, err := client.TPMEnroll(ctx, csr, cfg.ekcerts, ekpub, akpub)
	if err != nil {
		return fmt.Errorf("failed to enroll: %v", err)
	}

	// Activate the credential we received.
	tpm, err := openTPM(cfg.PrivateKey.TPM.Device)
	if err != nil {
		return fmt.Errorf("failed to open TPM device: %v", err)
	}
	defer tpm.Close()

	// First, the key being credentialed and the endorsement key must be loaded
	// onto the TPM. This client requires the endorsement key to be in permanent
	// or persistent storage, but the key being credentialed can be loaded on
	// demand. Therefore, if a persistent handle was provided, retrieve it.
	// Otherwise, load the key into transient storage.
	var handle tpmutil.Handle
	if cfg.PrivateKey.TPM.Persistent != nil {
		handle, err = toHandle(cfg.PrivateKey.TPM.Persistent)
		if err != nil {
			return fmt.Errorf("failed to read persistent handle: %v", err)
		}
	} else {
		// If the key being credentialed is to be loaded on demand, its storage
		// key must be in persistent storage, so return an error if it is not.
		if cfg.PrivateKey.TPM.Storage == nil {
			return errNoTPMSK
		}

		storage, err := toHandle(cfg.PrivateKey.TPM.Storage)
		if err != nil {
			return fmt.Errorf("failed to read storage handle: %v", err)
		}

		// If the key being credentialed is to be loaded on demand, both the
		// public and private areas must be provided.
		pubfile := cfg.PrivateKey.TPM.Public
		privfile := cfg.PrivateKey.TPM.Private
		if pubfile == "" {
			return errors.New("no public area provided")
		} else if privfile == "" {
			return errors.New("no private area provided")
		}

		pub, err := ioutil.ReadFile(pubfile)
		if err != nil {
			return fmt.Errorf("failed to read public area: %v", err)
		}

		priv, err := ioutil.ReadFile(privfile)
		if err != nil {
			return fmt.Errorf("failed to read private area: %v", err)
		}

		// Load the key onto the TPM, and defer a flush of it to ensure it's
		// ultimately removed.
		handle, _, err = tpm2.Load(tpm, storage, cfg.PrivateKey.TPM.StoragePass, pub, priv)
		if err != nil {
			return fmt.Errorf("failed to load key: %v", err)
		}
		defer func() {
			if err := tpm2.FlushContext(tpm, handle); err != nil {
				log.Printf("failed to flush key: %v", err)
			}
		}()
	}

	// Prepare the endorsement key handle.
	ek, err := toHandle(cfg.PrivateKey.TPM.EK)
	if err != nil {
		return fmt.Errorf("failed to read endorsement key handle: %v", err)
	}

	// Per the TPM EK Credential Profile for TPM Family 2.0, appendix B, the
	// default EK templates (stored in the low range) specify keys whose
	// authorization is only allowed with authPolicy, and to authorize use of
	// the EK require endorsementAuth. Therefore we start a policy session with
	// the TPM2_PolicySecret command.
	sess, _, err := tpm2.StartAuthSession(tpm, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16),
		nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return fmt.Errorf("failed to start auth session: %v", err)
	}
	defer tpm2.FlushContext(tpm, sess)

	if _, _, err := tpm2.PolicySecret(tpm, tpm2.HandleEndorsement,
		tpm2.AuthCommand{
			Session:    tpm2.HandlePasswordSession,
			Attributes: tpm2.AttrContinueSession,
		},
		sess, nil, nil, nil, 0); err != nil {
		return fmt.Errorf("failed to set policy secret: %v", err)
	}

	// Now, activate the credential to retrieve the key used to encrypt the
	// certificate.
	psk, err := tpm2.ActivateCredentialUsingAuth(tpm,
		[]tpm2.AuthCommand{
			{
				Session:    tpm2.HandlePasswordSession,
				Attributes: tpm2.AttrContinueSession,
				Auth:       []byte(cfg.PrivateKey.TPM.KeyPass),
			},
			{
				Session:    sess,
				Attributes: tpm2.AttrContinueSession,
				Auth:       []byte(cfg.PrivateKey.TPM.EKPass),
			},
		},
		handle, ek, blob, seed)
	if err != nil {
		return fmt.Errorf("failed to activate credential: %v", err)
	}

	// Parse and decrypte the PKCS7 object and extract the certificate.
	p7, err := pkcs7.Parse(p7der)
	if err != nil {
		return fmt.Errorf("failed to parse PKCS7 CMS EnvelopedData: %v", err)
	}

	der, err := p7.DecryptUsingPSK(psk)
	if err != nil {
		return fmt.Errorf("failed to decrypt PKCS7 CMS EnvelopedData: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Output certificate.
	out, closeFunc, err := maybeRedirect(w, cfg.FlagValue(outFlag), 0666)
	if err != nil {
		return err
	}
	defer closeFunc()

	pemfile.WriteCert(out, cert)

	return nil
}

// readEKPublic reads the public area of an endorsement key from a
// configuration object and returns the TPM-encoded bytes. The endorsement
// key must be in permanent or persistent storage on the TPM.
func readEKPublic(cfg *config) ([]byte, error) {
	if cfg.PrivateKey.TPM == nil {
		return nil, errNoTPMPrivateKey
	} else if cfg.PrivateKey.TPM.EK == nil {
		return nil, errNoTPMEK
	}

	handle, err := toHandle(cfg.PrivateKey.TPM.EK)
	if err != nil {
		return nil, fmt.Errorf("failed to read endorsement key handle: %v", err)
	}

	pub, err := readPublicAreaFromTPM(cfg, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to read endorsement key public area: %v", err)
	}

	return pub, nil
}

// readAKPublic reads the public area of an attestation (or general signing)
// key from a configuration object and returns the TPM-encoded bytes. The key
// may be persistent storage on the TPM, or a file containing the encoded
// public area may be referenced in the configuration.
func readAKPublic(cfg *config) ([]byte, error) {
	if cfg.PrivateKey.TPM == nil {
		return nil, errNoTPMPrivateKey
	}

	// First check if the public area has been referenced in a file, and read
	// and return if it has.
	if cfg.PrivateKey.TPM.Public != "" {
		data, err := ioutil.ReadFile(cfg.PrivateKey.TPM.Public)
		if err != nil {
			return nil, fmt.Errorf("failed to read public area: %v", err)
		}

		return data, nil
	}

	// Return with error if the public area was not referenced in a file, and
	// no persistent handle for the key was provided.
	if cfg.PrivateKey.TPM.Persistent == nil {
		return nil, errNoTPMHandleOrPublicArea
	}

	// Otherwise, read the public area from the TPM.
	handle, err := toHandle(cfg.PrivateKey.TPM.Persistent)
	if err != nil {
		return nil, fmt.Errorf("failed to read persistent handle: %v", err)
	}

	pub, err := readPublicAreaFromTPM(cfg, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to read public area: %v", err)
	}

	return pub, nil
}

// readPublicAreaFromTPM reads the public area for a key loaded in a TPM.
func readPublicAreaFromTPM(cfg *config, handle tpmutil.Handle) ([]byte, error) {
	if cfg.PrivateKey.TPM == nil {
		return nil, errNoTPMPrivateKey
	} else if cfg.PrivateKey.TPM.Device == "" {
		return nil, errNoTPMDevice
	}

	tpm, err := openTPM(cfg.PrivateKey.TPM.Device)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM device: %v", err)
	}
	defer tpm.Close()

	pub, _, _, err := tpm2.ReadPublic(tpm, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to read public area: %v", err)
	}

	enc, err := pub.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode public area: %v", err)
	}

	return enc, nil
}

// toHandle converts a *big.Int to a (unsigned 32-bit) TPM handle. An error
// is returned if the integer cannot be represented as a TPM handle.
func toHandle(n *big.Int) (tpmutil.Handle, error) {
	if !n.IsUint64() {
		return 0, fmt.Errorf("invalid handle value: %v", n)
	}

	tmp := uint32(n.Uint64())
	if uint64(tmp) != n.Uint64() {
		return 0, fmt.Errorf("invalid handle value: %v", n)
	}

	return tpmutil.Handle(tmp), nil
}
