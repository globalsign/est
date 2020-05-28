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
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/globalsign/est"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/globalsign/pemfile"
	"github.com/globalsign/tpmkeys"
)

// config contains configuration options.
type config struct {
	Server            string            `json:"server"`
	APS               string            `json:"additional_path_segment"`
	AdditionalHeaders map[string]string `json:"additional_headers,omitempty"`
	HostHeader        string            `json:"host_header"`
	Username          string            `json:"username"`
	Password          string            `json:"password"`
	Explicit          string            `json:"explicit_anchor"`
	Implicit          string            `json:"implicit_anchor"`
	PrivateKey        *privateKey       `json:"private_key,omitempty"`
	Certificates      string            `json:"client_certificates"`
	certificates      []*x509.Certificate
	ekcerts           []*x509.Certificate
	baseDir           string
	closeFuncs        []func() error
	explicitAnchor    *x509.CertPool
	flagSet           *flag.FlagSet
	flags             map[string]string
	implicitAnchor    *x509.CertPool
	insecure          bool
	openPrivateKey    interface{}
	separator         string
	timeout           time.Duration
}

// privateKey specifies the source of a private key, which could be a file,
// a hardware security module (HSM), a Trusted Platform Module (TPM) device,
// or another source.
type privateKey struct {
	Path string
	HSM  *hsmKey
	TPM  *tpmKey
}

// hsmKey is an HSM-resident private key.
type hsmKey struct {
	LibraryPath string   `json:"pkcs11_library_path"`
	Label       string   `json:"token_label"`
	PIN         string   `json:"token_pin"`
	KeyID       *big.Int `json:"key_id"`
}

// tpmKey is a TPM-resident private key.
type tpmKey struct {
	Device      string   `json:"device"`
	Persistent  *big.Int `json:"persistent_handle,omitempty"`
	Storage     *big.Int `json:"storage_handle,omitempty"`
	EK          *big.Int `json:"ek_handle,omitempty"`
	KeyPass     string   `json:"key_password"`
	StoragePass string   `json:"storage_password"`
	EKPass      string   `json:"ek_password"`
	EKCerts     string   `json:"ek_certs"`
	Public      string   `json:"public_area"`
	Private     string   `json:"private_area"`
}

const (
	configDirectoryVar = "ESTCLIENT_CONFIG_DIRECTORY"
	hsmKeyLabel        = "hsm"
	tpmKeyLabel        = "tpm"
)

var (
	errNoPrivateKey = errors.New("no private key provided")
	errNoServer     = errors.New("EST server not specified")
)

// Close releases resources associated with a configuration.
func (cfg *config) Close() (err error) {
	for _, closeFunc := range cfg.closeFuncs {
		err = closeFunc()
	}

	return
}

// FlagWasPassed reports whether a flag was passed at the command line.
func (cfg *config) FlagWasPassed(name string) bool {
	_, ok := cfg.flags[name]
	return ok
}

// FlagValue returns the raw (string) value of a flag, or the empty string if
// it was not set.
func (cfg *config) FlagValue(name string) string {
	v, _ := cfg.flags[name]
	return v
}

// MakeContext returns a context with the configured timeout, and its cancel
// function.
func (cfg *config) MakeContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), cfg.timeout)
}

// makeClient builds an EST client from a configuration file, overriding the
// values with command line options, if applicable.
func (cfg *config) MakeClient() (*est.Client, error) {
	client := est.Client{
		Host:                  cfg.Server,
		AdditionalPathSegment: cfg.APS,
		AdditionalHeaders:     cfg.AdditionalHeaders,
		ExplicitAnchor:        cfg.explicitAnchor,
		ImplicitAnchor:        cfg.implicitAnchor,
		HostHeader:            cfg.HostHeader,
		PrivateKey:            cfg.openPrivateKey,
		Certificates:          cfg.certificates,
		Username:              cfg.Username,
		Password:              cfg.Password,
		InsecureSkipVerify:    cfg.insecure,
	}

	// Host is the only required field for all operations.
	if client.Host == "" {
		return nil, errNoServer
	}

	return &client, nil
}

// GenerateCSR generates a certificate signing request. If the argument is
// nil, the private key from the configuration will be used.
func (cfg *config) GenerateCSR(key interface{}) (*x509.CertificateRequest, error) {
	if key == nil {
		if cfg.openPrivateKey == nil {
			return nil, errNoPrivateKey
		}
		key = cfg.openPrivateKey
	}

	tmpl, err := cfg.CSRTemplate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate request template: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}

	return csr, nil
}

// CSRTemplate generates a certificate request template from flags.
func (cfg *config) CSRTemplate() (*x509.CertificateRequest, error) {
	tmpl := &x509.CertificateRequest{}

	// Process single string flags.
	for _, f := range []struct {
		name  string
		value *string
	}{
		{commonNameFlag, &tmpl.Subject.CommonName},
		{serialNumberFlag, &tmpl.Subject.SerialNumber},
	} {
		if v, ok := cfg.flags[f.name]; ok {
			*f.value = v
		}
	}

	// Process flags which accept a single string, but which are stored in
	// a string slice.
	for _, f := range []struct {
		name  string
		value *[]string
	}{
		{organizationFlag, &tmpl.Subject.Organization},
		{streetAddressFlag, &tmpl.Subject.StreetAddress},
		{localityFlag, &tmpl.Subject.Locality},
		{provinceFlag, &tmpl.Subject.Province},
		{postalCodeFlag, &tmpl.Subject.PostalCode},
		{countryFlag, &tmpl.Subject.Country},
	} {
		if v, ok := cfg.flags[f.name]; ok {
			*f.value = []string{v}
		}
	}

	// Process flags which are lists of strings.
	for _, f := range []struct {
		name  string
		value *[]string
	}{
		{organizationalUnitFlag, &tmpl.Subject.OrganizationalUnit},
		{dnsNamesFlag, &tmpl.DNSNames},
		{emailsFlag, &tmpl.EmailAddresses},
	} {
		if v, ok := cfg.flags[f.name]; ok {
			*f.value = strings.Split(v, cfg.separator)
		}
	}

	// Process SAN IP addresses.
	if v, ok := cfg.flags[ipsFlag]; ok {
		for _, strIP := range strings.Split(v, cfg.separator) {
			ip := net.ParseIP(strIP)
			if ip == nil {
				return nil, fmt.Errorf("failed to parse IP address %q", strIP)
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}

	// Process SAN URIs.
	if v, ok := cfg.flags[urisFlag]; ok {
		for _, strURI := range strings.Split(v, cfg.separator) {
			uri, err := url.Parse(strURI)
			if err != nil {
				return nil, fmt.Errorf("failed to parse URI: %v", err)
			}
			tmpl.URIs = append(tmpl.URIs, uri)
		}
	}

	return tmpl, nil
}

// Get returns a private key and a close function.
func (k *privateKey) Get(baseDir string) (interface{}, func() error, error) {
	switch {
	case k.Path != "":
		key, err := pemfile.ReadPrivateKeyWithPasswordFunc(fullPath(baseDir, k.Path), nil)
		if err != nil {
			return nil, nil, err
		}

		return key, func() error { return nil }, nil

	case k.HSM != nil:
		return k.HSM.Get(baseDir)

	case k.TPM != nil:
		return k.TPM.Get(baseDir)
	}

	return nil, nil, errNoPrivateKey
}

// Get returns a private key and a close function.
func (k *hsmKey) Get(baseDir string) (key interface{}, closeFunc func() error, err error) {
	closeFunc = func() error { return nil }
	defer func() {
		if err != nil {
			closeFunc()
			closeFunc = nil
		}
	}()

	// Get the HSM PIN from the terminal if one was not specified in the
	// config file.
	if k.PIN == "" {
		var pin []byte
		pin, err = passwordFromTerminal("PIN", "HSM")
		if err != nil {
			err = fmt.Errorf("failed to get HSM PIN: %w", err)
			return
		}

		k.PIN = string(pin)
	}

	var p *crypto11.Context
	p, err = crypto11.Configure(&crypto11.Config{
		Path:       fullPath(baseDir, k.LibraryPath),
		TokenLabel: k.Label,
		Pin:        k.PIN,
	})
	if err != nil {
		err = fmt.Errorf("failed to configure PKCS11: %w", err)
		return
	}
	closeFunc = func() error {
		return p.Close()
	}

	key, err = p.FindKeyPair(k.KeyID.Bytes(), nil)
	if err != nil {
		err = fmt.Errorf("failed to find key pair: %w", err)
		return
	} else if key == nil {
		err = errors.New("failed to find key pair")
		return
	}

	return
}

// Get returns a private key and a close function.
func (k *tpmKey) Get(baseDir string) (interface{}, func() error, error) {
	var key interface{}
	var err error

	switch {
	case k.Persistent != nil:
		key, err = tpmkeys.NewFromPersistentHandle(k.Device, uint32(k.Persistent.Uint64()), k.KeyPass)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get private key: %w", err)
		}

	case k.Storage != nil:
		pub, err := ioutil.ReadFile(fullPath(baseDir, k.Public))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read public area: %w", err)
		}

		priv, err := ioutil.ReadFile(fullPath(baseDir, k.Private))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read private area: %w", err)
		}

		key, err = tpmkeys.NewFromBlobs(k.Device, uint32(k.Storage.Uint64()), k.StoragePass,
			pub, priv, k.KeyPass)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get private key: %w", err)
		}

	default:
		return nil, nil, errNoPrivateKey
	}

	return key, func() error { return nil }, nil
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (k *privateKey) UnmarshalJSON(b []byte) error {
	// If the value is a string, then it's a simple file path.
	var fp string
	if err := json.Unmarshal(b, &fp); err == nil {
		*k = privateKey{
			Path: fp,
		}
		return nil
	}

	// Otherwise, parse the object into a map and make sure we have exactly
	// one object defined.
	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}

	if len(obj) == 0 {
		return errNoPrivateKey
	} else if len(obj) > 1 {
		return errors.New("more than one private key provided")
	}

	// Unmarshal object depending on type.
	if msg, ok := obj[hsmKeyLabel]; ok {
		var s hsmKey
		if err := json.Unmarshal(msg, &s); err != nil {
			return err
		}

		*k = privateKey{HSM: &s}
	} else if msg, ok := obj[tpmKeyLabel]; ok {
		var s tpmKey
		if err := json.Unmarshal(msg, &s); err != nil {
			return err
		}

		*k = privateKey{TPM: &s}
	} else {
		return errors.New("unknown private key format")
	}

	return nil
}

// newConfig returns a configuration object from a file.
func newConfig(set *flag.FlagSet) (config, error) {
	var cfg = config{
		flagSet:   set,
		flags:     make(map[string]string),
		separator: sepChar,
		timeout:   defaultTimeout,
	}

	// Store values of set command line flags.
	cfg.flagSet.Visit(func(f *flag.Flag) {
		cfg.flags[f.Name] = f.Value.String()
	})

	// Override defaults from command line, if provided.
	if v, ok := cfg.flags[separatorFlag]; ok {
		cfg.separator = v
	}

	if d, ok := cfg.flags[timeoutFlag]; ok {
		var err error
		cfg.timeout, err = time.ParseDuration(d)
		if err != nil {
			return config{}, fmt.Errorf("failed to parse -%s flag: %v", timeoutFlag, err)
		}
	}

	// Note that -insecure can deliberately only be specified at the command
	// line, and not in the configuration file.
	if v, ok := cfg.flags[insecureFlag]; ok {
		var err error
		cfg.insecure, err = strconv.ParseBool(v)
		if err != nil {
			return config{}, fmt.Errorf("failed to parse -%s flag: %v", insecureFlag, err)
		}
	}

	// Get working directory.
	wd, err := os.Getwd()
	if err != nil {
		return config{}, fmt.Errorf("failed to get working directory: %v", err)
	}

	// Parse configuration file, if provided.
	if filename, ok := cfg.flags[configFlag]; ok {
		// If filename is not an absolute path, look for it in a set sequence
		// of locations.
		if !filepath.IsAbs(filename) {
			// Check current working directory first.
			searchPaths := []string{wd}

			// Check in the directory specified by the ESTCLIENT_CONFIG_DIRECTORY
			// environment variable, if set.
			if cd, ok := os.LookupEnv(configDirectoryVar); ok {
				info, err := os.Stat(cd)
				if err == nil && info.IsDir() && filepath.IsAbs(cd) {
					searchPaths = append(searchPaths, cd)
				}
			}

			// Check in the user's home directory, if we can find it.
			if hd, err := os.UserHomeDir(); err == nil {
				searchPaths = append(searchPaths, hd)
			}

			// Search for the file itself.
			for _, searchPath := range searchPaths {
				fp := filepath.Join(searchPath, filename)
				if info, err := os.Stat(fp); err == nil && info.Mode().IsRegular() {
					filename = fp
					break
				}
			}
		}

		// Read the file and parse the configuration.
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			return config{}, fmt.Errorf("failed to open configuration file: %v", err)
		}

		if err := json.Unmarshal(data, &cfg); err != nil {
			return config{}, fmt.Errorf("failed to unmarshal configuration file: %v", err)
		}

		cfg.baseDir = filepath.Clean(filepath.Dir(filename))
	}

	// Override configuration file values from command line, if specified
	if aps, ok := cfg.flags[apsFlag]; ok {
		cfg.APS = aps
	}

	if server, ok := cfg.flags[serverFlag]; ok {
		cfg.Server = server
	}

	if hdr, ok := cfg.flags[hostHeaderFlag]; ok {
		cfg.HostHeader = hdr
	}

	if username, ok := cfg.flags[usernameFlag]; ok {
		cfg.Username = username
	}

	if password, ok := cfg.flags[passwordFlag]; ok {
		cfg.Password = password
	}

	if hdrs, ok := cfg.flags[headersFlag]; ok {
		cfg.AdditionalHeaders = make(map[string]string)
		for _, hdr := range strings.Split(hdrs, cfg.separator) {
			vals := strings.SplitN(hdr, ":", 2)
			name := vals[0]
			val := ""
			if len(vals) >= 2 {
				val = vals[1]
			}

			cfg.AdditionalHeaders[strings.TrimSpace(name)] = strings.TrimSpace(val)
		}
	}

	// Process explicit and implicit anchor databases.
	for _, anchor := range []struct {
		name   string
		flag   string
		field  *string
		anchor **x509.CertPool
	}{
		{
			name:   "explicit",
			flag:   explicitAnchorFlag,
			field:  &cfg.Explicit,
			anchor: &cfg.explicitAnchor,
		},
		{
			name:   "implicit",
			flag:   implicitAnchorFlag,
			field:  &cfg.Implicit,
			anchor: &cfg.implicitAnchor,
		},
	} {
		if filename, ok := cfg.flags[anchor.flag]; ok {
			*anchor.field = fullPath(wd, filename)
		} else if *anchor.field != "" {
			*anchor.field = fullPath(cfg.baseDir, *anchor.field)
		}

		if *anchor.field != "" {
			*anchor.anchor = x509.NewCertPool()

			certs, err := pemfile.ReadCerts(*anchor.field)
			if err != nil {
				return config{}, fmt.Errorf("failed to read %s anchor file: %v", anchor.name, err)
			}

			for _, cert := range certs {
				(*anchor.anchor).AddCert(cert)
			}
		}
	}

	// Process client certificate(s).
	if filename, ok := cfg.flags[certsFlag]; ok {
		cfg.Certificates = fullPath(wd, filename)
	} else if cfg.Certificates != "" {
		cfg.Certificates = fullPath(cfg.baseDir, cfg.Certificates)
	}

	if cfg.Certificates != "" {
		certs, err := pemfile.ReadCerts(cfg.Certificates)
		if err != nil {
			return config{}, fmt.Errorf("failed to read client certificates: %v", err)
		}

		cfg.certificates = certs
	}

	// Process TPM endorsement key certificate(s).
	var ekCertsPath string
	if filename, ok := cfg.flags[ekcertsFlag]; ok {
		ekCertsPath = fullPath(wd, filename)
	} else if cfg.PrivateKey != nil && cfg.PrivateKey.TPM != nil && cfg.PrivateKey.TPM.EKCerts != "" {
		ekCertsPath = fullPath(cfg.baseDir, cfg.PrivateKey.TPM.EKCerts)
	}

	if ekCertsPath != "" {
		ekcerts, err := pemfile.ReadCerts(ekCertsPath)
		if err != nil {
			return config{}, fmt.Errorf("failed to read endorsement key certificates: %v", err)
		}

		cfg.ekcerts = ekcerts
	}

	// Process private key. Note that a private key located in a file is the
	// only type which can be specified at the command line.
	if filename, ok := cfg.flags[keyFlag]; ok {
		cfg.PrivateKey = &privateKey{Path: fullPath(wd, filename)}
	}

	if cfg.PrivateKey != nil {
		privkey, closeFunc, err := cfg.PrivateKey.Get(cfg.baseDir)
		if err != nil {
			return config{}, fmt.Errorf("failed to get private key: %v", err)
		}

		cfg.openPrivateKey = privkey
		cfg.closeFuncs = append(cfg.closeFuncs, closeFunc)
	}

	return cfg, nil
}

// passwordFromTerminal prompts for a password at the terminal.
func passwordFromTerminal(cred, target string) ([]byte, error) {
	// Open the (POSIX standard) /dev/tty to ensure we're reading from and
	// writing to an actual terminal. If /dev/tty doesn't exist, we're
	// probably on Windows, so just check if os.Stdin is a terminal, and
	// use it if it is.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if !os.IsNotExist(err) || !terminal.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("failed to open terminal: %w", err)
		}
		tty = os.Stdin
	} else {
		defer tty.Close()
	}

	tty.Write([]byte(fmt.Sprintf("Enter %s for %s: ", cred, target)))
	pass, err := terminal.ReadPassword(int(tty.Fd()))
	tty.Write([]byte("\n"))

	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	return pass, nil
}

// fullPath returns filename if it is an absolute path, or filename joined to
// baseDir if it is not.
func fullPath(baseDir, filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}

	return filepath.Clean(filepath.Join(baseDir, filename))
}
