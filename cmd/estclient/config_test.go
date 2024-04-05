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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/est"
	"github.com/globalsign/est/internal/mockca"

	"github.com/globalsign/pemfile"
)

const (
	skipVar     = "GLOBALSIGN_EST_SKIP"
	testTimeout = time.Second * 30
)

var (
	skipHSM = false
	skipTPM = false
)

func init() {
	if val, ok := os.LookupEnv(skipVar); ok {
		for _, ts := range strings.Split(val, ",") {
			switch strings.ToLower(ts) {
			case "hsm":
				skipHSM = true
			case "tpm":
				skipTPM = true
			}
		}
	}
}

func TestNewConfig(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	var testcases = []struct {
		name    string
		skipHSM bool
		skipTPM bool
		args    []string
		want    config
	}{
		{
			name: "NoFlags",
			args: []string{
				"-" + configFlag, "testdata/test.cfg",
			},
			want: config{
				Server:   "est.fake.domain:8443",
				APS:      "someseg",
				Explicit: wd + "/testdata/test_anchor.pem",
				Implicit: wd + "/testdata/test_anchor.pem",
				AdditionalHeaders: map[string]string{
					"Certificate-Template": "my-template",
					"Bit-Size":             "3072",
				},
				HostHeader: "est.fake.host",
				Username:   "someuser",
				Password:   "somepass",
				PrivateKey: &privateKey{
					Path: "test_key.pem",
				},
				separator: ",",
				timeout:   defaultTimeout,
			},
		},
		{
			name: "AllOverrides",
			args: []string{
				"-" + configFlag, "testdata/test.cfg",
				"-" + separatorFlag, ";",
				"-" + serverFlag, "est.alt.domain:9999",
				"-" + explicitAnchorFlag, "testdata/alt_test_anchor.pem",
				"-" + implicitAnchorFlag, "testdata/alt_test_anchor.pem",
				"-" + apsFlag, "otherseg",
				"-" + headersFlag, "This-Thing:stuff;That-Thing:nonsense",
				"-" + hostHeaderFlag, "est.morefake.host",
				"-" + usernameFlag, "otheruser",
				"-" + passwordFlag, "otherpass",
				"-" + timeoutFlag, "17s",
			},
			want: config{
				Server:   "est.alt.domain:9999",
				APS:      "otherseg",
				Explicit: wd + "/testdata/alt_test_anchor.pem",
				Implicit: wd + "/testdata/alt_test_anchor.pem",
				AdditionalHeaders: map[string]string{
					"This-Thing": "stuff",
					"That-Thing": "nonsense",
				},
				HostHeader: "est.morefake.host",
				Username:   "otheruser",
				Password:   "otherpass",
				PrivateKey: &privateKey{
					Path: "test_key.pem",
				},
				separator: ";",
				timeout:   time.Second * 17,
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if skipHSM && tc.skipHSM {
				t.Skip("skipping HSM test")
			} else if skipTPM && tc.skipTPM {
				t.Skip("skipping TPM test")
			}

			got, err := newConfig(makeCmdFlagSet(t, enrollCmd, tc.args))
			if err != nil {
				t.Fatalf("failed to get configuration: %v", err)
			}
			defer func() {
				if err := got.Close(); err != nil {
					t.Fatalf("failed to close configuration: %v", err)
				}
			}()

			// Make a copy for comparison, to ignore any internally set fields.
			cmp := config{
				Server:            got.Server,
				APS:               got.APS,
				AdditionalHeaders: got.AdditionalHeaders,
				HostHeader:        got.HostHeader,
				Username:          got.Username,
				Password:          got.Password,
				Explicit:          got.Explicit,
				Implicit:          got.Implicit,
				PrivateKey:        got.PrivateKey,
				separator:         got.separator,
				timeout:           got.timeout,
			}

			if !reflect.DeepEqual(cmp, tc.want) {
				t.Fatalf("got %v, want %v", cmp, tc.want)
			}
		})
	}
}

func TestNewConfigHardware(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		skipHSM bool
		skipTPM bool
		args    []string
	}{
		{
			name:    "HSM",
			skipHSM: true,
			args: []string{
				"-" + configFlag, "testdata/test_hsm.cfg",
			},
		},
		{
			name:    "TPM",
			skipTPM: true,
			args: []string{
				"-" + configFlag, "testdata/test_tpm.cfg",
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if skipHSM && tc.skipHSM {
				t.Skip("skipping HSM test")
			} else if skipTPM && tc.skipTPM {
				t.Skip("skipping TPM test")
			}

			got, err := newConfig(makeCmdFlagSet(t, enrollCmd, tc.args))
			if err != nil {
				t.Fatalf("failed to get configuration: %v", err)
			}
			defer func() {
				if err := got.Close(); err != nil {
					t.Fatalf("failed to close configuration: %v", err)
				}
			}()
		})
	}
}

func TestCACerts(t *testing.T) {
	t.Parallel()

	s, rootCert, uri := newTestServer(t)
	defer s.Close()

	cafile, remove := makeRootCertFile(t, rootCert)
	defer remove(t)

	var testcases = []struct {
		name string
		args []string
		err  []error
	}{
		{
			name: "NoAnchor",
			args: []string{
				"-" + serverFlag, uri,
			},
			err: []error{
				errors.New("failed to verify certificate"),
				errors.New("certificate is not trusted"),
				errors.New("certificate signed by unknown authority"),
			},
		},
		{
			name: "Insecure",
			args: []string{
				"-" + serverFlag, uri,
				"-" + insecureFlag,
			},
		},
		{
			name: "ExplicitAnchor",
			args: []string{
				"-" + serverFlag, uri,
				"-" + apsFlag, "something",
				"-" + explicitAnchorFlag, cafile,
			},
		},
		{
			name: "ImplicitAnchor",
			args: []string{
				"-" + serverFlag, uri,
				"-" + apsFlag, "otherthing",
				"-" + implicitAnchorFlag, cafile,
			},
		},
		{
			name: "TriggerError",
			args: []string{
				"-" + serverFlag, uri,
				"-" + apsFlag, "triggererrors",
				"-" + explicitAnchorFlag, cafile,
			},
			err: []error{errors.New("internal server error")},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			err := cacerts(buf, makeCmdFlagSet(t, cacertsCmd, tc.args))
			VerifyErrorTextContainsOneOf(t, err, tc.err)
			if tc.err != nil {
				return
			}

			verifyIsPEMBlocks(t, buf.Bytes(), 2)
		})
	}
}

func TestCSRAttrs(t *testing.T) {
	t.Parallel()

	s, rootCert, uri := newTestServer(t)
	defer s.Close()

	cafile, remove := makeRootCertFile(t, rootCert)
	defer remove(t)

	var testcases = []struct {
		name   string
		args   []string
		length int
		err    error
	}{
		{
			name: "NoAnchor",
			args: []string{
				"-" + serverFlag, uri,
			},
			err: errors.New("certificate signed by unknown authority"),
		},
		{
			name: "Insecure",
			args: []string{
				"-" + serverFlag, uri,
				"-" + insecureFlag,
			},
			length: 0,
		},
		{
			name: "ExplicitAnchor",
			args: []string{
				"-" + serverFlag, uri,
				"-" + apsFlag, "something",
				"-" + explicitAnchorFlag, cafile,
			},
			length: 0,
		},
		{
			name: "ImplicitAnchor",
			args: []string{
				"-" + serverFlag, uri,
				"-" + apsFlag, "csrattrs",
				"-" + implicitAnchorFlag, cafile,
			},
			length: 171,
		},
		{
			name: "TriggerError",
			args: []string{
				"-" + serverFlag, uri,
				"-" + apsFlag, "triggererrors",
				"-" + explicitAnchorFlag, cafile,
			},
			err: errors.New("internal server error"),
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			err := csrattrs(buf, makeCmdFlagSet(t, csrattrsCmd, tc.args))
			verifyErrorTextContains(t, err, tc.err)

			if tc.err != nil {
				return
			}

			if got := len(buf.Bytes()); got != tc.length {
				t.Fatalf("got %d bytes, want %d", got, tc.length)
			}
		})
	}
}

func TestEnroll(t *testing.T) {
	t.Parallel()

	s, rootCert, uri := newTestServer(t)
	defer s.Close()

	cafile, remove := makeRootCertFile(t, rootCert)
	defer remove(t)

	var testcases = []struct {
		name string
		args []string
		err  error
	}{
		{
			name: "CSR",
			args: []string{
				"-" + serverFlag, uri,
				"-" + explicitAnchorFlag, cafile,
				"-" + csrFlag, "testdata/test_csr.pem",
				"-" + usernameFlag, "testuser",
				"-" + passwordFlag, "xyzzy",
			},
		},
		{
			name: "NoCSR",
			args: []string{
				"-" + serverFlag, uri,
				"-" + implicitAnchorFlag, cafile,
				"-" + commonNameFlag, "Jorknorr Doe",
				"-" + keyFlag, "testdata/test_key.pem",
				"-" + usernameFlag, "testuser",
				"-" + passwordFlag, "xyzzy",
			},
		},
		{
			name: "Neither",
			args: []string{
				"-" + serverFlag, uri,
				"-" + explicitAnchorFlag, cafile,
				"-" + usernameFlag, "testuser",
				"-" + passwordFlag, "xyzzy",
			},
			err: errors.New("no private key provided"),
		},
		{
			name: "BadPassword",
			args: []string{
				"-" + serverFlag, uri,
				"-" + implicitAnchorFlag, cafile,
				"-" + commonNameFlag, "Jorknorr Doe",
				"-" + keyFlag, "testdata/test_key.pem",
				"-" + usernameFlag, "testuser",
				"-" + passwordFlag, "opensesame",
			},
			err: errors.New("authorization required"),
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			err := enroll(buf, makeCmdFlagSet(t, enrollCmd, tc.args))
			verifyErrorTextContains(t, err, tc.err)

			if tc.err != nil {
				return
			}

			verifyIsPEMBlocks(t, buf.Bytes(), 1)
		})
	}
}

func TestReenroll(t *testing.T) {
	t.Parallel()

	s, rootCert, uri := newTestServer(t)
	defer s.Close()

	cafile, remove := makeRootCertFile(t, rootCert)
	defer remove(t)

	cacertsArgs := []string{
		"-" + serverFlag, uri,
		"-" + explicitAnchorFlag, cafile,
	}

	var testcases = []struct {
		name         string
		enrollArgs   []string
		reenrollArgs []string
	}{
		{
			name: "OK",
			enrollArgs: []string{
				"-" + serverFlag, uri,
				"-" + explicitAnchorFlag, cafile,
				"-" + commonNameFlag, "Jorknorr Doe",
				"-" + emailsFlag, "jorknorr@doe.spork",
				"-" + keyFlag, "testdata/test_key.pem",
				"-" + usernameFlag, "testuser",
				"-" + passwordFlag, "xyzzy",
			},
			reenrollArgs: []string{
				"-" + serverFlag, uri,
				"-" + explicitAnchorFlag, cafile,
				"-" + keyFlag, "testdata/test_key.pem",
				"-" + usernameFlag, "testuser",
				"-" + passwordFlag, "xyzzy",
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "reenroll_test_")
			if err != nil {
				t.Fatalf("failed to create temporary file: %v", err)
			}
			defer func() {
				if err := os.Remove(f.Name()); err != nil {
					t.Errorf("failed to remove temporary file: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("failed to close temporary file: %v", err)
				}
			}()

			buf := bytes.NewBuffer([]byte{})
			if err := cacerts(buf, makeCmdFlagSet(t, cacertsCmd, cacertsArgs)); err != nil {
				t.Fatalf("failed to get CA certificates enroll: %v", err)
			}

			blocks := verifyIsPEMBlocks(t, buf.Bytes(), 2)
			cacerts := make([]*x509.Certificate, 0)
			for _, block := range blocks {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("failed to parse certificate: %v", err)
				}

				cacerts = append(cacerts, cert)
			}

			buf.Reset()
			if err := enroll(buf, makeCmdFlagSet(t, enrollCmd, tc.enrollArgs)); err != nil {
				t.Fatalf("failed to enroll: %v", err)
			}
			blocks = verifyIsPEMBlocks(t, buf.Bytes(), 1)

			cert, err := x509.ParseCertificate(blocks[0].Bytes)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}

			if err := pemfile.WriteCert(f, cert); err != nil {
				t.Fatalf("failed to write certificate: %v", err)
			}

			if err := pemfile.WriteCerts(f, cacerts); err != nil {
				t.Fatalf("failed to write CA certificates: %v", err)
			}

			tc.reenrollArgs = append(tc.reenrollArgs, []string{"-" + certsFlag, f.Name()}...)

			buf.Reset()
			if err := reenroll(buf, makeCmdFlagSet(t, reenrollCmd, tc.reenrollArgs)); err != nil {
				t.Fatalf("failed to enroll: %v", err)
			}
		})
	}
}

func TestServerKeyGen(t *testing.T) {
	t.Parallel()

	s, rootCert, uri := newTestServer(t)
	defer s.Close()

	cafile, remove := makeRootCertFile(t, rootCert)
	defer remove(t)

	var testcases = []struct {
		name string
		args []string
	}{
		{
			name: "PKCS8",
			args: []string{
				"-" + serverFlag, uri,
				"-" + explicitAnchorFlag, cafile,
				"-" + commonNameFlag, "Jackie Doe",
				"-" + usernameFlag, "testuser",
				"-" + passwordFlag, "xyzzy",
			},
		},
		{
			name: "PKCS7",
			args: []string{
				"-" + serverFlag, uri,
				"-" + apsFlag, "pkcs7",
				"-" + implicitAnchorFlag, cafile,
				"-" + commonNameFlag, "Jenny Doe",
				"-" + usernameFlag, "testuser",
				"-" + passwordFlag, "xyzzy",
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			if err := serverkeygen(buf, makeCmdFlagSet(t, serverkeygenCmd, tc.args)); err != nil {
				t.Fatalf("failed to enroll: %v", err)
			}

			verifyIsPEMBlocks(t, buf.Bytes(), 2)
		})
	}
}

func TestCSR(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		skipHSM bool
		args    []string
		subject pkix.Name
		ips     []net.IP
		uris    []*url.URL
	}{
		{
			name: "AllFieldTypes",
			args: []string{
				"-" + configFlag, "testdata/test.cfg",
				"-" + commonNameFlag, "John Doe",
				"-" + organizationalUnitFlag, "Sales,Marketing",
				"-" + organizationFlag, "JD Associates",
				"-" + ipsFlag, "10.0.0.1,192.168.1.1",
				"-" + urisFlag, "www.this.com,ftp.that.com",
			},
			subject: pkix.Name{
				CommonName:         "John Doe",
				Organization:       []string{"JD Associates"},
				OrganizationalUnit: []string{"Sales", "Marketing"},
			},
			ips: []net.IP{
				net.ParseIP("10.0.0.1").To4(),
				net.ParseIP("192.168.1.1").To4(),
			},
			uris: []*url.URL{
				mustParseURL(t, "www.this.com"),
				mustParseURL(t, "ftp.that.com"),
			},
		},
		{
			name:    "SoftwareHSMKey",
			skipHSM: true,
			args: []string{
				"-" + configFlag, "testdata/test_hsm.cfg",
				"-" + separatorFlag, ";",
				"-" + commonNameFlag, "Jingles Doe",
				"-" + organizationalUnitFlag, "Finance;Digging",
			},
			subject: pkix.Name{
				CommonName:         "Jingles Doe",
				OrganizationalUnit: []string{"Finance", "Digging"},
			},
		},
		{
			name: "OverrideHSMKey",
			args: []string{
				"-" + configFlag, "testdata/test_hsm.cfg",
				"-" + commonNameFlag, "Jabberwock Doe",
				"-" + keyFlag, "testdata/test_key.pem",
			},
			subject: pkix.Name{
				CommonName: "Jabberwock Doe",
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if skipHSM && tc.skipHSM {
				t.Skip("skipping HSM test")
			}

			buf := bytes.NewBuffer([]byte{})
			if err := csr(buf, makeCmdFlagSet(t, csrCmd, tc.args)); err != nil {
				t.Fatalf("failed to generate CSR: %v", err)
			}

			block, rest := pem.Decode(buf.Bytes())
			if block == nil {
				t.Fatal("failed to parse PEM block")
			} else if len(rest) > 0 {
				t.Fatal("trailing PEM data")
			}

			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse certificate request: %v", err)
			}

			assertPKIXNamesEqual(t, csr.Subject, tc.subject)

			if !reflect.DeepEqual(csr.IPAddresses, tc.ips) {
				t.Fatalf("got IPs %v, want %v", csr.IPAddresses, tc.ips)
			}

			if !reflect.DeepEqual(csr.URIs, tc.uris) {
				t.Fatalf("got IPs %v, want %v", csr.URIs, tc.uris)
			}
		})
	}
}

func TestSampleConfig(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		args   []string
		length int
	}{
		{
			name:   "NoArgs",
			args:   []string{},
			length: 319,
		},
		{
			name: "HSM",
			args: []string{
				"-" + hsmFlag,
			},
			length: 516,
		},
		{
			name: "TPM",
			args: []string{
				"-" + tpmFlag,
			},
			length: 773,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buf := bytes.NewBuffer([]byte{})
			if err := sampleconfig(buf, makeCmdFlagSet(t, sampleconfigCmd, tc.args)); err != nil {
				t.Fatalf("failed to output sample configuration: %v", err)
			}

			if got := buf.Len(); got != tc.length {
				t.Fatalf("got length %d, want %d", got, tc.length)
			}
		})
	}
}

func newTestServer(t *testing.T) (*httptest.Server, *x509.Certificate, string) {
	t.Helper()

	// Create new transient CA.
	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create new mock CA: %v", err)
	}

	// Obtain a TLS certificate for the server.
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "Test EST Server"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EST server private key: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, serverKey)
	if err != nil {
		t.Fatalf("failed to create EST server certificate request: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("failed to parse EST server certificate request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	serverCert, err := ca.Enroll(ctx, csr, "", nil)
	if err != nil {
		t.Fatalf("failed to enroll for EST server certificate: %v", err)
	}

	caCerts, err := ca.CACerts(ctx, "", nil)
	if err != nil {
		t.Fatalf("failed to obtain CA certificates: %v", err)
	}

	checkBasicAuth := func(
		_ context.Context,
		_ *http.Request,
		_, username, password string,
	) error {
		if username != "testuser" || password != "xyzzy" {
			return errors.New("bad credentials")
		}
		return nil
	}

	// Create the EST server.
	cfg := &est.ServerConfig{
		CA:             ca,
		Timeout:        testTimeout,
		RateLimit:      1000,
		CheckBasicAuth: checkBasicAuth,
	}

	r, err := est.NewRouter(cfg)
	if err != nil {
		t.Fatalf("failed to create new router: %v", err)
	}

	s := httptest.NewUnstartedServer(r)

	s.Config.ErrorLog = log.New(io.Discard, "", 0)

	var clientCAs = x509.NewCertPool()
	clientCAs.AddCert(caCerts[len(caCerts)-1])

	tlsCerts := [][]byte{serverCert.Raw}
	for i, cert := range caCerts {
		if i != len(caCerts)-1 {
			tlsCerts = append(tlsCerts, cert.Raw)
		}
	}

	s.TLS = &tls.Config{
		ClientCAs:  clientCAs,
		ClientAuth: tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCerts,
				PrivateKey:  serverKey,
				Leaf:        serverCert,
			},
		},
	}

	s.StartTLS()

	return s, caCerts[len(caCerts)-1], strings.TrimPrefix(s.URL, "https://")
}

func verifyIsPEMBlocks(t *testing.T, data []byte, n int) []*pem.Block {
	t.Helper()

	numFound := 0
	blocks := make([]*pem.Block, 0)
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			if len(rest) == 0 {
				break
			}
			t.Fatal("trailing PEM data")
		}
		numFound++
		blocks = append(blocks, block)
		data = rest
	}

	if numFound != n {
		t.Fatalf("found %d PEM blocks, want %d", numFound, n)
	}

	return blocks
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()

	uri, err := url.Parse(s)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}

	return uri
}

func makeCmdFlagSet(t *testing.T, cmd string, args []string) *flag.FlagSet {
	t.Helper()

	fcmd, ok := commands[cmd]
	if !ok {
		t.Fatalf("command not recognized: %s", cmd)
	}

	set := fcmd.FlagSet(io.Discard, 80)
	if err := set.Parse(args); err != nil {
		t.Fatalf("failed to parse flag set: %v", err)
	}

	return set
}

func makeRootCertFile(t *testing.T, cert *x509.Certificate) (string, func(t *testing.T)) {
	t.Helper()

	f, err := os.CreateTemp("", "estclient_test_")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	defer f.Close()

	if err := pemfile.WriteCert(f, cert); err != nil {
		if rerr := os.Remove(f.Name()); rerr != nil {
			t.Errorf("failed to remove temporary file: %v", rerr)
		}

		t.Fatalf("failed to write certificate: %v", err)
	}

	return f.Name(), func(t *testing.T) {
		if err := os.Remove(f.Name()); err != nil {
			t.Errorf("failed to remove temporary file: %v", err)
		}
	}
}

func verifyErrorTextContains(t *testing.T, got, want error) {
	t.Helper()

	if (got == nil) != (want == nil) {
		t.Fatalf("got error %v, want %v", got, want)
	}

	if got != nil && !strings.Contains(got.Error(), want.Error()) {
		t.Fatalf("got error %v, want %v", got, want)
	}
}

// VerifyErrorTextContainsOneOf tests if the error text contains one of the strings.
// This is useful for testing errors that output different text on different
// platforms or between versions.
func VerifyErrorTextContainsOneOf(t *testing.T, got error, wants []error) {
	t.Helper()

	if got == nil && len(wants) == 0 {
		return
	}

	if got != nil && len(wants) == 0 {
		t.Fatalf("got %v, want no error", got)
	}

	if got == nil && len(wants) > 0 {
		t.Fatalf("got nil, want one of %v", wants)
	}

	contains := false
	for _, w := range wants {
		if got != nil && !strings.Contains(got.Error(), w.Error()) {
			break
		}
		contains = true
	}

	if !contains {
		t.Fatalf("got error %v, want one of %v", got, wants)
	}
}

// assertPKIXNamesEqual tests if two pkix.Name objects are equal in all
// respects other than the ordering of the name attributes.
func assertPKIXNamesEqual(t *testing.T, first, second pkix.Name) {
	t.Helper()

	atvLess := func(s []pkix.AttributeTypeAndValue) func(i, j int) bool {
		return func(i, j int) bool {
			if len(s[i].Type) < len(s[j].Type) {
				return true
			} else if len(s[i].Type) > len(s[j].Type) {
				return false
			}

			for k := range s[i].Type {
				if s[i].Type[k] < s[j].Type[k] {
					return true
				} else if s[i].Type[k] > s[j].Type[k] {
					return false
				}
			}

			return s[i].Value.(string) < s[j].Value.(string)
		}
	}

	firstSlice := first.ToRDNSequence()[0]
	secondSlice := second.ToRDNSequence()[0]

	sort.Slice(firstSlice, atvLess(firstSlice))
	sort.Slice(secondSlice, atvLess(secondSlice))

	if !reflect.DeepEqual(firstSlice, secondSlice) {
		t.Fatalf("got %v, want %v", first, second)
	}
}
