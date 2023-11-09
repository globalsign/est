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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/globalsign/pemfile"
	"github.com/haritzsaiz/est"
	"github.com/haritzsaiz/est/internal/basiclogger"
	"github.com/haritzsaiz/est/internal/mockca"
)

const (
	defaultListenAddr   = ":8443"
	healthCheckUsername = "healthcheck"
	healthCheckEndpoint = "/healthcheck"
)

func main() {
	log.SetPrefix(fmt.Sprintf("%s: ", appName))
	log.SetFlags(0)

	flag.Usage = usage
	flag.Parse()

	// Process special-purpose flags.
	switch {
	case *fHelp:
		usage()
		return

	case *fSampleConfig:
		sampleConfig()
		return

	case *fVersion:
		version()
		return
	}

	// Load and process configuration.
	var cfg *config
	var err error
	if *fConfig != "" {
		cfg, err = configFromFile(*fConfig)
		if err != nil {
			log.Fatalf("failed to read configuration file: %v", err)
		}
	} else {
		cfg = &config{}
	}

	// Create mock CA. If no mock CA was specified in the configuration file,
	// create a transient one.
	var ca *mockca.MockCA
	if cfg.MockCA != nil {
		ca, err = mockca.NewFromFiles(cfg.MockCA.Certs, cfg.MockCA.Key)
		if err != nil {
			log.Fatalf("failed to create mock CA: %v", err)
		}
	} else {
		ca, err = mockca.NewTransient()
		if err != nil {
			log.Fatalf("failed to create mock CA: %v", err)
		}
	}

	// Create logger. If no log file was specified, log to standard error.
	var logger est.Logger
	if cfg.Logfile == "" {
		logger = basiclogger.New(os.Stderr)
	} else {
		f, err := os.OpenFile(cfg.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		logger = basiclogger.New(f)
		defer f.Close()
	}

	// Create server TLS configuration. If a server TLS configuration was
	// specified in the configuration file, use it. Otherwise, generate a
	// transient server key and enroll for a server certificate with the
	// mock CA, and use the CA certificates as the client CA certificates
	// also.
	var listenAddr = defaultListenAddr
	var serverKey interface{}
	var serverCerts []*x509.Certificate
	var clientCACerts []*x509.Certificate

	if cfg.TLS != nil {
		serverKey, err = pemfile.ReadPrivateKey(cfg.TLS.Key)
		if err != nil {
			log.Fatalf("failed to read server private key from file: %v", err)
		}

		serverCerts, err = pemfile.ReadCerts(cfg.TLS.Certs)
		if err != nil {
			log.Fatalf("failed to read server certificates from file: %v", err)
		}

		for _, certPath := range cfg.TLS.ClientCAs {
			certs, err := pemfile.ReadCerts(certPath)
			if err != nil {
				log.Fatalf("failed to read client CA certificates from file: %v", err)
			}
			clientCACerts = append(clientCACerts, certs...)
		}

		listenAddr = cfg.TLS.ListenAddr
	} else {
		serverKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate server private key: %v", err)
		}

		tmpl := &x509.CertificateRequest{
			Subject:     pkix.Name{CommonName: "Testing Non-Production EST Server"},
			DNSNames:    []string{"localhost"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		}

		der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, serverKey)
		if err != nil {
			log.Fatalf("failed to generate server certificate signing request: %v", err)
		}

		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			log.Fatalf("failed to parse server certificate signing request: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)

		cert, err := ca.Enroll(ctx, csr, "", nil)
		if err != nil {
			log.Fatalf("failed to enroll for server certificate: %v", err)
		}

		cacerts, err := ca.CACerts(ctx, "", nil)
		if err != nil {
			log.Fatalf("failed to retrieve CA certificates: %v", err)
		}

		cancel()

		serverCerts = append([]*x509.Certificate{cert}, cacerts...)
		clientCACerts = []*x509.Certificate{cacerts[len(cacerts)-1]}
	}

	var tlsCerts [][]byte
	for i := range serverCerts {
		tlsCerts = append(tlsCerts, serverCerts[i].Raw)
	}

	clientCAs := x509.NewCertPool()
	for _, cert := range clientCACerts {
		clientCAs.AddCert(cert)
	}

	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCerts,
				PrivateKey:  serverKey,
				Leaf:        serverCerts[0],
			},
		},
		ClientCAs: clientCAs,
	}

	// Create a password function which requires a HTTP Basic Authentication
	// username of "healthcheck" and the password from the configuration (no
	// password if no configuration was provided) to access the /healthcheck
	// endpoint, and no username or password otherwise required.
	pwfunc := func(ctx context.Context, r *http.Request, aps, username, password string) error {
		if strings.ToLower(r.URL.Path) != healthCheckEndpoint {
			return nil
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != healthCheckUsername || pass != cfg.HealthCheckPassword {
			return errors.New("authorization required")
		}

		return nil
	}

	// Create server mux.
	r, err := est.NewRouter(&est.ServerConfig{
		CA:             ca,
		Logger:         logger,
		AllowedHosts:   cfg.AllowedHosts,
		Timeout:        time.Duration(cfg.Timeout) * time.Second,
		RateLimit:      cfg.RateLimit,
		CheckBasicAuth: pwfunc,
	})
	if err != nil {
		log.Fatalf("failed to create new EST router: %v", err)
	}

	// Create and start server.
	s := &http.Server{
		Addr:      listenAddr,
		Handler:   r,
		TLSConfig: tlsCfg,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	logger.Infof("Starting EST server FOR NON-PRODUCTION USE ONLY")

	go s.ListenAndServeTLS("", "")

	// Wait for signal.
	got := <-stop

	// Shutdown server.
	logger.Infof("Closing EST server with signal %v", got)

	s.Close()
}
