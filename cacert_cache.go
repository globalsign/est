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

package est

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// cacertCache contains a cache of CA certificates for each "CA" (identified
// by the optional additional path segment) to enable client certificate
// validation during reenrollment without excessive network calls to /cacerts.
type cacertCache struct {
	ca    CA
	mutex sync.RWMutex
	cache map[string]cacheEntry
}

// cacheEntry is an entry in the CA certificates cache.
type cacheEntry struct {
	roots   *x509.CertPool
	inters  *x509.CertPool
	updated time.Time
}

const (
	// assumeFresh is the amount of time for which cached CA certificates will
	// be assumed to be fresh, i.e. a new call to /cacerts will not be made if
	// the cached CA certs are younger than this time period.
	assumeFresh = time.Minute * 5
)

// Add adds a set of CA certificates to the cache. The operation is performed
// asynchronously and the method returns immediately..
func (c *cacertCache) Add(aps string, certs []*x509.Certificate) {
	go c.addSync(aps, certs)
}

// Verify verifies a certificate against the cached CA certificates for the
// specified CA. If the CA certificates for that CA are not in the cache, or
// if they are not fresh has expired, an attempt is made to retrieve them.
func (c *cacertCache) Verify(
	ctx context.Context,
	aps string,
	cert *x509.Certificate,
	r *http.Request,
) error {
	current, err := c.get(ctx, aps, r)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots:         current.roots,
		Intermediates: current.inters,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return errInvalidClientCert
	}

	return nil
}

// addSync synchonrously adds a set of CA certificates to the cache. If
// a sufficiently fresh entry is already in the cache, it is returned,
// otherwise a new entry is added and returned.
func (c *cacertCache) addSync(aps string, certs []*x509.Certificate) cacheEntry {
	// Acquire a read lock to check for an existing entry.
	c.mutex.RLock()
	current, ok := c.cache[aps]
	c.mutex.RUnlock()

	// Do nothing if entry exists and was updated sufficiently recently.
	if ok && time.Since(current.updated) < assumeFresh {
		return current
	}

	// Build new certificate pools before acquiring the mutex, to minimize
	// time holding it.
	var roots *x509.CertPool
	var inters *x509.CertPool

	for _, cert := range certs {
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			if roots == nil {
				roots = x509.NewCertPool()
			}
			roots.AddCert(cert)
		} else {
			if inters == nil {
				inters = x509.NewCertPool()
			}
			inters.AddCert(cert)
		}
	}

	// Acquire a write mutex.
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check again in case entry was updated since we released the read mutex.
	current, ok = c.cache[aps]
	if ok && time.Since(current.updated) < assumeFresh {
		return current
	}

	// Add the new/updated entry to the cache and return it.
	newEntry := cacheEntry{
		roots:   roots,
		inters:  inters,
		updated: time.Now(),
	}

	c.cache[aps] = newEntry

	return newEntry
}

// get retrieves the CA certificates for the specified CA from the cache.
// If the CA certificates for that CA are not in the cache, or if their
// freshness has expired, an attempt is made to retrieve them.
func (c *cacertCache) get(ctx context.Context, aps string, r *http.Request) (cacheEntry, error) {
	// Acquire a read lock to check for an existing entry.
	c.mutex.RLock()
	current, ok := c.cache[aps]
	c.mutex.RUnlock()

	// If entry exists and was updated sufficiently recently, return it.
	if ok && time.Since(current.updated) < assumeFresh {
		return current, nil
	}

	// Request latest CA certificates and return them.
	certs, err := c.ca.CACerts(ctx, aps, r)
	if err != nil {
		LoggerFromContext(r.Context()).Errorf("failed to retrieve CA certificates: %v", err)

		return cacheEntry{}, fmt.Errorf("failed to retrieve CA certificates: %w", err)
	}

	return c.addSync(aps, certs), nil
}

// newCACertCache creates a new CA certificate cache.
func newCACertCache(ca CA) *cacertCache {
	return &cacertCache{
		ca:    ca,
		cache: make(map[string]cacheEntry),
	}
}
