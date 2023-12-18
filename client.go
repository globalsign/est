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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client is an EST client implementing the Enrollment over Secure Transport
// protocol as defined in RFC7030.
//
// All EST client operations will return an error object implementing Error
// when the EST server returns any status other than 200 OK. The status code,
// description and, if applicable, retry-after seconds can be extracted from
// that object. In order to make the retry-after seconds available through
// this mechanism, note that a 202 Accepted response to enroll and reenroll
// operations is returned as an error for this purpose, even though 2** status
// codes indicate success.
type Client struct {
	// Host is the host:path of the EST server excluding any URL path
	// component, e.g. est.server.com:8443
	Host string

	// AdditionalPathSegment is an optional label for EST servers to provide
	// service for multiple CAs. See RFC7030 3.2.2.
	AdditionalPathSegment string

	// ExplicitAnchor is the optional Explicit TA database. See RFC7030 3.6.1.
	ExplicitAnchor *x509.CertPool

	// ImplicitAnchor is an optional Implicit TA database. If nil, the system
	// certificate pool will be used. See RFC7030 3.6.2.
	ImplicitAnchor *x509.CertPool

	// Certificates are the client certificates to present to the EST server
	// during the handshake. If more than one certificate is provided, they
	// should be provided in order, with the end-entity certificate first, and
	// the root CA (or last intermediate CA) certificate last.
	Certificates []*x509.Certificate

	// PrivateKey is the private key associated with the end-entity TLS
	// certificate. Any object implementing crypto.Signer may be used, to
	// support private keys resident on a hardware security module (HSM),
	// Trusted Platform Module (TPM) or other hardware device.
	PrivateKey interface{}

	// AdditionalHeaders are additional HTTP headers to include with the
	// request to the EST server.
	AdditionalHeaders map[string]string

	// HostHeader overrides the default Host header for the HTTP request to the
	// EST server, and is mostly useful for testing.
	HostHeader string

	// Username is an optional HTTP Basic Authentication username.
	Username string

	// Password is an optional HTTP Basic Authentication password.
	Password string

	// DisableKeepAlives disables HTTP keep-alives if set.
	DisableKeepAlives bool

	// InsecureSkipVerify controls whether the client verifies the EST server's
	// certificate chain and host name. If true, the client accepts any
	// certificate presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks. This should
	// be used only for testing. If used to obtain the CA certificates from an
	// otherwise untrusted EST server, those certificates must be manually
	// verified in some out-of-band manner before any further EST operations with
	// that server are performed.
	InsecureSkipVerify bool
}

// Client constants.
const (
	estVersion = "v1.0.6"
	userAgent  = "GlobalSign EST Client " + estVersion + " github.com/globalsign/est"
)

// CACerts requests a copy of the current CA certificates.
func (c *Client) CACerts(ctx context.Context) ([]*x509.Certificate, error) {
	req, err := c.newRequest(ctx, http.MethodGet, cacertsEndpoint, "", "", mimeTypePKCS7, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.makeHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp.Body)

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, mimeTypePKCS7, encodingTypeBase64); err != nil {
		return nil, err
	}

	return readCertsResponse(resp.Body)
}

// CSRAttrs requests a list of CA-desired CSR attributes.
func (c *Client) CSRAttrs(ctx context.Context) (CSRAttrs, error) {
	req, err := c.newRequest(ctx, http.MethodGet, csrattrsEndpoint, "", "", mimeTypeCSRAttrs, nil)
	if err != nil {
		return CSRAttrs{}, err
	}

	resp, err := c.makeHTTPClient().Do(req)
	if err != nil {
		return CSRAttrs{}, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp.Body)

	if err := checkResponseError(resp); err != nil {
		// Per RFC7030 section 4.5.2, an HTTP response code of 204 or 404
		// indicates that a CSR attributes response is not available, and that
		// this is functionally equivalent to returning an empty SEQUENCE
		// indicating that the server has no specific additional information
		// it desires in a client certification request. Therefore we do not
		// treat these two response codes as errors, and we just return an
		// empty CSR attributes object.
		var estErr Error
		if errors.As(err, &estErr); estErr.StatusCode() == http.StatusNotFound ||
			estErr.StatusCode() == http.StatusNoContent {
			return CSRAttrs{}, nil
		}

		return CSRAttrs{}, err
	}

	if err := verifyResponseType(resp, mimeTypeCSRAttrs, encodingTypeBase64); err != nil {
		return CSRAttrs{}, err
	}

	return readCSRAttrsResponse(resp.Body)
}

// Enroll requests a new certificate.
func (c *Client) Enroll(ctx context.Context, r *x509.CertificateRequest) (*x509.Certificate, error) {
	return c.enrollCommon(ctx, r, false)
}

// Reenroll renews an existing certificate.
func (c *Client) Reenroll(ctx context.Context, r *x509.CertificateRequest) (*x509.Certificate, error) {
	return c.enrollCommon(ctx, r, true)
}

// Enroll requests a new certificate.
func (c *Client) enrollCommon(ctx context.Context, r *x509.CertificateRequest, renew bool) (*x509.Certificate, error) {
	reqBody := ioutil.NopCloser(bytes.NewBuffer(base64Encode(r.Raw)))

	var endpoint = enrollEndpoint
	if renew {
		endpoint = reenrollEndpoint
	}

	req, err := c.newRequest(ctx, http.MethodPost, endpoint, mimeTypePKCS10, encodingTypeBase64, mimeTypePKCS7, reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.makeHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp.Body)

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, mimeTypePKCS7, encodingTypeBase64); err != nil {
		return nil, err
	}

	return readCertResponse(resp.Body)
}

// ServerKeyGen requests a new certificate and a server-generated private key.
func (c *Client) ServerKeyGen(ctx context.Context, r *x509.CertificateRequest) (*x509.Certificate, []byte, error) {
	reqBody := ioutil.NopCloser(bytes.NewBuffer(base64Encode(r.Raw)))

	req, err := c.newRequest(ctx, http.MethodPost, serverkeygenEndpoint,
		mimeTypePKCS10, encodingTypeBase64, mimeTypeMultipart, reqBody)
	if err != nil {
		return nil, nil, err
	}

	resp, err := c.makeHTTPClient().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp.Body)

	if err := checkResponseError(resp); err != nil {
		return nil, nil, err
	}

	// Ensure overall content-type is as expected.
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get(contentTypeHeader))
	if err != nil {
		return nil, nil, fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
	} else if !strings.HasPrefix(mediaType, mimeTypeMultipart) {
		return nil, nil, fmt.Errorf("unexpected %s: %s", contentTypeHeader, mediaType)
	}

	mpr := multipart.NewReader(resp.Body, params[mimeParamBoundary])

	var cert *x509.Certificate
	var key []byte

	// Process all the parts.
	var numParts = 2
	for i := 1; ; i++ {
		// First, break if there are no more parts in the response.
		part, err := mpr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
		}
		defer part.Close()

		// Return with error if there are more parts than we expect.
		if i > numParts {
			return nil, nil, fmt.Errorf("more than %d parts in HTTP response", numParts)
		}

		// Process based on the part's content-type. Per RFC7030 4.4.2, if
		// additional encryption is not being employed, the private key data
		// must be placed in an application/pkcs8 part. Otherwise, it must
		// be placed in an application/pkcs7-mime part with an smime-type
		// parameter of "server-generated-key". The certificate response
		// matches that for /simpleenroll and /simplereenroll, namely an
		// application/pkcs7-mime part with an smime-type parameter of
		// "certs-only" (RFC7040 4.2.3).
		mediaType, params, err := mime.ParseMediaType(part.Header.Get(contentTypeHeader))
		if err != nil {
			return nil, nil, fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
		}

		switch {
		case strings.HasPrefix(mediaType, mimeTypePKCS8):
			key, err = readAllBase64Response(part)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
			}

		case strings.HasPrefix(mediaType, mimeTypePKCS7):
			t := params[mimeParamSMIMEType]

			switch t {
			case paramValueGenKey:
				key, err = readAllBase64Response(part)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
				}

			case paramValueCertsOnly:
				cert, err = readCertResponse(part)
				if err != nil {
					return nil, nil, err
				}

			default:
				return nil, nil, fmt.Errorf("unexpected %s: %s", mimeParamSMIMEType, t)

			}

		default:
			return nil, nil, fmt.Errorf("unexpected %s: %s", contentTypeHeader, mediaType)
		}
	}

	// Ensure both parts were returned.
	if cert == nil {
		return nil, nil, errors.New("no certificate returned")
	} else if key == nil {
		return nil, nil, errors.New("no private key returned")
	}

	return cert, key, nil
}

// TPMEnroll requests a certificate using the TPM 2.0 privacy preserving
// protocol for distributing credentials for keys on a TPM.
func (c *Client) TPMEnroll(
	ctx context.Context,
	r *x509.CertificateRequest,
	ekCerts []*x509.Certificate,
	ekPub []byte,
	akPub []byte,
) ([]byte, []byte, []byte, error) {
	buf, contentType, err := encodeMultiPart(
		tpmEnrollBoundary,
		[]multipartPart{
			{contentType: mimeTypePKCS10, data: r},
			{contentType: mimeTypePKCS7CertsOnly, data: ekCerts},
			{contentType: mimeTypeOctetStream, data: ekPub},
			{contentType: mimeTypeOctetStream, data: akPub},
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}

	reqBody := ioutil.NopCloser(buf)

	req, err := c.newRequest(ctx, http.MethodPost, tpmenrollEndpoint,
		contentType, "", mimeTypeMultipart, reqBody)
	if err != nil {
		return nil, nil, nil, err
	}

	resp, err := c.makeHTTPClient().Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp.Body)

	if err := checkResponseError(resp); err != nil {
		return nil, nil, nil, err
	}

	// Ensure overall content-type is as expected.
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get(contentTypeHeader))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
	} else if !strings.HasPrefix(mediaType, mimeTypeMultipart) {
		return nil, nil, nil, fmt.Errorf("unexpected %s: %s", contentTypeHeader, mediaType)
	}

	mpr := multipart.NewReader(resp.Body, params[mimeParamBoundary])

	var credBlob []byte
	var encSeed []byte
	var cred []byte

	var parts = []struct {
		ctype string
		data  *[]byte
	}{
		{mimeTypeOctetStream, &credBlob},
		{mimeTypeOctetStream, &encSeed},
		{mimeTypePKCS7, &cred},
	}

	// Process all the parts.
	var numParts = 3
	for i := 1; ; i++ {
		// First, break if there are no more parts in the response.
		part, err := mpr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get next HTTP response part: %w", err)
		}
		defer part.Close()

		// Return with error if there are more parts than we expect.
		if i > numParts {
			return nil, nil, nil, fmt.Errorf("more than %d parts in HTTP response", numParts)
		}

		// Check content-transfer-encoding is as expected, and read the part
		// body.
		if err := verifyPartTypeResponse(part, parts[i-1].ctype, encodingTypeBase64); err != nil {
			return nil, nil, nil, err
		}

		*parts[i-1].data, err = readAllBase64Response(part)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
		}
	}

	return credBlob, encSeed, cred, nil
}

// newRequest builds an HTTP request for an EST operation.
func (c *Client) newRequest(
	ctx context.Context,
	method, endpoint string,
	contentType, transferEncoding string,
	accepts string,
	body io.Reader,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.uri(endpoint), body)
	if err != nil {
		return nil, fmt.Errorf("failed to make new HTTP request: %w", err)
	}

	req.Close = c.DisableKeepAlives
	req.Header.Set(userAgentHeader, userAgent)
	if accepts != "" {
		req.Header.Set(acceptHeader, accepts)
	}
	if contentType != "" {
		req.Header.Set(contentTypeHeader, contentType)
	}
	if transferEncoding != "" {
		req.Header.Set(transferEncodingHeader, transferEncoding)
	}

	if c.HostHeader != "" {
		req.Host = c.HostHeader
	}

	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}

	for k, v := range c.AdditionalHeaders {
		req.Header.Add(k, v)
	}

	return req, err
}

// checkResponseError returns nil if the HTTP response status code is 200 OK,
// otherwise it returns an error object implementing est.Error. In order to
// parse the Retry-After header and return a value, note that 202 Accepted
// is treated as an error for this purpose.
func checkResponseError(r *http.Response) error {
	if r.StatusCode == http.StatusOK {
		return nil
	}

	// Attempt to extract human-readable error message from the HTTP
	// response body, if the content type permits or if it is not set.
	// RFC7030 states in section 4.2.3 for enroll and reenroll operations,
	// and in 4.4.2 for server key generation operations, that if the
	// content-type is not set, the response data MUST be a plaintext
	// human-readable error message. No such requirements are stipulated
	// for any of the other operations, but we here make the same assumptions.
	//
	// TODO(paul): Section 4.2.3 permits an application/pkcs-mime simple PKI
	// response also to be used to convey an error response for enroll and
	// reenroll operations.
	var msg string
	mediaType, _, err := mime.ParseMediaType(r.Header.Get(contentTypeHeader))
	if err == nil || r.Header.Get(contentTypeHeader) == "" {
		switch mediaType {
		case "", mimeTypeTextPlain, mimeTypeJSON, mimeTypeProblemJSON:
			data, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return err
			}

			if len(data) > 0 {
				msg = string(data)
			} else {
				msg = http.StatusText(r.StatusCode)
			}

		default:
			msg = fmt.Sprintf("%s (%s)",
				http.StatusText(r.StatusCode), mediaType)
		}
	}

	// Parse Retry-After header if present. Per RFC7231 7.1.3, the value
	// of a Retry-After header may be either an HTTP-date or a number of
	// seconds to delay after the response is received.
	var retryAfter int
	if secs := r.Header.Get(retryAfterHeader); secs != "" {
		retryAfter, err = strconv.Atoi(secs)
		if err != nil {
			if t, err := parseHTTPTime(secs); err == nil {
				retryAfter = int(t.Sub(time.Now()).Seconds())
			}
		}

		if retryAfter < 0 {
			retryAfter = 0
		}
	}

	return &estError{
		status:     r.StatusCode,
		desc:       msg,
		retryAfter: retryAfter,
	}
}

// uri builds an EST URI for the specified endpoint, using the optional
// additional path segment if appropriate.
func (c *Client) uri(endpoint string) string {
	var builder strings.Builder

	builder.WriteString("https://")
	builder.WriteString(c.Host)
	builder.WriteString(estPathPrefix)

	if c.AdditionalPathSegment != "" {
		builder.WriteRune('/')
		builder.WriteString(c.AdditionalPathSegment)
	}

	builder.WriteString(endpoint)

	return builder.String()
}

// makeHTTPClient makes and configures an HTTP client for connecting to an
// EST server.
func (c *Client) makeHTTPClient() *http.Client {
	var rootCAs *x509.CertPool
	if c.ExplicitAnchor != nil {
		rootCAs = c.ExplicitAnchor
	} else if c.ImplicitAnchor != nil {
		rootCAs = c.ImplicitAnchor
	}

	var tlsCerts []tls.Certificate
	if len(c.Certificates) > 0 && c.PrivateKey != nil {
		tlsCerts = []tls.Certificate{{PrivateKey: c.PrivateKey, Leaf: c.Certificates[0]}}
		for i := range c.Certificates {
			tlsCerts[0].Certificate = append(tlsCerts[0].Certificate, c.Certificates[i].Raw)
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            rootCAs,
				Certificates:       tlsCerts,
				InsecureSkipVerify: c.InsecureSkipVerify,
			},
			DisableKeepAlives: c.DisableKeepAlives,
		},
	}
}
