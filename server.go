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
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"go.mozilla.org/pkcs7"
	"golang.org/x/time/rate"
)

// ServerConfig contains EST server configuration options.
type ServerConfig struct {
	// CA is an interface to the Certificate Authority backing the EST server.
	CA CA

	// Logger is an optional logger. The logger can be retrieved by the backing
	// CA from the HTTP request context using LoggerFromContext.
	Logger Logger

	// Timeout sets a request timeout. If zero, a reasonable default will be
	// used.
	Timeout time.Duration

	// AllowedHosts is an optional list of fully-qualified domain names
	// representing hosts which are allowed to serve the EST service.
	AllowedHosts []string

	// RateLimit is an optional rate limit expressed in requests per second.
	// If zero, no rate limit will be applied.
	RateLimit int

	// CheckBasicAuth is an optional callback function to check HTTP Basic
	// Authentication credentials. A nil error means that authentication was
	// successful, and a non-nil error means that it was not. If CheckBasicAuth
	// is nil, then HTTP Basic Authentication is not required for any EST
	// operation, but access to the /healthcheck endpoint will be blocked.
	CheckBasicAuth func(ctx context.Context, r *http.Request, aps, username, password string) error
}

// ctxKey is an unexported custom type for request context keys.
type ctxKey int

// Request context key constants.
const (
	ctxKeyCA ctxKey = iota
	ctxKeyCertCache
	ctxKeyLogger
	ctxKeyReenroll
)

// Server constants.
const (
	apsParamName   = "additionalPathSegment"
	defaultTimeout = time.Second * 60
)

// Log field and message constants.
const (
	logFieldError                 = "Error"
	logMsgCACertsFailed           = "failed to retrieve CA certificates"
	logMsgContentTypeInvalid      = "invalid content-type"
	logMsgCSRAttrsFailed          = "failed to retrieve CSR attributes"
	logMsgEnrollFailed            = "failed to enroll"
	logMsgMultipartDecodeFailed   = "failed to decode multipart request"
	logMsgMultipartEncodeFailed   = "failed to encode multipart response"
	logMsgPanicRecovery           = "recovered from panic"
	logMsgPublicKeyInvalid        = "invalid public key"
	logMsgReadBodyFailed          = "failed to read request body"
	logMsgTransferEncodingInvalid = "invalid content-transfer-encoding"
	logMsgVerifyFailed            = "failed to verify client certificate"
)

// LoggerFromContext returns a logger included in a context.
func LoggerFromContext(ctx context.Context) Logger {
	logger, _ := ctx.Value(ctxKeyLogger).(Logger)
	return logger
}

// caFromContext returns the backing CA from a request context, or nil if
// no backing CA is present.
func caFromContext(ctx context.Context) CA {
	ca, _ := ctx.Value(ctxKeyCA).(CA)
	return ca
}

// certCacheFromContext returns a CA certificates cache from a request context,
// or nil if none is present.
func certCacheFromContext(ctx context.Context) *cacertCache {
	cache, _ := ctx.Value(ctxKeyCertCache).(*cacertCache)
	return cache
}

// isReenroll checks if a context contains a reenrollment flag.
func isReenroll(ctx context.Context) bool {
	_, ok := ctx.Value(ctxKeyReenroll).(bool)
	return ok
}

// NewRouter creates a new EST server mux.
func NewRouter(cfg *ServerConfig) (http.Handler, error) {
	r := chi.NewRouter()

	timeout := defaultTimeout
	if cfg.Timeout != 0 {
		timeout = cfg.Timeout
	}

	var logger Logger
	if cfg.Logger != nil {
		logger = cfg.Logger
	} else {
		logger = newNOPLogger()
	}

	r.Use(middleware.Timeout(timeout))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(withLogger(logger))
	r.Use(recoverer(logger))
	r.Use(addServerHeader)
	r.Use(addSecureHeaders)
	if len(cfg.AllowedHosts) > 0 {
		r.Use(verifyAllowedHosts(cfg.AllowedHosts))
	}
	r.Use(maxBodySize(65536))
	if cfg.RateLimit != 0 {
		r.Use(rateLimit(cfg.RateLimit))
	}

	r.Use(middleware.WithValue(ctxKeyCA, cfg.CA))
	r.Use(middleware.WithValue(ctxKeyCertCache, newCACertCache(cfg.CA)))

	// Non-EST endpoints.
	r.With(
		requireBasicAuth(cfg.CheckBasicAuth, false),
	).Get("/healthcheck", healthcheck)

	// EST endpoints.
	r.Route(estPathPrefix, func(r chi.Router) {
		r.Get(cacertsEndpoint, cacerts)
		r.Get(csrattrsEndpoint, csrattrs)

		r.With(
			requireContentType(mimeTypePKCS10),
		).With(
			requireBasicAuth(cfg.CheckBasicAuth, true),
		).Post(enrollEndpoint, enroll)

		r.With(
			requireContentType(mimeTypePKCS10),
		).With(
			requireBasicAuth(cfg.CheckBasicAuth, true),
		).With(
			middleware.WithValue(ctxKeyReenroll, true),
		).Post(reenrollEndpoint, enroll)

		r.With(
			requireContentType(mimeTypePKCS10),
		).With(
			requireBasicAuth(cfg.CheckBasicAuth, true),
		).Post(serverkeygenEndpoint, serverkeygen)

		r.With(
			requireContentType(mimeTypeMultipart),
		).With(
			requireBasicAuth(cfg.CheckBasicAuth, true),
		).Post(tpmenrollEndpoint, tpmenroll)

		// Endpoints with additional path segment.
		r.Route(fmt.Sprintf("/{%s}", apsParamName), func(r chi.Router) {
			r.Get(cacertsEndpoint, cacerts)
			r.Get(csrattrsEndpoint, csrattrs)

			r.With(
				requireContentType(mimeTypePKCS10),
			).With(
				requireBasicAuth(cfg.CheckBasicAuth, true),
			).Post(enrollEndpoint, enroll)

			r.With(
				requireContentType(mimeTypePKCS10),
			).With(
				requireBasicAuth(cfg.CheckBasicAuth, true),
			).With(
				middleware.WithValue(ctxKeyReenroll, true),
			).Post(reenrollEndpoint, enroll)

			r.With(
				requireContentType(mimeTypePKCS10),
			).With(
				requireBasicAuth(cfg.CheckBasicAuth, true),
			).Post(serverkeygenEndpoint, serverkeygen)

			r.With(
				requireContentType(mimeTypeMultipart),
			).With(
				requireBasicAuth(cfg.CheckBasicAuth, true),
			).Post(tpmenrollEndpoint, tpmenroll)
		})
	})

	return r, nil
}

// healthcheck services the /healthcheck endpoint.
func healthcheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// cacerts services the /cacerts endpoint.
func cacerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aps := chi.URLParam(r, apsParamName)

	certs, err := caFromContext(ctx).CACerts(ctx, aps, r)
	if writeOnError(ctx, w, logMsgCACertsFailed, err) {
		return
	}

	// Update CA certificates cache with each explicit call to /cacerts.
	certCacheFromContext(ctx).Add(aps, certs)

	writeResponse(w, mimeTypePKCS7, true, certs)
}

// csrattrs services the /csrattrs endpoint.
func csrattrs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aps := chi.URLParam(r, apsParamName)

	attrs, err := caFromContext(ctx).CSRAttrs(ctx, aps, r)
	if writeOnError(ctx, w, logMsgCSRAttrsFailed, err) {
		return
	}

	writeResponse(w, mimeTypeCSRAttrs, true, attrs)
}

// enroll services the /simpleenroll endpoint.
func enroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aps := chi.URLParam(r, apsParamName)

	csr, err := readCSRRequest(r.Body, true)
	if writeOnError(ctx, w, logMsgReadBodyFailed, err) {
		return
	}

	renew := isReenroll(ctx)

	if renew {

		// Per RFC7030 4.2.2, for /simplereenroll the Subject and
		// SubjectAltName fields in the CSR MUST be identical to the
		// corresponding fields in the certificate being renewed. The
		// ChangeSubjectName attribute MAY be included in the CSR to request
		// that these fields be changed in the new certificate, but the
		// fields in the CSR (rather than the fields in the ChangeSubjectName
		// attribute) still must be identical with the certificate being
		// renewed. If the ChangeSubjectName attribute is included, we defer
		// it to the backing CA for handling.
		//
		// Per RFC7030 3.3.2, if the certificate to be renewed or rekeyed is
		// appropriate for the negotiated cipher suite, then the client MUST
		// use it for the TLS handshake. Otherwise, the client SHOULD use an
		// alternate certificate that is suitable for the cipher suite and
		// which contains the same subject identity information. In this case,
		// the subject fields in the CSR must still be identical with those of
		// the certificate being used for the TLS handshake.
		//
		// RFC7030 3.3.2 also says the a client MAY use a client certificate
		// issued by a third part to authenticate itself for an "enroll
		// operation". It is not clear if this only applies to /simpleenroll,
		// but for simplicity we here choose to interpret this as meaning that
		// a client may not use a third part certificate to authenticate itself
		// for a /simplereenroll operation, and we therefore require a client
		// to use an existing certificate for renew operations.
		//
		// This server does not support clients which do not support TLS client
		// authentication for renew operations.

		if len(r.TLS.PeerCertificates) == 0 {
			errNoClientCertificate.Write(w)
			return
		}

		// Use PeerCertificates rather than VerifiedChains in case the server
		// requests but does not verify.
		cert := r.TLS.PeerCertificates[0]

		// Compare Subject fields.
		if !bytes.Equal(csr.RawSubject, cert.RawSubject) {
			errSubjectChanged.Write(w)
			return
		}

		// Compare SubjectAltName fields.
		var csrSAN pkix.Extension
		var certSAN pkix.Extension

		for _, ext := range csr.Extensions {
			if ext.Id.Equal(oidSubjectAltName) {
				csrSAN = ext
				break
			}
		}

		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidSubjectAltName) {
				certSAN = ext
				break
			}
		}

		if !bytes.Equal(csrSAN.Value, certSAN.Value) {
			errSubjectChanged.Write(w)
			return
		}

		// Verify certificate against CA certificates.
		err := certCacheFromContext(ctx).Verify(ctx, aps, cert, r)
		if writeOnError(ctx, w, logMsgVerifyFailed, err) {
			return
		}
	}

	// Request certificate from backing CA.
	var cert *x509.Certificate
	if renew {
		cert, err = caFromContext(ctx).Reenroll(ctx, r.TLS.PeerCertificates[0], csr, aps, r)
	} else {
		cert, err = caFromContext(ctx).Enroll(ctx, csr, aps, r)
	}
	if writeOnError(r.Context(), w, logMsgEnrollFailed, err) {
		return
	}

	writeResponse(w, mimeTypePKCS7CertsOnly, true, cert)
}

// serverkeygen services the /serverkeygen endpoint.
func serverkeygen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aps := chi.URLParam(r, apsParamName)

	csr, err := readCSRRequest(r.Body, true)
	if writeOnError(ctx, w, logMsgReadBodyFailed, err) {
		return
	}

	// Request certificate from backing CA.
	cert, key, err := caFromContext(ctx).ServerKeyGen(ctx, csr, aps, r)
	if writeOnError(ctx, w, logMsgEnrollFailed, err) {
		return
	}

	// Encode and write response.
	var keyContentType string
	if _, p8err := x509.ParsePKCS8PrivateKey(key); p8err == nil {
		keyContentType = mimeTypePKCS8
	} else if _, p7err := pkcs7.Parse(key); p7err == nil {
		keyContentType = mimeTypePKCS7GenKey
	} else {
		LoggerFromContext(ctx).Errorf("failed to parse private key: %v, %v", p8err, p7err)
		errInternal.Write(w)
		return
	}

	buf, contentType, err := encodeMultiPart(
		serverKeyGenBoundary,
		[]multipartPart{
			{contentType: keyContentType, data: key},
			{contentType: mimeTypePKCS7CertsOnly, data: cert},
		},
	)
	if writeOnError(ctx, w, logMsgMultipartEncodeFailed, err) {
		return
	}

	writeResponse(w, contentType, false, buf.Bytes())
}

// tpmenroll services the /tpmenroll endpoint.
func tpmenroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aps := chi.URLParam(r, apsParamName)

	// Read and decode request.
	var csr *x509.CertificateRequest
	var ekCerts []*x509.Certificate
	var ekPub []byte
	var akPub []byte

	_, err := decodeMultipartRequest(
		r,
		[]multipartPart{
			{contentType: mimeTypePKCS10, data: &csr},
			{contentType: mimeTypePKCS7, data: &ekCerts},
			{contentType: mimeTypeOctetStream, data: &ekPub},
			{contentType: mimeTypeOctetStream, data: &akPub},
		},
	)
	if writeOnError(ctx, w, logMsgMultipartDecodeFailed, err) {
		return
	}

	// Validate EK public key matches that in the EK certificate. Note that
	// while the name of the AK (i.e. the hash of the entire AK public area)
	// will be used to protect the credential, only the name algorithm and
	// the symmetric encryption algorithm from the EK public area will be used,
	// so none of the protection depends on the EK public area and in general
	// it can be manipulated and is unreliable.
	if err := validatePublicAreaPublicKey(ekPub, ekCerts[0].PublicKey); err != nil {
		writeOnError(ctx, w, logMsgPublicKeyInvalid, err)
		return
	}

	// Note that we could verify if the AK public key matches that in the CSR,
	// but the TPM device will fail to activate the credential if a matching
	// key is not on the TPM, so even if we don't verify proof-of-possession,
	// the TPM privacy-preserving protocol will ensure that certificate can
	// only be decrypted by a TPM possessing that private key, so we achieve
	// the same end. Since it's possible a client may request a certificate for
	// a key which cannot be used for signing CSRs, and since the TPM privacy-
	// preserving protocol gives us a means to do that securely, we here choose
	// to allow it, and effectively ignore the public key in the CSR in a
	// manner similar to /serverkeygen.

	// Request credential blob and encrypted seed from backing CA.
	credBlob, encSeed, cred, err := caFromContext(ctx).TPMEnroll(ctx, csr, ekCerts, ekPub, akPub, aps, r)
	if writeOnError(ctx, w, logMsgEnrollFailed, err) {
		return
	}

	// Encode and write response.
	buf, contentType, err := encodeMultiPart(
		tpmEnrollBoundary,
		[]multipartPart{
			{contentType: mimeTypeOctetStream, data: credBlob},
			{contentType: mimeTypeOctetStream, data: encSeed},
			{contentType: mimeTypePKCS7Enveloped, data: cred},
		},
	)
	if writeOnError(ctx, w, logMsgMultipartEncodeFailed, err) {
		return
	}

	writeResponse(w, contentType, false, buf.Bytes())
}

// writeOnError writes returns true and writes an error to the provided HTTP
// response writer if error is nil. Otherwise, it returns false and does
// nothing.
func writeOnError(ctx context.Context, w http.ResponseWriter, msg string, err error) bool {
	if err == nil {
		return false
	}

	var estErr Error
	if errors.As(err, &estErr) {
		if estErr.StatusCode() == http.StatusInternalServerError {
			LoggerFromContext(ctx).Errorw(msg, logFieldError, err.Error())
		}

		w.Header().Set(contentTypeHeader, mimeTypeTextPlainUTF8)
		if secs := estErr.RetryAfter(); secs != 0 {
			w.Header().Set(retryAfterHeader, strconv.Itoa(secs))
		}

		w.WriteHeader(estErr.StatusCode())
		w.Write([]byte(fmt.Sprintf("%d %s\n", estErr.StatusCode(), estErr.Error())))
	} else {
		LoggerFromContext(ctx).Errorw(msg, logFieldError, err.Error())
		errInternal.Write(w)
	}

	return true
}

// withLogger is middleware that logs each HTTP request.
func withLogger(logger Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {

			// Capture our own copy of the logger so change in this closure
			// won't affect the object passed-in.

			logger := logger

			if reqID := middleware.GetReqID(r.Context()); reqID != "" {
				logger = logger.With("HTTP Request ID", reqID)
			}

			// Defer a function to log and entry once the main handler
			// has returned.

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			t1 := time.Now()

			defer func() {
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				}

				logger.Infow("HTTP request",
					"Method", r.Method,
					"URI", fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI),
					"Protocol", r.Proto,
					"Remote Address", r.RemoteAddr,
					"Status", ww.Status(),
					"Bytes Written", ww.BytesWritten(),
					"Time Taken", time.Since(t1),
				)
			}()

			ctx := context.WithValue(r.Context(), ctxKeyLogger, logger)
			next.ServeHTTP(ww, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

// recoverer is middleware which recovers from a panic and logs a stack trace.
func recoverer(logger Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Capture our own copy of the logger so change in this closure
			// won't affect the object passed-in.

			logger := logger

			// Defer a function to catch any panic and log a stack trace.

			defer func() {
				if rcv := recover(); rcv != nil {
					if reqID := middleware.GetReqID(r.Context()); reqID != "" {
						logger = logger.With("HTTP Request ID", reqID)
					}

					scheme := "http"
					if r.TLS != nil {
						scheme = "https"
					}

					logger.Errorw(
						logMsgPanicRecovery,
						"Method", r.Method,
						"URI", fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI),
						"Protocol", r.Proto,
						"Remote Address", r.RemoteAddr,
						"Panic Value", rcv,
						"Stack Trace", string(debug.Stack()),
					)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// requireContentType is middleware which rejects a request if the content
// type is not as stated.
func requireContentType(t string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := verifyRequestType(r.Header.Get(contentTypeHeader), t); err != nil {
				writeOnError(r.Context(), w, logMsgContentTypeInvalid, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// addServerHeader is middleware which writes to an HTTP response a Server HTTP
// header. Including too much detail (such as an operating system version) in
// this header can be a security risk, but including enough detail can sometimes
// enable clients to work around known bugs. Here, we restrict ourselves to
// returning the name and version of the server software.
func addServerHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(serverHeader, "GlobalSign EST Server "+estVersion)
		next.ServeHTTP(w, r)
	})
}

// addSecureHeaders is middleware which writes to an HTTP response a selection
// of secure HTTP headers as described by the OWASP Secure Headers Project. See
// https://owasp.org/www-project-secure-headers/. Many of these headers are of
// only limited use to us, since our intended clients are not browsers, but
// some may be useful for some clients.
func addSecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(strictTransportHeader, "max-age=31536000")
		w.Header().Set(contentTypeOptionsHeader, "nosniff")
		next.ServeHTTP(w, r)
	})
}

// verifyAllowedHosts is middleware which rejects a request if the host in the
// Host header is not in the list of allowed hosts.
func verifyAllowedHosts(allowed []string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqHost := r.Host
			if host, _, err := net.SplitHostPort(reqHost); err == nil {
				reqHost = host
			}

			goodHost := false
			for _, host := range allowed {
				if strings.EqualFold(host, reqHost) {
					goodHost = true
					break
				}
			}

			if !goodHost {
				errHostNotAllowed.Write(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimit is middleware which applies a general rate limit of limit requests
// per second, with a burst size of limit * 2 requests.
func rateLimit(limit int) func(next http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Every(time.Second/time.Duration(limit)), limit*2)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				errRateLimitExceeded.Write(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// maxBodySize is middleware which wraps the http.Request.Body with an
// http.MaxBytesReader with the specified maximum size.
func maxBodySize(sz int64) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, sz)
			next.ServeHTTP(w, r)
		})
	}
}

// requireBasicAuth is middleware which optionally requires HTTP Basic
// Authentication. If checkFunc is nil, authentication will succeed if and
// only if optional is true.
func requireBasicAuth(
	checkFunc func(context.Context, *http.Request, string, string, string) error,
	optional bool,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authenticated := false

			if checkFunc != nil {
				aps := chi.URLParam(r, apsParamName)
				username, password, _ := r.BasicAuth()
				if err := checkFunc(r.Context(), r, aps, username, password); err == nil {
					authenticated = true
				}
			} else if optional {
				authenticated = true
			}

			if !authenticated {
				reqHost := r.Host
				if host, _, err := net.SplitHostPort(reqHost); err == nil {
					reqHost = host
				}

				w.Header().Set(wwwAuthenticateHeader, fmt.Sprintf(`Basic realm="estserver@%s"`,
					url.QueryEscape(reqHost)))
				errAuthRequired.Write(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
