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
	"fmt"
	"net/http"
)

// estError is an internal error structure implementing est.Error.
type estError struct {
	status     int
	desc       string
	retryAfter int
}

// Internal error values.
var (
	errAuthRequired = &estError{
		status: http.StatusUnauthorized,
		desc:   "authorization required",
	}
	errBodyParse = &estError{
		status: http.StatusBadRequest,
		desc:   "unable to parse request body",
	}
	errExtractPublicAreaKey = &estError{
		status: http.StatusBadRequest,
		desc:   "unable to extract public key from TPM object public area",
	}
	errHostNotAllowed = &estError{
		status: http.StatusBadRequest,
		desc:   "host not allowed",
	}
	errInternal = &estError{
		status: http.StatusInternalServerError,
		desc:   "internal server error",
	}
	errInvalidBase64 = &estError{
		status: http.StatusBadRequest,
		desc:   "invalid base64 encoding",
	}
	errInvalidClientCert = &estError{
		status: http.StatusForbidden,
		desc:   "invalid client certificate",
	}
	errInvalidPKCS7 = &estError{
		status: http.StatusBadRequest,
		desc:   "malformed PKCS7 structure",
	}
	errInvalidPKCS10 = &estError{
		status: http.StatusBadRequest,
		desc:   "malformed PKCS10 certificate signing request",
	}
	errInvalidPKCS10Signature = &estError{
		status: http.StatusBadRequest,
		desc:   "invalid PKCS10 certificate signing request signature",
	}
	errInvalidTPMPublicArea = &estError{
		status: http.StatusBadRequest,
		desc:   "malformed TPM object public area",
	}
	errMalformedCert = &estError{
		status: http.StatusBadRequest,
		desc:   "malformed certificate",
	}
	errNoCertificatesInPKCS7 = &estError{
		status: http.StatusBadRequest,
		desc:   "no certificates found in PKCS7 structure",
	}
	errNoClientCertificate = &estError{
		status: http.StatusForbidden,
		desc:   "client certificate must be provided for /simplereenroll",
	}
	errRateLimitExceeded = &estError{
		status: http.StatusTooManyRequests,
		desc:   "rate limit exceeded",
	}
	errSubjectChanged = &estError{
		status: http.StatusForbidden,
		desc:   "Subject and SubjectAltName fields in CSR must be identical to certificate being renewed",
	}
	errTPMPublicAreaFlags = &estError{
		status: http.StatusUnprocessableEntity,
		desc:   "EK is not a storage key",
	}
	errTPMPublicKeyNoMatch = &estError{
		status: http.StatusUnprocessableEntity,
		desc:   "public key in public area doesn't match",
	}
)

// StatusCode returns the HTTP status code.
func (e estError) StatusCode() int {
	return e.status
}

// Error returns a human-readable description of the error.
func (e estError) Error() string {
	if e.desc == "" {
		return http.StatusText(e.status)
	}

	return e.desc
}

// RetryAfter returns the value in seconds after which the client should
// retry the request.
func (e estError) RetryAfter() int {
	return e.retryAfter
}

// Write writes the error to the supplied writer.
func (e estError) Write(w http.ResponseWriter) {
	w.Header().Set(contentTypeHeader, mimeTypeTextPlainUTF8)
	w.WriteHeader(e.status)
	w.Write([]byte(fmt.Sprintf("%d %s\n", e.status, e.desc)))
}
