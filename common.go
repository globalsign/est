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
	"encoding/asn1"
	"io"
)

// URI constants.
const (
	cacertsEndpoint      = "/cacerts"
	csrattrsEndpoint     = "/csrattrs"
	enrollEndpoint       = "/simpleenroll"
	estPathPrefix        = "/.well-known/est"
	healthCheckEndpoint  = "/healthcheck"
	reenrollEndpoint     = "/simplereenroll"
	serverkeygenEndpoint = "/serverkeygen"
	tpmenrollEndpoint    = "/tpmenroll"
)

// HTTP header and MIME type constants.
const (
	acceptHeader             = "Accept"
	contentTypeHeader        = "Content-Type"
	contentTypeOptionsHeader = "X-Content-Type-Options"
	encodingTypeBase64       = "base64"
	mimeParamBoundary        = "boundary"
	mimeParamSMIMEType       = "smime-type"
	mimeTypeCertificate      = "application/pkix-cert"
	mimeTypeCSRAttrs         = "application/csrattrs"
	mimeTypeJSON             = "application/json"
	mimeTypeMultipart        = "multipart/mixed"
	mimeTypeOctetStream      = "application/octet-stream"
	mimeTypePKCS10           = "application/pkcs10"
	mimeTypePKCS7            = "application/pkcs7-mime"
	mimeTypePKCS7CertsOnly   = "application/pkcs7-mime; smime-type=certs-only"
	mimeTypePKCS7Enveloped   = "application/pkcs7-mime; smime-type=enveloped-data"
	mimeTypePKCS7GenKey      = "application/pkcs7-mime; smime-type=server-generated-key"
	mimeTypePKCS8            = "application/pkcs8"
	mimeTypeProblemJSON      = "application/problem+json"
	mimeTypeTextPlain        = "text/plain"
	mimeTypeTextPlainUTF8    = "text/plain; charset=utf-8"
	paramValueCertsOnly      = "certs-only"
	paramValueGenKey         = "server-generated-key"
	retryAfterHeader         = "Retry-After"
	serverHeader             = "Server"
	serverKeyGenBoundary     = "estServerKeyGenBoundary"
	strictTransportHeader    = "Strict-Transport-Security"
	tpmEnrollBoundary        = "estTPMEnrollBoundary"
	transferEncodingHeader   = "Content-Transfer-Encoding"
	userAgentHeader          = "User-Agent"
	wwwAuthenticateHeader    = "WWW-Authenticate"
)

// Other variables.
var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// consumeAndClose discards any remaining data in the io.ReadCloser and then
// closes it.
func consumeAndClose(rc io.ReadCloser) {
	io.Copy(io.Discard, rc)
	rc.Close()
}
