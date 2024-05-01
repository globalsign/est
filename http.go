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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

type multipartPart struct {
	contentType string
	data        interface{}
}

var httpTimeFormats = []string{
	time.RFC1123,
	time.RFC1123Z,
	time.RFC850,
	time.ANSIC,
}

func ordinal(n int) string {
	retval := "unknown"

	switch n {
	case 1:
		retval = "first"
	case 2:
		retval = "second"
	case 3:
		retval = "third"
	case 4:
		retval = "fourth"
	case 5:
		retval = "fifth"
	case 6:
		retval = "sixth"
	case 7:
		retval = "seventh"
	case 8:
		retval = "eighth"
	case 9:
		retval = "ninth"
	case 10:
		retval = "tenth"
	}

	return retval
}

func decodeMultipartRequest(r *http.Request, parts []multipartPart) (int, error) {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get(contentTypeHeader))
	if err != nil {
		return 0, &estError{
			status: http.StatusUnsupportedMediaType,
			desc:   fmt.Sprintf("malformed or missing %s header", contentTypeHeader),
		}
	}
	if !strings.HasPrefix(mediaType, mimeTypeMultipart) {
		return 0, &estError{
			status: http.StatusUnsupportedMediaType,
			desc:   fmt.Sprintf("%s must be %s", contentTypeHeader, mimeTypeMultipart),
		}
	}

	var numParts = 0
	mpr := multipart.NewReader(r.Body, params[mimeParamBoundary])

	for i, part := range parts {
		p, err := mpr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return 0, errBodyParse
		}
		defer p.Close()

		if err := verifyPartType(p, part.contentType, encodingTypeBase64, ordinal(i)); err != nil {
			return 0, err
		}

		switch t := part.data.(type) {
		case **x509.CertificateRequest:
			csr, err := readCSRRequest(p, true)
			if err != nil {
				return 0, err
			}

			*t = csr

		case *[]*x509.Certificate:
			certs, err := readCertsRequest(p)
			if err != nil {
				return 0, err
			}

			*t = certs

		case *[]byte:
			pub, err := readTPMPublicAreaRequest(p)
			if err != nil {
				return 0, err
			}

			*t = pub

		default:
			return 0, errInternal
		}

		numParts++
	}

	return numParts, nil
}

func encodeMultiPart(boundary string, parts []multipartPart) (*bytes.Buffer, string, error) {
	buf := bytes.NewBuffer([]byte{})
	w := multipart.NewWriter(buf)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, "", fmt.Errorf("failed to set multipart writer boundary: %w", err)
	}

	for _, part := range parts {
		var data []byte
		var err error

		switch t := part.data.(type) {
		case []*x509.Certificate:
			data, err = encodePKCS7CertsOnly(t)
			if err != nil {
				return nil, "", err
			}

		case *x509.Certificate:
			data, err = encodePKCS7CertsOnly([]*x509.Certificate{t})
			if err != nil {
				return nil, "", err
			}

		case *x509.CertificateRequest:
			data = t.Raw

		case []byte:
			data = t

		default:
			return nil, "", fmt.Errorf("unexpected multipart part body type: %T", t)
		}

		v := textproto.MIMEHeader{}
		v.Add(contentTypeHeader, part.contentType)
		v.Add(transferEncodingHeader, encodingTypeBase64)
		data = base64Encode(data)

		pw, err := w.CreatePart(v)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create multipart writer part: %w", err)
		}

		if _, err := pw.Write(data); err != nil {
			return nil, "", fmt.Errorf("failed to write to multipart writer: %w", err)
		}
	}

	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	return buf, fmt.Sprintf("%s; %s=%s", mimeTypeMultipart, mimeParamBoundary, boundary), nil
}

// parseHTTPTime attempts to parse an HTTP-time against a selection of layouts.
func parseHTTPTime(s string) (time.Time, error) {
	// Per RFC7231, a recipient that parses a timestamp value in an HTTP
	// header field must accept all three of the layouts:
	//
	//  - Sun, 06 Nov 1994 08:49:37 GMT    ; IMF-fixdate
	//  - Sunday, 06-Nov-94 08:49:37 GMT   ; obsolete RFC 850 format
	//  - Sun Nov  6 08:49:37 1994         ; ANSI C's asctime() format
	//
	// Here, time.RFC1123 is a close enough proxy for IMF-fixdate.
	for _, layout := range httpTimeFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, errors.New("failed to parse time")
}

// verifyPartType checks if the content-type and content-transfer-encoding of
// a multipart-part is as expected.
func verifyPartType(part *multipart.Part, ct, ce, pos string) error {
	ctype, _, err := mime.ParseMediaType(part.Header.Get(contentTypeHeader))
	if err != nil || !strings.HasPrefix(ctype, ct) {
		return &estError{
			status: http.StatusUnsupportedMediaType,
			desc:   fmt.Sprintf("%s of %s part must be %s", contentTypeHeader, pos, ct),
		}
	}

	if part.Header.Get(transferEncodingHeader) != ce {
		return &estError{
			status: http.StatusUnsupportedMediaType,
			desc:   fmt.Sprintf("%s of %s part must be %s", transferEncodingHeader, pos, ce),
		}
	}

	return nil
}

// verifyResponseType verifies if the content-type and content-transfer-encoding
// of an HTTP response are as expected. It returns a normal error and is intended
// to be used by client code.
func verifyResponseType(r *http.Response, t, e string) error {
	ctype, _, err := mime.ParseMediaType(r.Header.Get(contentTypeHeader))
	if err != nil {
		return fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
	}

	if !strings.HasPrefix(ctype, t) {
		return fmt.Errorf("unexpected %s: %s", contentTypeHeader, ctype)
	}

	return nil
}

// verifyPartTypeResponse verifies if the content-type and content-transfer-encoding
// of a multipart response part are as expected. It returns a normal error and
// is intended to be used by client code.
func verifyPartTypeResponse(part *multipart.Part, t, e string) error {
	ctype, _, err := mime.ParseMediaType(part.Header.Get(contentTypeHeader))
	if err != nil {
		return fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
	}

	if !strings.HasPrefix(ctype, t) {
		return fmt.Errorf("unexpected %s: %s", contentTypeHeader, ctype)
	}

	return nil
}

// verifyRequestType verifies if the content-type of an HTTP request is as
// expected. It returns an error implementing Error and is intended to be used
// by server code.
func verifyRequestType(have, want string) error {
	mediaType, _, err := mime.ParseMediaType(have)
	if err != nil {
		return &estError{
			status: http.StatusUnsupportedMediaType,
			desc:   fmt.Sprintf("malformed or missing %s header", contentTypeHeader),
		}
	}
	if !strings.HasPrefix(mediaType, want) {
		return &estError{
			status: http.StatusUnsupportedMediaType,
			desc:   fmt.Sprintf("%s must be %s", contentTypeHeader, want),
		}
	}

	return nil
}

// writeResponse writes headers, a status code, and an object containing the
// body to an HTTP response. If encode is true, the object is base64-encoded.
// The appropriate encoding is chosen according to the object's type.
func writeResponse(w http.ResponseWriter, contentType string, encode bool, obj interface{}) {
	if contentType != "" {
		w.Header().Set(contentTypeHeader, contentType)
	}

	var body []byte
	var err error = errInternal

	switch t := obj.(type) {
	case []*x509.Certificate:
		body, err = encodePKCS7CertsOnly(t)

	case *x509.Certificate:
		body, err = encodePKCS7CertsOnly([]*x509.Certificate{t})

	case CSRAttrs:
		body, err = t.Marshal()

	case []byte:
		body, err = t, nil
	}

	if err != nil {
		errInternal.Write(w)
		return
	}

	if encode {
		w.Header().Set(transferEncodingHeader, encodingTypeBase64)
		body = base64Encode(body)
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
