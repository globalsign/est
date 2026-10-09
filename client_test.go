/*
Copyright (c) 2026 GMO GlobalSign, Inc.

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
	"net/http"
	"testing"
)

func TestUri(t *testing.T) {
	t.Parallel()

	var testCases = []struct {
		name    string
		host    string
		segment string
		want    string
	}{
		{
			name: "Hostname",
			host: "est.example.com:8443",
			want: "https://est.example.com:8443/.well-known/est/cacerts",
		},
		{
			name:    "AdditionalPathSegment",
			host:    "est.example.com:8443",
			segment: "ca1",
			want:    "https://est.example.com:8443/.well-known/est/ca1/cacerts",
		},
		{
			name: "IPv4",
			host: "192.0.2.1:8443", // 192.0.2.x range is reserved for documentation
			want: "https://192.0.2.1:8443/.well-known/est/cacerts",
		},
		{
			name: "IPv6 global",
			host: "[fe80::1]:8443",
			want: "https://[fe80::1]:8443/.well-known/est/cacerts",
		},
		{
			name: "IPv6 link-local",
			host: "[fe80::1%eth0]:8443",
			want: "https://[fe80::1%25eth0]:8443/.well-known/est/cacerts",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// arrange
			c := &Client{
				Host:                  tc.host,
				AdditionalPathSegment: tc.segment,
			}

			// act
			got := c.uri(cacertsEndpoint)

			// assert
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}

			if _, err := http.NewRequest(http.MethodGet, got, nil); err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
		})
	}
}
