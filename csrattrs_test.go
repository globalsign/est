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

package est_test

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"

	"github.com/arlotito/est"
)

func TestCSRAttrsMarshal(t *testing.T) {
	t.Parallel()

	type oidSET []asn1.ObjectIdentifier

	var testcases = []struct {
		name  string
		attrs est.CSRAttrs
		want  []byte
	}{
		{
			name:  "Empty",
			attrs: est.CSRAttrs{},
			want:  []byte{asn1.TagSequence | 0x01<<5, 0},
		},
		{
			name: "VariousAttributeTypes",
			attrs: est.CSRAttrs{
				Attributes: []est.Attribute{
					{
						Type: asn1.ObjectIdentifier{1, 2, 3, 4},
						Values: est.AttributeValueSET{
							true,
							big.NewInt(42),
							"beans",
						},
					},
				},
			},
			want: []byte{asn1.TagSequence | 0x01<<5, 0x16,
				asn1.TagSequence | 0x01<<5, 0x14,
				asn1.TagOID, 0x03, 0x2a, 0x03, 0x04,
				asn1.TagSet | 0x01<<5, 0x0d,
				asn1.TagBoolean, 0x01, 0xff,
				asn1.TagInteger, 0x01, 0x2a,
				asn1.TagPrintableString, 0x05, 'b', 'e', 'a', 'n', 's',
			},
		},
		{
			name: "RFC7030Example",
			attrs: est.CSRAttrs{
				OIDs: []asn1.ObjectIdentifier{
					{1, 2, 840, 113549, 1, 9, 7},
					{1, 2, 840, 10045, 4, 3, 3},
				},
				Attributes: []est.Attribute{
					{
						Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
						Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 6, 1, 1, 1, 1, 22}},
					},
					{
						Type:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
						Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
					},
				},
			},
			want: []byte{asn1.TagSequence | 0x01<<5, 0x41,
				asn1.TagOID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07,
				asn1.TagOID, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
				asn1.TagSequence | 0x01<<5, 0x16,
				asn1.TagOID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
				asn1.TagSet | 0x01<<5, 0x09,
				asn1.TagOID, 0x07, 0x2b, 0x06, 0x01, 0x01, 0x01, 0x01, 0x16,
				asn1.TagSequence | 0x01<<5, 0x12,
				asn1.TagOID, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
				asn1.TagSet | 0x01<<5, 0x07,
				asn1.TagOID, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.attrs.Marshal()
			if err != nil {
				t.Fatalf("failed to marshal CSR attributes: %v", err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCSRAttrsUnmarshal(t *testing.T) {
	t.Parallel()

	type oidSET []asn1.ObjectIdentifier

	var testcases = []struct {
		name string
		der  []byte
		want est.CSRAttrs
	}{
		{
			name: "Empty",
			der:  []byte{asn1.TagSequence | 0x01<<5, 0},
			want: est.CSRAttrs{},
		},
		{
			name: "VariousAttributeTypes",
			der: []byte{asn1.TagSequence | 0x01<<5, 0x16,
				asn1.TagSequence | 0x01<<5, 0x14,
				asn1.TagOID, 0x03, 0x2a, 0x03, 0x04,
				asn1.TagSet | 0x01<<5, 0x0d,
				asn1.TagBoolean, 0x01, 0xff,
				asn1.TagInteger, 0x01, 0x2a,
				asn1.TagPrintableString, 0x05, 'b', 'e', 'a', 'n', 's',
			},
			want: est.CSRAttrs{
				Attributes: []est.Attribute{
					{
						Type: asn1.ObjectIdentifier{1, 2, 3, 4},
						Values: est.AttributeValueSET{
							true,
							big.NewInt(42),
							"beans",
						},
					},
				},
			},
		},
		{
			name: "RFC7030Example",
			der: []byte{asn1.TagSequence | 0x01<<5, 0x41,
				asn1.TagOID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07,
				asn1.TagOID, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
				asn1.TagSequence | 0x01<<5, 0x16,
				asn1.TagOID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
				asn1.TagSet | 0x01<<5, 0x09,
				asn1.TagOID, 0x07, 0x2b, 0x06, 0x01, 0x01, 0x01, 0x01, 0x16,
				asn1.TagSequence | 0x01<<5, 0x12,
				asn1.TagOID, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
				asn1.TagSet | 0x01<<5, 0x07,
				asn1.TagOID, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
			},
			want: est.CSRAttrs{
				OIDs: []asn1.ObjectIdentifier{
					{1, 2, 840, 113549, 1, 9, 7},
					{1, 2, 840, 10045, 4, 3, 3},
				},
				Attributes: []est.Attribute{
					{
						Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
						Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 6, 1, 1, 1, 1, 22}},
					},
					{
						Type:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
						Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got est.CSRAttrs
			err := got.Unmarshal(tc.der)
			if err != nil {
				t.Fatalf("failed to unmarshal CSR attributes: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
