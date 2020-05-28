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
	"errors"
	"math/big"
)

// CSRAttrs contains CSR attributes as defined by RFC7030 4.5.
//
// CSR attributes are defined by RFC7030 as a sequence of AttrOrOID, where
// AttrOrOID is a CHOICE of Object Identifier or Attribute. For ease of use,
// CRSAttrs provides separately a list of Object Identifiers, and a list of
// Attributes.
//
// When the EST client retrieves and parses CSR attributes from an EST server,
// attribute values of the ASN.1 types:
//
//  - OBJECT IDENTIFIER
//  - BOOLEAN
//  - INTEGER
//  - most STRING types
//
// will be unmarshalled into the Attribute.Values field as standard Go
// asn1.ObjectIdentifier, bool, *big.Int and string types where possible, and
// they can be retrieved via a type assertion. Other types will be unmarshalled
// into an asn1.RawValue structure and must be interpreted by the caller.
type CSRAttrs struct {
	OIDs       []asn1.ObjectIdentifier
	Attributes []Attribute
}

// Attribute is a CSR Attribute type, as defined by RFC7030 4.5.2.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values AttributeValueSET
}

// AttributeValueSET is an ASN.1 SET of CSR attribute values.
type AttributeValueSET []interface{}

var (
	errTrailingASN1 = errors.New("trailing ASN.1 bytes")
)

// Marshal returns the ASN.1 DER-encoding of a value.
func (a CSRAttrs) Marshal() ([]byte, error) {
	seq := make([]interface{}, 0, len(a.OIDs)+len(a.Attributes))

	for i := range a.OIDs {
		seq = append(seq, a.OIDs[i])
	}

	for i := range a.Attributes {
		seq = append(seq, a.Attributes[i])
	}

	return asn1.Marshal(seq)
}

// Unmarshal parses an DER-encoded ASN.1 data structure and stores the result
// in the object. Attribute values of the ASN.1 types:
//
//  - OBJECT IDENTIFIER
//  - BOOLEAN
//  - INTEGER
//  - most STRING types
//
// will be unmarshalled into standard Go asn1.ObjectIdentifier, bool, *big.Int
// and string types where possible, and can be retrieved via a type assertion.
// Other types will be unmarshalled into an asn1.RawValue structure and must
// be interpreted by the caller.
func (a *CSRAttrs) Unmarshal(b []byte) error {

	// CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
	//
	// AttrOrOID ::= CHOICE (oid OBJECT IDENTIFIER, attribute Attribute }
	//
	// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
	//      type   ATTRIBUTE.&id({IOSet}),
	//      values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type}) }

	// First, unmarshal the SEQUENCE of AttrOrOID into a slice.

	var seq []asn1.RawValue

	rest, err := asn1.Unmarshal(b, &seq)
	if err != nil {
		return err
	} else if len(rest) > 0 {
		return errTrailingASN1
	}

	var oids []asn1.ObjectIdentifier
	var attrs []Attribute

	// Then loop through each AttrOrOID in the SEQUENCE.

	for _, item := range seq {
		switch item.Tag {
		case asn1.TagOID:

			// It's an OID, so unmarshal it into an asn1.ObjectIdentifier.

			var oid asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(item.FullBytes, &oid); err != nil {
				return err
			} else if len(rest) > 0 {
				return errTrailingASN1
			}

			oids = append(oids, oid)

		case asn1.TagSequence:

			// It's an Attribute, so first unmarshal it into a temporary
			// structure with a type and a SET of raw ASN.1 values. Note
			// that the asn1 package needs the custom type to unmarshal
			// a SET rather than a SEQUENCE.

			type attrValuesSET []asn1.RawValue

			var raw struct {
				Type   asn1.ObjectIdentifier
				Values attrValuesSET
			}
			if rest, err := asn1.Unmarshal(item.FullBytes, &raw); err != nil {
				return err
			} else if len(rest) > 0 {
				return errTrailingASN1
			}

			var attr = Attribute{
				Type: raw.Type,
			}

			// Parse each value in the set. If the type is one of the supported
			// types, then convert it to the appropriate Go type before storing
			// it in the returned structure, otherwise return the asn1.RawValue.
			for _, value := range raw.Values {
				switch value.Tag {
				case asn1.TagBoolean:
					var b bool
					if rest, err := asn1.Unmarshal(value.FullBytes, &b); err != nil {
						return err
					} else if len(rest) > 0 {
						return errTrailingASN1
					}
					attr.Values = append(attr.Values, b)

				case asn1.TagInteger:
					var n *big.Int
					if rest, err := asn1.Unmarshal(value.FullBytes, &n); err != nil {
						return err
					} else if len(rest) > 0 {
						return errTrailingASN1
					}
					attr.Values = append(attr.Values, n)

				case asn1.TagUTF8String,
					asn1.TagNumericString,
					asn1.TagPrintableString,
					asn1.TagT61String,
					asn1.TagIA5String,
					asn1.TagGeneralString:
					var s string
					if rest, err := asn1.Unmarshal(value.FullBytes, &s); err != nil {
						return err
					} else if len(rest) > 0 {
						return errTrailingASN1
					}
					attr.Values = append(attr.Values, s)

				case asn1.TagOID:
					var oid asn1.ObjectIdentifier
					if rest, err := asn1.Unmarshal(value.FullBytes, &oid); err != nil {
						return err
					} else if len(rest) > 0 {
						return errTrailingASN1
					}
					attr.Values = append(attr.Values, oid)

				default:
					attr.Values = append(attr.Values, value)
				}
			}

			attrs = append(attrs, attr)
		}
	}

	// Store the result in the object and return.
	*a = CSRAttrs{
		OIDs:       oids,
		Attributes: attrs,
	}

	return nil
}
