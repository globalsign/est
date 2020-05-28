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
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// option represents a command line option, and is used both for creating a
// command line flag set, and for formatting a list of options in a usage
// message.
type option struct {
	// argFmt is an optional type label to display for the option, e.g.
	// "<string>" or "<path>".
	argFmt string

	// DefaultLabel is an optional default value to display for the option.
	defaultLabel interface{}

	// defaultValue is the required default value for the option. This is used
	// to determine the type of flag to create when populating a flag set. If
	// this value is nil a panic will result.
	defaultValue interface{}

	// desc is a brief description for the option.
	desc string
}

// Global constants.
const (
	appName        = "estclient"
	defaultTimeout = time.Second * 15
	sepChar        = ","
	versionString  = "1.0.0"
)

// Flag name constants.
const (
	apsFlag                = "aps"
	certsFlag              = "certs"
	commonFlag             = "common"
	commonNameFlag         = "cn"
	configFlag             = "config"
	countryFlag            = "country"
	csrFlag                = "csr"
	dnsNamesFlag           = "dnsnames"
	ekcertsFlag            = "ekcerts"
	emailsFlag             = "emails"
	explicitAnchorFlag     = "explicit"
	headersFlag            = "headers"
	helpFlag               = "help"
	hostHeaderFlag         = "hostheader"
	hsmFlag                = "hsm"
	implicitAnchorFlag     = "implicit"
	insecureFlag           = "insecure"
	ipsFlag                = "ips"
	keyFlag                = "key"
	keyOutFlag             = "keyout"
	localityFlag           = "locality"
	organizationFlag       = "org"
	organizationalUnitFlag = "ou"
	outFlag                = "out"
	passwordFlag           = "pass"
	postalCodeFlag         = "postalcode"
	provinceFlag           = "province"
	rootOutFlag            = "rootout"
	separatorFlag          = "separator"
	serialNumberFlag       = "sn"
	serverFlag             = "server"
	streetAddressFlag      = "street"
	timeoutFlag            = "timeout"
	tpmFlag                = "tpm"
	urisFlag               = "uris"
	usernameFlag           = "user"
)

// Option format constants.
const (
	durFmt    = "<duration>"
	hostFmt   = "<host:port>"
	pathFmt   = "<path>"
	stringFmt = "<string>"
)

// List of flag names for any command which accepts a set of CSR-generating
// options, e.g. csr, enroll and serverkeygen.
var csrFlags = []string{
	commonNameFlag,
	countryFlag,
	dnsNamesFlag,
	emailsFlag,
	ipsFlag,
	localityFlag,
	organizationFlag,
	organizationalUnitFlag,
	postalCodeFlag,
	provinceFlag,
	serialNumberFlag,
	streetAddressFlag,
	urisFlag,
}

// Global command line option definitions.
var optDefs = map[string]option{
	apsFlag: {
		argFmt:       stringFmt,
		defaultLabel: "none",
		defaultValue: "",
		desc:         "optional additional path segment",
	},
	certsFlag: {
		argFmt:       pathFmt,
		defaultLabel: "none",
		desc:         "TLS client certificate(s)",
		defaultValue: "",
	},
	commonFlag: {
		desc:         "show information about common options",
		defaultValue: false,
	},
	configFlag: {
		argFmt:       pathFmt,
		defaultLabel: "none",
		desc:         "configuration file",
		defaultValue: "",
	},
	csrFlag: {
		argFmt:       pathFmt,
		desc:         "PKCS#10 certificate signing request",
		defaultValue: "",
	},
	ekcertsFlag: {
		argFmt:       pathFmt,
		desc:         "endorsement key certificate(s) chain",
		defaultValue: "",
	},
	explicitAnchorFlag: {
		argFmt:       pathFmt,
		defaultLabel: "none",
		desc:         "explicit anchor file",
		defaultValue: "",
	},
	implicitAnchorFlag: {
		argFmt:       pathFmt,
		defaultLabel: "none",
		desc:         "implicit anchor file",
		defaultValue: "",
	},
	helpFlag: {
		desc:         "show this usage information",
		defaultValue: false,
	},
	headersFlag: {
		argFmt:       stringFmt,
		desc:         "optional list of additional HTTP headers",
		defaultValue: "",
	},
	hostHeaderFlag: {
		argFmt:       stringFmt,
		desc:         "override HTTP host header",
		defaultValue: "",
	},
	hsmFlag: {
		desc:         "output sample file for HSM-resident key",
		defaultValue: false,
	},
	insecureFlag: {
		desc:         "omit server TLS certificate verification",
		defaultValue: false,
	},
	keyFlag: {
		argFmt:       pathFmt,
		desc:         "private key",
		defaultValue: "",
	},
	keyOutFlag: {
		argFmt:       pathFmt,
		defaultLabel: "stdout",
		desc:         "output file for private key",
		defaultValue: "",
	},
	outFlag: {
		argFmt:       pathFmt,
		defaultLabel: "stdout",
		desc:         "output file",
		defaultValue: "",
	},
	passwordFlag: {
		argFmt:       stringFmt,
		defaultLabel: "none",
		desc:         "HTTP Basic Auth password",
		defaultValue: "",
	},
	rootOutFlag: {
		argFmt:       pathFmt,
		desc:         "output root CA certificate only",
		defaultValue: false,
	},
	separatorFlag: {
		argFmt:       stringFmt,
		defaultLabel: sepChar,
		desc:         "list item separator character",
		defaultValue: "",
	},
	serverFlag: {
		argFmt:       hostFmt,
		desc:         "server host and port",
		defaultValue: "",
	},
	usernameFlag: {
		argFmt:       stringFmt,
		defaultLabel: "none",
		desc:         "HTTP Basic Auth username",
		defaultValue: "",
	},
	timeoutFlag: {
		argFmt:       durFmt,
		defaultLabel: defaultTimeout,
		desc:         "request timeout",
		defaultValue: time.Duration(0),
	},
	tpmFlag: {
		desc:         "output sample file for TPM-resident key",
		defaultValue: false,
	},
	commonNameFlag: {
		argFmt:       stringFmt,
		desc:         "subject common name",
		defaultValue: "",
	},
	countryFlag: {
		argFmt:       stringFmt,
		desc:         "subject country",
		defaultValue: "",
	},
	dnsNamesFlag: {
		argFmt:       stringFmt,
		desc:         "subject alternative name DNS names",
		defaultValue: "",
	},
	emailsFlag: {
		argFmt:       stringFmt,
		desc:         "subject alternative name email addresses",
		defaultValue: "",
	},
	ipsFlag: {
		argFmt:       stringFmt,
		desc:         "subject alternative name IP addresses",
		defaultValue: "",
	},
	localityFlag: {
		argFmt:       stringFmt,
		desc:         "subject locality/city",
		defaultValue: "",
	},
	organizationalUnitFlag: {
		argFmt:       stringFmt,
		desc:         "subject organizational unit",
		defaultValue: "",
	},
	organizationFlag: {
		argFmt:       stringFmt,
		desc:         "subject organization",
		defaultValue: "",
	},
	postalCodeFlag: {
		argFmt:       stringFmt,
		desc:         "subject postal/zip code",
		defaultValue: "",
	},
	provinceFlag: {
		argFmt:       stringFmt,
		desc:         "subject province/state",
		defaultValue: "",
	},
	serialNumberFlag: {
		argFmt:       stringFmt,
		desc:         "subject serial number",
		defaultValue: "",
	},
	streetAddressFlag: {
		argFmt:       stringFmt,
		desc:         "subject street address",
		defaultValue: "",
	},
	urisFlag: {
		argFmt:       stringFmt,
		desc:         "subject alternative name URIs",
		defaultValue: "",
	},
}

// listOpts outputs a formatted list of command line options.
func listOpts(w io.Writer, opts []string) {
	sort.Strings(opts)

	fieldWidth := 0
	for _, opt := range opts {
		def, ok := optDefs[opt]
		if !ok {
			panic(fmt.Sprintf("undefined option: %s", opt))
		}

		n := len(opt)
		if def.argFmt != "" {
			n += len(def.argFmt) + 1
		}

		if n+4 > fieldWidth {
			fieldWidth = n + 4
		}
	}

	for _, opt := range opts {
		var builder strings.Builder
		def, _ := optDefs[opt]
		argFmt := ""
		if def.argFmt != "" {
			argFmt = " " + def.argFmt
		}
		builder.WriteString(fmt.Sprintf("-%-*s%s", fieldWidth, opt+argFmt, def.desc))
		if def.defaultLabel != nil {
			builder.WriteString(fmt.Sprintf(" (default: %v)", def.defaultLabel))
		}

		fmt.Fprintf(w, "    %s\n", builder.String())
	}
}

// isFlagPassed checks if the named flag was passed.
func isFlagPassed(set *flag.FlagSet, name string) bool {
	if set == nil {
		return false
	}

	found := false
	set.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})

	return found
}

// usageError outputs a brief usage message and exits with status code 1.
func usageError(w io.Writer, line int) {
	outputPara(w, line, 0, usageShort)
	outputPara(w, line, 0, fmt.Sprintf(`Use "%s help" for a list of commands.`, appName))
	os.Exit(1)
}

// version outputs version information.
func version(w io.Writer, set *flag.FlagSet) error {
	fmt.Fprintf(w, "GlobalSign EST Client %s\n", versionString)
	return nil
}

// usageMain outputs a full usage message for the application.
func usageMain(w io.Writer, set *flag.FlagSet) error {
	outputPara(w, usageLineLength, 0, usageShort)
	outputPara(w, usageLineLength, 0, usageMainPara)

	cmdNames := commands.Names()

	fieldWidth := 0
	for _, name := range cmdNames {
		if n := len(name); n+4 > fieldWidth {
			fieldWidth = n + 4
		}
	}

	fmt.Fprintln(w, "Commands:")
	for _, name := range cmdNames {
		cmd, _ := commands[name]
		fmt.Fprintf(w, "%s%-*s %s\n", strings.Repeat(" ", usageIndent), fieldWidth, name, cmd.shortDesc)
	}
	fmt.Fprintln(w)
	outputPara(w, usageLineLength, 0, usageCommandPara)

	if !isFlagPassed(set, commonFlag) {
		outputPara(w, usageLineLength, 0, usageCommonPara)

		return nil
	}

	fmt.Fprintln(w, "Configuration file:")
	outputPara(w, usageLineLength, usageIndent, usageConfigIntroPara)
	outputPara(w, usageLineLength, usageIndent, usageConfigLocationPara)
	outputPara(w, usageLineLength, usageIndent, usageConfigKeysPara)

	fmt.Fprintln(w, "Explicit and implicit anchors:")
	outputPara(w, usageLineLength, usageIndent, usageAnchorsIntroPara)
	outputPara(w, usageLineLength, usageIndent, usageAnchorsFormatPara)
	outputPara(w, usageLineLength, usageIndent, usageAnchorsInsecurePara)

	fmt.Fprintln(w, "Additional path segment:")
	outputPara(w, usageLineLength, usageIndent, usageAPSIntroPara)

	fmt.Fprintln(w, "TLS client certificates:")
	outputPara(w, usageLineLength, usageIndent, usageCertsIntroPara)
	outputPara(w, usageLineLength, usageIndent, usageCertsFormatPara)
	outputPara(w, usageLineLength, usageIndent, usageCertsKeyPara)

	fmt.Fprintln(w, "Additional HTTP headers:")
	outputPara(w, usageLineLength, usageIndent, usageHeadersPara)
	outputPara(w, usageLineLength, usageIndent*2, usageHeadersExample)

	fmt.Fprintln(w, "HTTP Host header:")
	outputPara(w, usageLineLength, usageIndent, usageHostHeaderPara)

	fmt.Fprintln(w, "Request timeout:")
	outputPara(w, usageLineLength, usageIndent, usageTimeoutPara)

	return nil
}

// usageCSRFlags outputs a partial usage message describing the CSR field
// flags.
func usageCSRFlags(w io.Writer, line int) {
	fmt.Fprintln(w, "CSR field options:")
	listOpts(w, []string{
		commonNameFlag,
		serialNumberFlag,
		organizationalUnitFlag,
		organizationFlag,
		streetAddressFlag,
		localityFlag,
		provinceFlag,
		postalCodeFlag,
		countryFlag,
		dnsNamesFlag,
		emailsFlag,
		ipsFlag,
		urisFlag,
	})
	fmt.Fprintln(w)

	outputPara(w, line, 0, usageCSRMultiPara)
}

// usageCommon outputs a partial usage message describing how to obtain further
// information about common command line options.
func usageCommon(w io.Writer, line int) {
	outputPara(w, line, 0, usageCommonPara)
}

// usageDynamicCSR outputs a partial usage message describing how a CSR may be
// dynamically generated.
func usageDynamicCSR(w io.Writer, line int) {
	outputPara(w, line, 0, usageDynamicCSRPara)
}

// usageCopyCSR outputs a partial usage message describing how a CSR may be
// automatically created from a TLS client certificate.
func usageCopyCSR(w io.Writer, line int) {
	outputPara(w, line, 0, usageCopyCSRPara)
}
