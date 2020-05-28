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
	"fmt"
	"io"
	"strings"
)

// Global constants.
const (
	usageIndent     = 4
	usageLineLength = 80
)

// Long command descriptions.
const (
	cacertsDesc = `requests a copy of the current CA certificates from an ` +
		`EST server. See RFC7030 section 4.1.`
	csrattrsDesc = `requests a list of CA-desired CSR attributes from an EST ` +
		`server. See RFC7030 section 4.5.`
	csrDesc    = `generates a PKCS#10 certificate signing request.`
	enrollDesc = `requests a new certificate from an EST server. See RFC7030 ` +
		`section 4.2.`
	reenrollDesc = `requests renewal/rekey of an existing certificate from an ` +
		`EST server. See RFC7030 section 4.2.`
	sampleconfigDesc = `outputs a sample configuration file.`
	serverkeygenDesc = `requests a private key and an associated certificate ` +
		`from an EST server. See RFC7030 section 4.4.`
	tpmenrollDesc = `requests a new certificate from an EST server using the ` +
		`Trusted Platform Module (TPM) privacy preserving protocol for ` +
		`distributing credentials for keys on a TPM. See See Trusted ` +
		`Platform Module Library specification part 1, section 23.`
)

// Usage information texts.
var (
	usageShort = fmt.Sprintf("usage: %s <command> [options]\n", appName)

	usageCommandPara = fmt.Sprintf(`Use "%s <command> -help" for more information `+
		`about a command.`,
		appName)

	usageCommonPara = fmt.Sprintf(`Use "%s help -common" for more information `+
		`about common command line options, and about using a configuration `+
		`file.`,
		appName)

	usageMainPara = fmt.Sprintf("%s is a client for the Enrollment over Secure "+
		"Transport (EST) certificate enrollment protocol. See RFC7030.",
		appName)

	usageConfigIntroPara = fmt.Sprintf("Most options can also be specified in a "+
		"configuration file. Use \"%s %s\" to generate a sample configuration "+
		"file. Options specified at the console override options specified in "+
		"the configuration file.",
		appName, sampleconfigCmd)

	usageConfigLocationPara = fmt.Sprintf("If the configuration file is given "+
		"as a relative path, that path will be checked, in order, relative to "+
		"(1) the current working directory; (2) the directory specified by the "+
		"%s environment variable, if set; and (3) the user's home directory.",
		configDirectoryVar)

	usageConfigKeysPara = fmt.Sprintf("Hardware-resident private keys, including HSM " +
		"and TPM keys, can only be specified in a configuration file.")

	usageAnchorsIntroPara = fmt.Sprintf("RFC7030 refers to explicit and implicit " +
		"trust anchor (TA) databases which contain CA certificates used to authenticate " +
		"certificates, including the EST server certificate. The explicit anchor " +
		"should contain CA certificates explicitly configured for use during EST " +
		"TLS authentication, while the implicit anchor can contain any CA " +
		"certificates available for use during TLS authentication, but which are " +
		"not explicitly configured for use with EST (for example, CA certificates " +
		"commonly bundled with web browsers to authenticate web servers.) An " +
		"implicit TA database can be disabled.")

	usageAnchorsFormatPara = fmt.Sprintf("Explicit and implicit TA databases "+
		"used by this client are files containing one or more PEM-encoded CA "+
		"certificates. They can be specified in a configuration file or with "+
		"the -%s and -%s options. If both are specified, the explicit anchor "+
		"will be used, and the implicit anchor will be disabled. If neither "+
		"are specified, the system CA certificate pool will be used, if one "+
		"is available.",
		explicitAnchorFlag, implicitAnchorFlag)

	usageAnchorsInsecurePara = fmt.Sprintf("The -%s option can be used to "+
		"disable verification of the EST server certificate. This can be "+
		"used to \"bootstrap\" the client by making an initial call to "+
		"the \"%s\" command, and using the returned certificates as "+
		"the explicit TA database. Disabling verification of the EST "+
		"server certificate is inherently insecure, and the certificates "+
		"MUST be manually verified by a human user using out-of-band "+
		"data such as a CA certificate \"fingerprint\". Note that the "+
		"EST server certificate need not necessarily be issued by the "+
		"EST CA, in which case this \"bootstrap\" operation will fail.",
		insecureFlag, cacertsCmd)

	usageAPSIntroPara = fmt.Sprintf("RFC7030 allows an EST server to "+
		"provide service for multiple CAs as indicated by an optional "+
		"additional path segment between the registered application "+
		"name and the operation path. The -%s option can be used to "+
		"specify an additional path segment.",
		apsFlag)

	usageCertsIntroPara = fmt.Sprintf("The -%s and -%s options can be "+
		"used to specify a TLS client certificate and associated "+
		"private key for authenticating the client with the TLS server. "+
		"A TLS client certificate is required when using the \"%s\" command.",
		certsFlag, keyFlag, reenrollCmd)

	usageCertsFormatPara = fmt.Sprintf("The -%s option should contain "+
		"the path to a file containing the TLS client certificate, and "+
		"any CA certificates required to enable to EST server to form "+
		"a complete certificate chain. Including the root CA certificate "+
		"is optional. If any CA certificates are included, the certificates "+
		"in the file should appear in order, with the client certificate "+
		"first, and the root CA certificate (if present) last. All "+
		"certificates must be PEM-encoded.",
		certsFlag)

	usageCertsKeyPara = fmt.Sprintf("The -%s option should contain "+
		"the path to a file containing a PEM-encoded private key. If the "+
		"PEM block is an encrypted PEM-block, you will be prompted to "+
		"enter a passphrase. Hardware resident private keys (such as "+
		"private keys resident on a hardware security module (HSM) or "+
		"on a Trusted Platform Module (TPM) device) can be used but "+
		"must be specified in the configuration file. The -%s option "+
		"will override any private key specified in the configuration "+
		"file.",
		keyFlag, keyFlag)

	usagePEMPara = fmt.Sprintf("The files referred to by -%s, -%s and -%s "+
		"should contain one or more PEM-encoded certificates. If more than "+
		"one certificate is present (for example, because an intermediate CA "+
		"certificate must be included in the chain presented to the EST "+
		"server) then the certificates should appear in order, with the "+
		"end-entity certificate first, and the root CA certificate (if "+
		"present) last.",
		certsFlag, explicitAnchorFlag, implicitAnchorFlag)

	usagePrivateKeyPara = fmt.Sprintf("The file referred to by -%s should "+
		"contain a PEM-encoded private key. If the file contains an encrypted "+
		"PEM block, you will be prompted for a passphrase at the console. "+
		"Hardware-resident private keys can only be specified in the "+
		"configuration file.",
		keyFlag)

	usageHeadersPara = fmt.Sprintf("Custom additional HTTP headers can be "+
		"included in the request to the EST server by specifying them with "+
		"the -%s option. If multiple headers are sent, they must be "+
		"separated by the -%s character (the default is \"%s\"), and a colon "+
		"must separate the header name from its value, for example:",
		headersFlag, separatorFlag, sepChar)

	usageHeadersExample = fmt.Sprintf("-%s=\"Bit-Size:2048%sCertificate-"+
		"Template:my-template\"",
		headersFlag, sepChar)

	usageHostHeaderPara = fmt.Sprintf("For testing purposes it can occasionally "+
		"be useful to override the HTTP Host header, which by default is "+
		"set the host component of the server URI. The -%s option may be used "+
		"for this purpose.",
		hostHeaderFlag)

	usageTimeoutPara = fmt.Sprintf("A request timeout can be specified using "+
		"the -%s option with any reasonable duration string, such as \"30s\" "+
		"or \"2m\".",
		timeoutFlag)

	usageCSRMultiPara = fmt.Sprintf("The -%s, -%s, -%s, -%s and -%s options "+
		"can accept multiple values separated by the -%s character.",
		organizationalUnitFlag, dnsNamesFlag, emailsFlag,
		ipsFlag, urisFlag, separatorFlag)

	usageDynamicCSRPara = fmt.Sprintf("If the -%s option is omitted, a "+
		"certificate signing request can be dynamically generated using "+
		"the same options documented for the \"%s\" command.",
		csrFlag, csrCmd)

	usageCopyCSRPara = fmt.Sprintf("If the -%s option is omitted, a "+
		"certificate signing request will be automatically generated by "+
		"copying the subject field and subject alternative name "+
		"extension from the TLS client certificate.",
		csrFlag)
)

// outputPara outputs a formatted paragraph indented by the specified number
// of spaces, and word-wrapped to the specified line length.
func outputPara(w io.Writer, line, indent int, s string) {
	lineLen := indent
	if indent > 0 {
		fmt.Fprint(w, strings.Repeat(" ", indent))
	}

	for _, word := range strings.Fields(s) {
		wordLen := len(word)
		spaceLen := 0
		if lineLen != indent {
			spaceLen = 1
		}

		if lineLen+spaceLen+wordLen > line {
			fmt.Fprintln(w)
			if indent > 0 {
				fmt.Fprint(w, strings.Repeat(" ", indent))
			}
			lineLen = indent
		} else if spaceLen != 0 {
			fmt.Fprint(w, " ")
		}

		fmt.Fprint(w, word)
		lineLen += wordLen + spaceLen
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w)
}
