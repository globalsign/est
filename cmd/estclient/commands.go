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
	"sort"
	"time"
)

// command represents an application command.
type command struct {
	// name is the name of the command, used to select it at the command line.
	name string

	// shortDesc is the short description of the command, used in a list of
	// commands.
	shortDesc string

	// longDesc is a longer description of the command, used in a full usage
	// message.
	longDesc string

	// flags is a list of flag names which this command implements.
	flags []string

	// extraFlags is a list of additional flag names which this command
	// implements, but which should not be included in the basic list of flags
	// in the usage message. This is useful for uncommonly-used flags which
	// can be described on demand, or for groups of flags which are documented
	// elsewhere.
	extraFlags [][]string

	// usageExtras is a list of additional functions to call after a usage
	// method is called, to display customized additional information.
	usageExtras []func(io.Writer, int)

	// cmdFunc is the function implementing the command itself.
	cmdFunc func(io.Writer, *flag.FlagSet) error
}

// commandSet represents a set of application commands.
type commandSet map[string]command

// Command name constants.
const (
	cacertsCmd      = "cacerts"
	csrattrsCmd     = "csrattrs"
	csrCmd          = "csr"
	enrollCmd       = "enroll"
	helpCmd         = "help"
	reenrollCmd     = "reenroll"
	sampleconfigCmd = "sampleconfig"
	serverkeygenCmd = "serverkeygen"
	tpmenrollCmd    = "tpmenroll"
	versionCmd      = "version"
)

var commands commandSet

func init() {
	// Initialize within the init() function to avoid circular initialization
	// issues, particularly with the command or usage functions which may
	// themselves refer to this set of commands.
	commands = commandSet{
		cacertsCmd: {
			name:      cacertsCmd,
			shortDesc: "retrieve current CA certificates",
			longDesc:  cacertsDesc,
			cmdFunc:   cacerts,
			flags: []string{
				apsFlag,
				certsFlag,
				configFlag,
				explicitAnchorFlag,
				implicitAnchorFlag,
				helpFlag,
				headersFlag,
				hostHeaderFlag,
				insecureFlag,
				keyFlag,
				outFlag,
				passwordFlag,
				rootOutFlag,
				separateOutFlag,
				separatorFlag,
				serverFlag,
				usernameFlag,
				timeoutFlag,
			},
			usageExtras: []func(io.Writer, int){
				usageCommon,
			},
		},
		csrattrsCmd: {
			name:      csrattrsCmd,
			shortDesc: "request a list of CA-desired CSR attributes",
			longDesc:  csrattrsDesc,
			cmdFunc:   csrattrs,
			flags: []string{
				apsFlag,
				certsFlag,
				configFlag,
				explicitAnchorFlag,
				implicitAnchorFlag,
				helpFlag,
				headersFlag,
				hostHeaderFlag,
				insecureFlag,
				keyFlag,
				passwordFlag,
				separatorFlag,
				serverFlag,
				usernameFlag,
				timeoutFlag,
			},
			usageExtras: []func(io.Writer, int){
				usageCommon,
			},
		},
		csrCmd: {
			name:      csrCmd,
			shortDesc: "generate a PKCS#10 certificate signing request",
			longDesc:  csrDesc,
			cmdFunc:   csr,
			flags: []string{
				configFlag,
				helpFlag,
				keyFlag,
				outFlag,
				separatorFlag,
			},
			extraFlags: [][]string{
				csrFlags,
			},
			usageExtras: []func(io.Writer, int){
				usageCommon,
				usageCSRFlags,
			},
		},
		enrollCmd: {
			name:      enrollCmd,
			shortDesc: "request a new certificate",
			longDesc:  enrollDesc,
			cmdFunc:   enroll,
			flags: []string{
				apsFlag,
				certsFlag,
				configFlag,
				csrFlag,
				explicitAnchorFlag,
				implicitAnchorFlag,
				helpFlag,
				headersFlag,
				hostHeaderFlag,
				insecureFlag,
				keyFlag,
				outFlag,
				passwordFlag,
				separatorFlag,
				serverFlag,
				usernameFlag,
				timeoutFlag,
			},
			extraFlags: [][]string{
				csrFlags,
			},
			usageExtras: []func(io.Writer, int){
				usageDynamicCSR,
				usageCommon,
			},
		},
		helpCmd: {
			name:      helpCmd,
			cmdFunc:   usageMain,
			shortDesc: "show this usage information",
			flags: []string{
				commonFlag,
			},
		},
		reenrollCmd: {
			name:      reenrollCmd,
			shortDesc: "request renewal/rekey of an existing certificate",
			longDesc:  reenrollDesc,
			cmdFunc:   reenroll,
			flags: []string{
				apsFlag,
				certsFlag,
				configFlag,
				csrFlag,
				explicitAnchorFlag,
				implicitAnchorFlag,
				helpFlag,
				headersFlag,
				hostHeaderFlag,
				insecureFlag,
				keyFlag,
				outFlag,
				passwordFlag,
				separatorFlag,
				serverFlag,
				usernameFlag,
				timeoutFlag,
			},
			usageExtras: []func(io.Writer, int){
				usageCopyCSR,
				usageCommon,
			},
		},
		sampleconfigCmd: {
			name:      sampleconfigCmd,
			shortDesc: "output a sample configuration file",
			longDesc:  sampleconfigDesc,
			cmdFunc:   sampleconfig,
			flags: []string{
				helpFlag,
				hsmFlag,
				outFlag,
				tpmFlag,
			},
		},
		serverkeygenCmd: {
			name:      serverkeygenCmd,
			shortDesc: "request a private key and associated certificate",
			longDesc:  serverkeygenDesc,
			cmdFunc:   serverkeygen,
			flags: []string{
				apsFlag,
				certsFlag,
				configFlag,
				csrFlag,
				explicitAnchorFlag,
				implicitAnchorFlag,
				helpFlag,
				headersFlag,
				hostHeaderFlag,
				insecureFlag,
				keyFlag,
				keyOutFlag,
				outFlag,
				passwordFlag,
				separatorFlag,
				serverFlag,
				usernameFlag,
				timeoutFlag,
			},
			extraFlags: [][]string{
				csrFlags,
			},
			usageExtras: []func(io.Writer, int){
				usageDynamicCSR,
				usageCommon,
			},
		},
		tpmenrollCmd: {
			name:      tpmenrollCmd,
			shortDesc: "request a new TPM-protected certificate",
			longDesc:  tpmenrollDesc,
			cmdFunc:   tpmenroll,
			flags: []string{
				apsFlag,
				certsFlag,
				configFlag,
				csrFlag,
				ekcertsFlag,
				explicitAnchorFlag,
				implicitAnchorFlag,
				helpFlag,
				headersFlag,
				hostHeaderFlag,
				insecureFlag,
				keyFlag,
				outFlag,
				passwordFlag,
				separatorFlag,
				serverFlag,
				usernameFlag,
				timeoutFlag,
			},
			extraFlags: [][]string{
				csrFlags,
			},
			usageExtras: []func(io.Writer, int){
				usageDynamicCSR,
				usageCommon,
			},
		},
		versionCmd: {
			name:      versionCmd,
			cmdFunc:   version,
			shortDesc: "show version information",
		},
	}
}

// Names returns a sorted list of command names.
func (set commandSet) Names() []string {
	var names []string
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

// Usage outputs usage information for a command.
func (cmd command) Usage(w io.Writer, line int) error {
	outputPara(w, line, 0, fmt.Sprintf("usage: %s %s [options]", appName, cmd.name))

	if cmd.longDesc != "" {
		outputPara(w, line, 0, fmt.Sprintf("The %s command %s", cmd.name, cmd.longDesc))
	}

	if len(cmd.flags) > 0 {
		fmt.Fprintln(w, "Options:")
		listOpts(w, cmd.flags)
		fmt.Fprintln(w)
	}

	for _, extra := range cmd.usageExtras {
		extra(w, line)
	}

	return nil
}

// FlagSet returns a flag set for the command, ready for parsing.
func (cmd command) FlagSet(w io.Writer, line int) *flag.FlagSet {
	set := flag.NewFlagSet(cmd.name, flag.ExitOnError)
	set.Usage = func() {
		cmd.Usage(w, line)
	}

	flags := cmd.flags
	for _, extras := range cmd.extraFlags {
		flags = append(flags, extras...)
	}

	for _, flag := range flags {
		def, ok := optDefs[flag]
		if !ok {
			panic(fmt.Sprintf("flag not defined: %s", flag))
		}

		switch d := def.defaultValue.(type) {
		case bool:
			set.Bool(flag, d, "")

		case string:
			set.String(flag, d, "")

		case time.Duration:
			set.Duration(flag, d, "")

		default:
			panic(fmt.Sprintf("flag with no default: %s", flag))
		}
	}

	return set
}
