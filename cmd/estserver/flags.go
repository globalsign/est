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
)

// Global constants.
const (
	appName       = "estserver"
	versionString = "1.0.0"
)

// Flag name constants.
const (
	configFlag       = "config"
	helpFlag         = "help"
	sampleConfigFlag = "sampleconfig"
	versionFlag      = "version"
)

// Flags.
var (
	fConfig       = flag.String(configFlag, "", "")
	fHelp         = flag.Bool(helpFlag, false, "")
	fSampleConfig = flag.Bool(sampleConfigFlag, false, "")
	fVersion      = flag.Bool(versionFlag, false, "")
)

// usage outputs usage information.
func usage() {
	fmt.Printf("usage: %s [options]\n", appName)
	fmt.Println()

	fmt.Printf("%s is a non-production Enrollment over Secure Transport (EST)\n", appName)
	fmt.Printf("certificate enrollment protocol server for testing and demonstration\n")
	fmt.Printf("purposes. See RFC7030.\n")
	fmt.Println()

	const fw = 16
	fmt.Println("Options:")
	fmt.Printf("    -%-*s path to configuration file\n", fw, configFlag+" <path>")
	fmt.Printf("    -%-*s show this usage information\n", fw, helpFlag)
	fmt.Printf("    -%-*s output a sample configuration file\n", fw, sampleConfigFlag)
	fmt.Printf("    -%-*s show version information\n", fw, versionFlag)
	fmt.Println()
}

// version outputs version information.
func version() {
	fmt.Printf("GlobalSign EST Server %s\n", versionString)
}
