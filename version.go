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

import "runtime/debug"

// modulePath is the import path of this module, used to find its version in
// the build information the Go toolchain records in a binary.
const modulePath = "github.com/globalsign/est"

// estVersion is the version of this module that the running binary was built
// with, e.g. "v1.0.7". It is reported in the client's User-Agent header and in
// the server's Server header.
var estVersion = moduleVersion()

// moduleVersion returns the version of this module recorded in the build
// information, which the Go toolchain takes from the module's git tag when a
// binary is built or installed. It returns "(devel)" when no version was
// recorded, such as in tests, when the module is replaced by a local
// directory, or when a checkout is built with a Go toolchain older than 1.24.
func moduleVersion() string {
	const unknown = "(devel)"

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return unknown
	}

	// This module is the main module of the estclient and estserver binaries,
	// and a dependency of anything else that uses the library.
	mod := &info.Main
	if mod.Path != modulePath {
		mod = nil
		for _, dep := range info.Deps {
			if dep.Path == modulePath {
				mod = dep
				break
			}
		}
	}
	if mod != nil && mod.Replace != nil {
		mod = mod.Replace
	}
	if mod == nil || mod.Version == "" {
		return unknown
	}

	return mod.Version
}
