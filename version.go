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
	_ "embed"
	"strings"
)

// versionFile is the contents of VERSION.txt, the single source of truth for
// the release number. Bump it with `./version.sh increment`, which also adds a
// CHANGELOG.md section for the release, then commit and tag it with
// `./version.sh commit`.
//
//go:embed VERSION.txt
var versionFile string

// Version returns the release number of this module, e.g. "1.0.7".
func Version() string {
	return strings.TrimSpace(versionFile)
}
