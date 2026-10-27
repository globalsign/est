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

package est_test

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/globalsign/est"
)

var semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

// changelogRelease is one "# vX.Y.Z" section of CHANGELOG.md.
type changelogRelease struct {
	version string
	entries int
}

// parseChangelog returns the releases in CHANGELOG.md in file order. Every
// top-level heading must be a release version.
func parseChangelog(t *testing.T) []changelogRelease {
	t.Helper()
	data, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	var releases []changelogRelease
	for i, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "# "):
			v, ok := strings.CutPrefix(strings.TrimPrefix(line, "# "), "v")
			if !ok || !semverPattern.MatchString(v) {
				t.Fatalf("CHANGELOG.md:%d: heading %q is not a release version like \"# v1.2.3\"", i+1, line)
			}
			releases = append(releases, changelogRelease{version: v})
		case strings.HasPrefix(line, "- ") && len(releases) > 0:
			releases[len(releases)-1].entries++
		}
	}
	return releases
}

func semverParts(v string) [3]int {
	var parts [3]int
	for i, s := range strings.Split(v, ".") {
		parts[i], _ = strconv.Atoi(s)
	}
	return parts
}

func TestVersionIsSemver(t *testing.T) {
	if !semverPattern.MatchString(est.Version()) {
		t.Fatalf("VERSION.txt %q is not MAJOR.MINOR.PATCH", est.Version())
	}
}

func TestChangelogMatchesVersion(t *testing.T) {
	releases := parseChangelog(t)
	if len(releases) == 0 {
		t.Fatal("CHANGELOG.md has no release headings")
	}
	if releases[0].version != est.Version() {
		t.Errorf("first CHANGELOG.md heading is v%s, but VERSION.txt is %s", releases[0].version, est.Version())
	}
	for i, r := range releases {
		if r.entries == 0 {
			t.Errorf("CHANGELOG.md release v%s has no entries", r.version)
		}
		if i > 0 {
			prev, cur := semverParts(releases[i-1].version), semverParts(r.version)
			if !(prev[0] > cur[0] || prev[0] == cur[0] && (prev[1] > cur[1] || prev[1] == cur[1] && prev[2] > cur[2])) {
				t.Errorf("CHANGELOG.md releases out of order: v%s is listed above v%s", releases[i-1].version, r.version)
			}
		}
	}
}
