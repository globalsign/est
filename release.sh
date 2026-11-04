#!/usr/bin/env bash

# release.sh - checks that the checked-out commit is ready to be released, then
# tags it.
#
# A release is an annotated git tag of the form vX.Y.Z on the checked-out
# commit, which must already be in the history of master on GitHub. Go modules
# use the tag as the version, and the binaries and library report the version
# the Go toolchain records from it, so nothing in the source tree has to be
# bumped. This script checks that the working tree is clean, CHANGELOG.md has a
# section for the version, and a clean export of the commit builds and passes
# its tests, and then, with --apply, creates the tag locally. Without --apply
# it is a dry run that creates nothing. Pushing the tag is left to you so that
# you can inspect it first.
#
#   ./release.sh vX.Y.Z           run the checks only (a dry run)
#   ./release.sh --apply vX.Y.Z   run the checks, then tag HEAD as vX.Y.Z
#
# See RELEASING.md for the full procedure.

set -euo pipefail

# Releases are tagged on commits that are already in the history of this branch
# on this remote.
remote=origin
branch=master

changelog=CHANGELOG.md

me=$(basename "$0")

# Matches a bare "X.Y.Z" version without leading zeros. Release tags are the
# same with a "v" prefix.
version_re='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'

# Set by the steps of main, in the order they run.
apply=false      # create the tag rather than only run the checks
tag=""           # the release tag, vX.Y.Z
version=""       # the bare version, X.Y.Z
major=""         # its major version, X
head=""          # the short hash of HEAD
prev=""          # the previous release tag reachable from HEAD, if any
module=""        # the module path declared in go.mod
release_date=""  # the date of the release's changelog section
section=""       # the body of the release's changelog section
entries=0        # the number of entries in it
export_dir=""    # a clean export of HEAD, where the build and tests run

usage() {
	cat <<EOF
Usage: $me [--apply] vX.Y.Z

Checks that the checked-out commit is ready to be released as vX.Y.Z. With
--apply, also creates an annotated tag vX.Y.Z on it. Without it, this is a dry
run that creates nothing.
EOF
}

ok() {
	echo "ok    $*"
}

warn() {
	echo "warn  $*" >&2
}

fail() {
	echo "$me: error: $*" >&2
	exit 1
}

# Escapes the dots in version $1 for use in a regular expression.
re_escape() {
	printf '%s' "${1//./\\.}"
}

# Succeeds if a tag named $1 exists.
tag_exists() {
	git rev-parse -q --verify "refs/tags/$1" >/dev/null
}

# Prints the highest vX.Y.Z tag reachable from commit $1, or nothing if there
# isn't one.
latest_tag() {
	git tag --merged "$1" --list 'v*' --sort=-v:refname \
		| { grep -E "^v$version_re\$" || true; } \
		| awk 'NR == 1'
}

# Succeeds if version $1 is greater than version $2, both bare X.Y.Z.
version_gt() {
	local a b i
	IFS=. read -r -a a <<<"$1"
	IFS=. read -r -a b <<<"$2"
	for i in 0 1 2; do
		(( a[i] > b[i] )) && return 0
		(( a[i] < b[i] )) && return 1
	done
	return 1
}

# Prints the module path declared in go.mod, or nothing if there isn't one.
module_path() {
	awk '$1 == "module" { gsub(/"/, "", $2); print $2; exit }' go.mod
}

# Succeeds if module path $1 can be released with major version $2. Go's
# semantic import versioning requires a "/vN" suffix matching the major version
# for v2 and above, and no suffix for v0 and v1. Otherwise the tag is published
# but 'go get' refuses to install it.
module_path_matches() {
	if (( $2 >= 2 )); then
		[[ "$1" == */v$2 ]]
	else
		[[ ! "$1" =~ /v[0-9]+$ ]]
	fi
}

# Prints the body of the "## [X.Y.Z]" section of the changelog for version $1,
# without the heading or surrounding blank lines.
changelog_section() {
	awk -v prefix="## [$1]" '
		/^## /         { in_section = (substr($0, 1, length(prefix)) == prefix); next }
		/^\[[^]]+\]: / { in_section = 0 }
		in_section {
			if (n == 0 && $0 ~ /^[[:space:]]*$/) next
			lines[n++] = $0
		}
		END {
			while (n > 0 && lines[n-1] ~ /^[[:space:]]*$/) n--
			for (i = 0; i < n; i++) print lines[i]
		}
	' "$changelog"
}

# Parses the command line. Sets $apply, $tag, $version and $major.
parse_args() {
	while (( $# > 0 )); do
		case "$1" in
			--apply)
				apply=true
				;;
			-h|--help)
				usage
				exit 0
				;;
			-*)
				usage >&2
				fail "unknown option '$1'"
				;;
			*)
				if [[ -n "$tag" ]]; then
					usage >&2
					fail "unexpected argument '$1'"
				fi
				tag="$1"
				;;
		esac
		shift
	done
	if [[ -z "$tag" ]]; then
		usage >&2
		exit 2
	fi
	if [[ ! "$tag" =~ ^v$version_re$ ]]; then
		fail "'$tag' is not a release tag of the form vX.Y.Z (no leading zeros)"
	fi
	version="${tag#v}"
	major="${version%%.*}"
}

# Moves to the top of the repository, where go.mod and the changelog are.
enter_repository() {
	command -v go >/dev/null || fail "go is not installed"
	local top
	top=$(git rev-parse --show-toplevel) || fail "not inside a git repository"
	cd "$top"
}

# The commit must be exactly what gets tagged. Untracked files count too: go
# build and go test would compile them even though they aren't in the commit.
check_working_tree() {
	if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
		git status --short --untracked-files=all >&2
		fail "the working tree has staged, unstaged or untracked changes; commit, stash or remove them first"
	fi
	ok "working tree has no staged, unstaged or untracked changes"
}

# The checks against the remote need its current tags and branches.
fetch_remote() {
	if git fetch --quiet --tags "$remote"; then
		ok "fetched $remote"
	else
		warn "could not fetch $remote; checking against its last fetched state"
	fi
}

check_tag_unused() {
	if tag_exists "$tag"; then
		fail "tag $tag already exists"
	fi
}

# The commit must already be in the history of the release branch on the
# remote, so that the tag never points at something that isn't on GitHub. HEAD
# itself may be detached or on any local branch. Sets $head.
check_head_in_branch() {
	if ! git rev-parse -q --verify "refs/remotes/$remote/$branch" >/dev/null; then
		fail "there is no $remote/$branch; run 'git fetch $remote' first"
	fi
	head=$(git rev-parse --short HEAD)
	if ! git merge-base --is-ancestor HEAD "$remote/$branch"; then
		fail "HEAD not in history of $remote/$branch"
	fi
	ok "HEAD is $(git log -1 --format='%h (%s)'), in the history of $remote/$branch"
}

# The version must come after the previous release reachable from HEAD, if
# there is one. Sets $prev.
check_version_order() {
	prev=$(latest_tag HEAD)
	if [[ -n "$prev" ]]; then
		if ! version_gt "$version" "${prev#v}"; then
			fail "$tag is not greater than the previous release reachable from HEAD, $prev"
		fi
		ok "$tag is greater than the previous release, $prev"
	else
		ok "$tag is the first release"
	fi
}

# Sets $module.
check_module_path() {
	module=$(module_path)
	[[ -n "$module" ]] || fail "go.mod has no module directive"
	if ! module_path_matches "$module" "$major"; then
		if (( major >= 2 )); then
			fail "Go requires the module path for $tag to end in /v$major, but go.mod declares '$module'; change the module path and imports first"
		else
			fail "Go requires the module path for $tag to have no /vN suffix, but go.mod declares '$module'"
		fi
	fi
	ok "module path $module matches major version $major"
}

# The changelog's first section must be for this release. "Unreleased" is only
# for the main branch between releases.
check_changelog() {
	[[ -f "$changelog" ]] || fail "$changelog does not exist"
	check_changelog_closed
	check_changelog_heading
	check_changelog_entries
	check_changelog_link
	check_changelog_history
	local entry_word=entries
	(( entries == 1 )) && entry_word=entry
	ok "$changelog is ready for $tag ($entries $entry_word, dated $release_date)"
}

# Nothing may be left under Unreleased.
check_changelog_closed() {
	if grep -qiE '^##+ +\[?unreleased\]?' "$changelog"; then
		fail "$changelog still has an Unreleased section; rename it to '## [$version] - $(date +%F)'"
	fi
	if grep -qiE '^\[unreleased\]:' "$changelog"; then
		fail "$changelog still has an [Unreleased] link; replace it with one for [$version]"
	fi
}

# The first section heading must be "## [X.Y.Z] - YYYY-MM-DD". Sets
# $release_date.
check_changelog_heading() {
	local heading heading_re
	heading=$(grep -m 1 -E '^## ' "$changelog" || true)
	heading_re="^## \[$(re_escape "$version")\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$"
	if [[ ! "$heading" =~ $heading_re ]]; then
		fail "the first section of $changelog is '${heading:-missing}', expected '## [$version] - YYYY-MM-DD'"
	fi
	release_date="${heading##* - }"
	if [[ "$release_date" != "$(date +%F)" ]]; then
		warn "$changelog dates $tag $release_date, but today is $(date +%F)"
	fi
}

# The section must list at least one change. Sets $section and $entries.
check_changelog_entries() {
	section=$(changelog_section "$version")
	entries=$(grep -cE '^[[:space:]]*[-*][[:space:]]+[^[:space:]]' <<<"$section" || true)
	if (( entries == 0 )); then
		fail "the [$version] section of $changelog has no entries"
	fi
}

# The section's link must compare the release with the previous one.
check_changelog_link() {
	local link expected
	if [[ -n "$prev" ]]; then
		expected="/compare/$prev...$tag"
	else
		expected="/releases/tag/$tag"
	fi
	link=$(grep -m 1 -E "^\[$(re_escape "$version")\]: " "$changelog" || true)
	if [[ -z "$link" ]]; then
		fail "$changelog has no link for [$version]; add '[$version]: https://$module$expected'"
	fi
	if [[ "$link" != *"$expected" ]]; then
		fail "the [$version] link in $changelog is '$link', expected it to end in '$expected'"
	fi
}

# Every earlier release reachable from HEAD must have a section too.
check_changelog_history() {
	local t missing=""
	for t in $(git tag --merged HEAD --list 'v*' | { grep -E "^v$version_re\$" || true; }); do
		if ! grep -qE "^## \[$(re_escape "${t#v}")\]" "$changelog"; then
			missing="$missing $t"
		fi
	done
	if [[ -n "$missing" ]]; then
		fail "$changelog has no section for earlier release(s) reachable from HEAD:$missing"
	fi
}

# The build and tests run in a clean export of HEAD, so that nothing in the
# working tree that isn't in the commit, such as a gitignored file, can affect
# them. Sets $export_dir, which is removed when the script exits.
export_head() {
	export_dir=$(mktemp -d)
	trap 'rm -rf "$export_dir"' EXIT
	git archive HEAD | tar -x -C "$export_dir" || fail "could not export HEAD"
	ok "exported HEAD to a clean directory for the build and tests"
}

check_build() {
	echo "--- go build ./...   (in the export)"
	(cd "$export_dir" && go build ./...) || fail "the build failed"
	ok "build succeeded"
}

check_tests() {
	echo "--- go test -count=1 ./...   (in the export)"
	if [[ -n "${GLOBALSIGN_EST_SKIP:-}" ]]; then
		warn "GLOBALSIGN_EST_SKIP=$GLOBALSIGN_EST_SKIP, so some tests are skipped"
	fi
	# -count=1 runs the tests even if a cached result exists.
	(cd "$export_dir" && go test -count=1 ./...) || fail "the tests failed"
	ok "tests passed"
}

# The tag message is the changelog section. The whitespace cleanup keeps its
# "### Added" etc. headings, which the default cleanup would strip as comments.
# The tag is also signed if tag.gpgSign is set.
create_tag() {
	local msg
	msg=$(mktemp)
	printf '%s\n\n%s\n' "$tag" "$section" >"$msg"
	if ! git tag -a --cleanup=whitespace -F "$msg" "$tag"; then
		rm -f "$msg"
		fail "failed to create tag $tag"
	fi
	rm -f "$msg"
}

report_dry_run() {
	echo
	echo "All checks passed. HEAD ($head) is ready to be tagged as $tag."
	echo "Nothing was created. Run '$me --apply $tag' to create the tag."
}

report_tag() {
	echo
	echo "Created tag $tag on $(git log -1 --format='%h (%s)')."
	echo
	echo "  Inspect it:  git show $tag"
	echo "  Push it:     git push $remote $tag"
	echo "  Remove it:   git tag -d $tag    (only before pushing; a pushed tag is permanent)"
	echo
	echo "After pushing, publish the GitHub release as described in RELEASING.md."
}

main() {
	parse_args "$@"
	enter_repository
	check_working_tree
	fetch_remote
	check_tag_unused
	check_head_in_branch
	check_version_order
	check_module_path
	check_changelog
	export_head
	check_build
	check_tests
	if ! $apply; then
		report_dry_run
		return
	fi
	create_tag
	report_tag
}

main "$@"
