#! /bin/bash

# Adds a section for the next release to the top of CHANGELOG.md, listing the
# subject of every commit since the latest release tag. Release versions come
# from git tags of the form vX.Y.Z, which is what Go modules use, so there is
# no version file to keep in sync. Edit the new section as needed, commit it,
# then tag the release.

# Set much more strict behavior for failed commands and unexpanded variables.
set -eu

# Run this script inside of the directory it resides in. Quoted so that paths
# containing spaces work.
cd "$(dirname "$(realpath "$0")")"

# Allow's the script to refer to itself.
me=$(basename "$0")

function log() {
	echo "[$me] $@"
}

function fatal() {
	log "$@" >&2
	exit 1
}

function usage() {
	echo "Usage: $me [help]"
}

# Matches a bare "X.Y.Z" version without leading zeros. Release tags are the
# same with a "v" prefix.
version_re='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'

# Prints the highest "vX.Y.Z" tag reachable from HEAD, or nothing if there
# isn't one.
function latest-tag() {
	git tag --merged HEAD --list 'v*' --sort=-v:refname \
		| grep -E "^v$version_re\$" \
		| head -n 1
}

# Prints the "- " entries under the "# vX.Y.Z" heading for the given version.
function changelog-entries() {
	awk -v heading="# v$1" '
		$0 == heading { in_section = 1; next }
		/^# /         { in_section = 0 }
		in_section && /^- *[^ ]/' CHANGELOG.md
}

# Inserts a "# vX.Y.Z" heading at the top of CHANGELOG.md, listing the subject
# of every commit since the previous release tag (excluding merge commits).
function add-changelog-section() {
	local version="$1"
	local since="$2"
	local tmp=$(mktemp)
	trap "rm -f $(printf %q "$tmp")" EXIT

	{
		printf '# v%s\n\n' "$version"
		git log --no-merges --format='- %s' "$since..HEAD"
		printf '\n'
		cat CHANGELOG.md
	} > "$tmp"
	# Copy rather than mv, so CHANGELOG.md keeps its permissions instead of
	# getting mktemp's 0600.
	cat "$tmp" > CHANGELOG.md
}

function main() {
	case ${1-} in
		"")
			;;
		-h|--help|help)
			usage
			return
			;;
		*)
			log "$1 is not a valid argument."
			usage
			exit 1
			;;
	esac

	local old_tag=$(latest-tag)
	if [[ -z "$old_tag" ]]; then
		fatal "There is no vX.Y.Z release tag reachable from HEAD."
	fi
	local old_version="${old_tag#v}"
	local a=( ${old_version//./ } )
	local major=${a[0]}
	local minor=${a[1]}
	local patch=${a[2]}

	# Merge commits are skipped to match add-changelog-section, which would
	# otherwise write a section with no entries.
	if [[ "$(git rev-list --no-merges --count "$old_tag..HEAD")" == 0 ]]; then
		fatal "There are no commits since $old_tag, so there is nothing to release."
	fi

	# Prevents mixing the new section into uncommitted edits.
	if [[ -n "$(git status --porcelain -- CHANGELOG.md)" ]]; then
		fatal "CHANGELOG.md has uncommitted changes. Please stash or commit them first."
	fi

	while true; do
		read -p "Increment version from $old_version [(m)ajor/m(i)nor/(p)atch]? " part
		case "$part" in
			[Mm])
				major=$((major + 1))
				minor=0
				patch=0
				break
			;;
			[Ii])
				minor=$((minor + 1))
				patch=0
				break
			;;
			[Pp])
				patch=$((patch + 1))
				break
			;;
			*)
				log "Error: invalid option '$part'. Enter M for major, I for minor, or P for patch." >&2
			;;
		esac
	done

	local version="$major.$minor.$patch"

	# Running the script twice before tagging would otherwise add a second
	# section for the same release.
	if grep -qxF "# v$version" CHANGELOG.md; then
		fatal "CHANGELOG.md already has a '# v$version' section. Edit it, or tag v$version first."
	fi

	add-changelog-section "$version" "$old_tag"

	local count=$(changelog-entries "$version" | wc -l)
	log "Added '# v$version' to CHANGELOG.md with $count commit(s) since $old_tag."
	log "Edit CHANGELOG.md as needed and commit it. Once that is merged, tag the release v$version."
}

main "$@"
