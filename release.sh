#! /bin/bash

# Release helper. A release is a git tag of the form vX.Y.Z, which is what Go
# modules use as their version, with a matching section in CHANGELOG.md.
#
#   1. 'release.sh prepare' creates a release/vX.Y.Z branch from the latest
#      origin/master and adds a CHANGELOG.md section listing every commit since
#      the previous release. Edit it, commit it, push the branch, and open a
#      pull request.
#   2. Once that is merged, 'release.sh tag vX.Y.Z <commit>' tags the commit it
#      was merged as and pushes the tag.

# Set much more strict behavior for failed commands and unexpanded variables.
set -eu

# Run this script inside of the directory it resides in. Quoted so that paths
# containing spaces work.
cd "$(dirname "$(realpath "$0")")"

# Allow's the script to refer to itself.
me=$(basename "$0")

# Releases are prepared from and tagged on this branch of this remote.
remote=origin
main_branch=master

function log() {
	echo "[$me] $@"
}

function fatal() {
	log "$@" >&2
	exit 1
}

function usage() {
	echo "Usage: $me prepare"
	echo "       $me tag vX.Y.Z <full commit hash>"
	echo "       $me help"
}

# Matches a bare "X.Y.Z" version without leading zeros. Release tags are the
# same with a "v" prefix.
version_re='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'

function tag-exists() {
	git rev-parse -q --verify "refs/tags/$1" >/dev/null
}

# Prints the highest "vX.Y.Z" tag reachable from the given commit, or nothing
# if there isn't one.
function latest-tag() {
	git tag --merged "$1" --list 'v*' --sort=-v:refname \
		| grep -E "^v$version_re\$" \
		| head -n 1
}

# Succeeds if version $1 is greater than version $2.
function version-gt() {
	local a=( ${1//./ } )
	local b=( ${2//./ } )
	local i
	for i in 0 1 2; do
		(( a[i] > b[i] )) && return 0
		(( a[i] < b[i] )) && return 1
	done
	return 1
}

# Prints the "- " entries under the "# vX.Y.Z" heading for the given version,
# reading the changelog from stdin.
function changelog-entries() {
	awk -v heading="# v$1" '
		$0 == heading { in_section = 1; next }
		/^# /         { in_section = 0 }
		in_section && /^- *[^ ]/'
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

function require-clean-tree() {
	if [[ -n "$(git status --porcelain)" ]]; then
		git status --short >&2
		fatal "There are staged, unstaged, or untracked changes. Please stash or commit them first."
	fi
}

function prepare-release() {
	if (( $# != 0 )); then
		usage >&2
		exit 1
	fi

	# The release branch is switched to, so it must not carry anything along.
	require-clean-tree

	log "Fetching $remote..."
	git fetch --quiet --tags "$remote"
	local base="$remote/$main_branch"

	local old_tag=$(latest-tag "$base")
	if [[ -z "$old_tag" ]]; then
		fatal "There is no vX.Y.Z release tag reachable from $base."
	fi
	local old_version="${old_tag#v}"
	local a=( ${old_version//./ } )
	local major=${a[0]}
	local minor=${a[1]}
	local patch=${a[2]}

	# Merge commits are skipped to match add-changelog-section, which would
	# otherwise write a section with no entries.
	if [[ "$(git rev-list --no-merges --count "$old_tag..$base")" == 0 ]]; then
		fatal "There are no commits on $base since $old_tag, so there is nothing to release."
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
	local tag="v$version"
	local branch="release/$tag"

	if tag-exists "$tag"; then
		fatal "$tag already exists."
	fi
	if git show "$base:CHANGELOG.md" | grep -qxF "# $tag"; then
		fatal "CHANGELOG.md on $base already has a '# $tag' section. Run '$me tag $tag <commit>' to tag it."
	fi
	if git rev-parse -q --verify "refs/heads/$branch" >/dev/null; then
		fatal "Branch $branch already exists."
	fi

	git switch --quiet --no-track -c "$branch" "$base"
	add-changelog-section "$version" "$old_tag"

	local count=$(changelog-entries "$version" < CHANGELOG.md | wc -l)
	log "Switched to $branch and added '# $tag' to CHANGELOG.md with $count commit(s) since $old_tag."
	log "Edit CHANGELOG.md as needed, then commit it, push the branch, and open a pull request:"
	log "  git commit -am 'Add $tag to CHANGELOG.md' && git push -u $remote $branch"
	log "Once it is merged, run '$me tag $tag <commit>' with the hash of the commit it was merged as."
}

# Tags the given commit, which must be on origin/master and have a CHANGELOG.md
# whose first section is for the given version, and pushes the tag. Taking the
# commit hash, rather than tagging the tip of origin/master, means anything
# merged after the release pull request isn't swept into the release.
function tag-release() {
	if (( $# != 2 )); then
		usage >&2
		exit 1
	fi
	local tag="$1"
	local commit="$2"

	if [[ ! "$tag" =~ ^v$version_re$ ]]; then
		fatal "'$tag' is not a release tag of the form vX.Y.Z."
	fi
	local version="${tag#v}"

	local hash_len=40
	if [[ "$(git rev-parse --show-object-format)" == sha256 ]]; then
		hash_len=64
	fi
	if [[ ! "$commit" =~ ^[0-9a-f]{$hash_len}$ ]]; then
		fatal "'$commit' is not a full commit hash. Pass all $hash_len characters, as shown by 'git log'."
	fi

	log "Fetching $remote..."
	git fetch --quiet --tags "$remote"
	local base="$remote/$main_branch"

	if tag-exists "$tag"; then
		fatal "$tag already exists."
	fi
	if ! git rev-parse -q --verify "$commit^{commit}" >/dev/null; then
		fatal "$commit is not a commit in this repository."
	fi
	if ! git merge-base --is-ancestor "$commit" "$base"; then
		fatal "$commit is not on $base. Pass the commit the release pull request was merged as."
	fi

	local old_tag=$(latest-tag "$commit")
	if [[ -n "$old_tag" ]] && ! version-gt "$version" "${old_tag#v}"; then
		fatal "$version is not greater than the previous release, $old_tag."
	fi

	local changelog
	if ! changelog=$(git show "$commit:CHANGELOG.md" 2>/dev/null); then
		fatal "There is no CHANGELOG.md at $commit."
	fi
	local first_heading=$(grep -m 1 '^# ' <<<"$changelog" || true)
	if [[ "$first_heading" != "# $tag" ]]; then
		fatal "The first heading in CHANGELOG.md at $commit is '$first_heading', expected '# $tag'."
	fi
	if [[ -z "$(changelog-entries "$version" <<<"$changelog")" ]]; then
		fatal "CHANGELOG.md at $commit has no '- ' entries under '# $tag'."
	fi

	git log -1 --format='Commit:  %H%nSubject: %s%nDate:    %cd' "$commit"
	echo "Previous release: ${old_tag:-none}"
	read -p "Create $tag at this commit and push it to $remote [y/N]? " answer
	if [[ "$answer" != [Yy] ]]; then
		fatal "Aborted. Nothing was tagged."
	fi

	# Annotated, so 'git describe' uses it. Signed too if tag.gpgSign is set.
	git tag -a -m "$tag" "$tag" "$commit"
	if ! git push "$remote" "refs/tags/$tag"; then
		git tag -d "$tag" >/dev/null
		fatal "Failed to push $tag, so the local tag was deleted. Fix the problem and run this again."
	fi
	log "Pushed $tag."
}

function main() {
	local subcommand=${1-}

	case $subcommand in
		prepare)
			prepare-release "${@:2}"
			;;
		tag)
			tag-release "${@:2}"
			;;
		-h|--help|help)
			usage
			;;
		*)
			log "'$subcommand' is not a valid subcommand."
			usage >&2
			exit 1
			;;
	esac
}

main "$@"
