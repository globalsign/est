#! /bin/bash

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

function tag-exists() {
	git rev-parse -q --verify "refs/tags/$1" >/dev/null
}

# Fails if there are untracked files, unstaged changes, or staged changes to
# anything except the files located in the paths provided as arguments.
function require-clean-tree() {
	local exclude=()
	local file
	for file in "$@"; do
		exclude+=( ":!$file" )
	done
	# ${exclude[@]+...} avoids an unbound variable error on bash 3 when empty.
	if [[ -n "$(git ls-files --others --exclude-standard)" ]] \
		|| ! git diff --quiet \
		|| ! git diff --cached --quiet -- . ${exclude[@]+"${exclude[@]}"}; then
		git status --short >&2
		local msg="There are staged, unstaged, or untracked changes. Please stash or commit them first."
		if (( $# > 0 )); then
			msg+=" Staged changes to $* are fine, but 'git add' any edits to them."
		fi
		fatal "$msg"
	fi
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

function increment-version() {
	local version=$(cat VERSION.txt)
	local old_version="$version"
	local a=( ${version//./ } )
	local major=${a[0]}
	local minor=${a[1]}
	local patch=${a[2]}

	if ! tag-exists "v$old_version"; then
		fatal "v$old_version has not been tagged yet. Run '$me commit' first."
	fi

	require-clean-tree

	while true; do
		read -p "Increment version [(m)ajor/m(i)nor/(p)atch]? " part
		if [[ "$part" == "" ]]; then
			part="M"
		fi
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
				echo "Enter M to increment major version, I for minor version, or P for patch"
			;;
		esac
	done

	version="$major.$minor.$patch"

	echo "Version: $old_version -> $version"
	echo "$version" > VERSION.txt
	add-changelog-section "$version" "v$old_version"
	git add -- VERSION.txt CHANGELOG.md

	local count=$(changelog-entries "$version" | wc -l)
	log "Added '# v$version' to CHANGELOG.md with $count commit(s) since v$old_version."
	log "Staged VERSION.txt and CHANGELOG.md. Edit CHANGELOG.md as needed ('git add' it afterwards), then run '$me commit'."
}

# Fails unless the first CHANGELOG.md heading is "# vX.Y.Z" for the given
# version and has at least one "- " entry.
function check-changelog() {
	local version="$1"
	local first_heading=$(grep -m 1 '^# ' CHANGELOG.md || true)
	if [[ "$first_heading" != "# v$version" ]]; then
		fatal "The first heading in CHANGELOG.md is '$first_heading', expected '# v$version'."
	fi
	if [[ -z "$(changelog-entries "$version")" ]]; then
		fatal "CHANGELOG.md has no '- ' entries under '# v$version'."
	fi
}

# Commits VERSION.txt and CHANGELOG.md as "Version: OLD -> NEW" and tags that
# commit, so every release tag points at a commit made by this script. If HEAD
# is already that commit (for example, a previous run committed but couldn't
# tag), it is tagged without making a new one. There is no separate way to
# tag, so a release tag can't land on any other commit.
function commit-version() {
	local version=$(cat VERSION.txt)
	local tag="v$version"

	if tag-exists "$tag"; then
		fatal "$tag already exists."
	fi

	# To avoid creating a release commit against a branch tested with accidentally uncommitted code,
	# this command is rejected if there are any untracked files or uncommitted changes. This also
	# catches edits to CHANGELOG.md that were made after 'increment' but not staged.
	require-clean-tree VERSION.txt CHANGELOG.md
	check-changelog "$version"

	local old_version=$(git show HEAD:VERSION.txt 2>/dev/null || echo "none")
	if [[ "$old_version" != "$version" ]]; then
		local commit_msg="Version: $old_version -> $version"
		echo "$commit_msg"
		git commit -m "$commit_msg" -- VERSION.txt CHANGELOG.md
	else
		local subject=$(git log -1 --format=%s)
		if [[ "$subject" != "Version: "*" -> $version" ]]; then
			fatal "VERSION.txt is already $version in HEAD, but HEAD ('$subject') is not a 'Version: ... -> $version' commit. Run '$me increment' first."
		fi
		if [[ -n "$(git status --porcelain -- CHANGELOG.md)" ]]; then
			fatal "CHANGELOG.md has changes that aren't in the $version release commit. Add them with 'git commit --amend -- CHANGELOG.md' first."
		fi
	fi
	git tag "$tag"
	log "Tagged $tag. Run '$me push' to push it."
}

function push-version() {
	local version="v$(cat VERSION.txt)"
	git push origin "$version"
}

function usage() {
	echo "Usage: $me [version|increment|commit|push|help]"
}

function main() {
	local subcommand=${1-version}
	local args=${@:2}

	case $subcommand in
		version)
			echo "$(cat VERSION.txt)"
			;;
		increment)
			increment-version $args
			;;
		commit)
			commit-version $args
			;;
		push)
			push-version $args
			;;
		-h|--help|help)
			usage
			;;
		*)
			log "$subcommand is not a valid subcommand."
			usage
			exit 1
			;;
	esac
}

main $@
