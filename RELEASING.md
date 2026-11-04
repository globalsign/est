# Releasing

How to cut a release of `github.com/globalsign/est`. This is for maintainers;
users of the library and tools should see [README.md](README.md).

## How releases work

A release is an annotated git tag of the form `vX.Y.Z` on a commit in the
history of `master`. Go modules use the tag as the version, so
`go install github.com/globalsign/est/cmd/estclient@v1.2.3` builds exactly the
tagged commit, and `estclient`, `estserver` and the library report the version
the Go toolchain records from the tag. Nothing in the source tree holds a
version number, so a release never needs a "bump version" commit.

Tagging doesn't block merging to `master`. Pick the commit to release,
tag it, and work on `master` carries on.

Versions follow [semantic versioning](https://semver.org): bump the patch
version for fixes, the minor version for backwards-compatible additions, and
the major version for breaking changes. Go's
[semantic import versioning](https://go.dev/ref/mod#major-version-suffixes)
requires the module path in `go.mod` to end in `/v2`, `/v3`, ... for major
versions 2 and above, so a major release also needs the module path and every
import changed first; `release.sh` refuses to tag otherwise.

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com): each
release has a `## [X.Y.Z] - YYYY-MM-DD` section and, at the bottom, a link
comparing it with the previous release. Between releases, changes go under
`## [Unreleased]`. A tagged commit must have no `Unreleased` section: its
first section is the release being tagged.

## Procedure

1. **Check `master`.** Everything for the release is merged, and CI is
   green on the commit you want to release.

2. **Close out the changelog.** On `master`, edit `CHANGELOG.md`:

   - rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` with today's date;
   - make sure it lists every notable change since the previous release,
     grouped under `### Added`, `### Changed`, `### Fixed`, `### Removed` and
     so on;
   - replace the `[Unreleased]: ...` link at the bottom with
     `[X.Y.Z]: https://github.com/globalsign/est/compare/vPREV...vX.Y.Z`.

   Commit it (for example `Release vX.Y.Z`) and get it onto `master` the
   usual way.

3. **Tag it.** Check out that commit with a clean working tree and run the
   release script:

       ./release.sh vX.Y.Z
       ./release.sh --apply vX.Y.Z

   The first run is a dry run: it checks the commit (see below) and creates
   nothing. The second, with `--apply`, runs the same checks and then creates
   the annotated tag `vX.Y.Z` on it, with the changelog section as the tag
   message. The script tags `HEAD`, which may be detached or on any local
   branch as long as the commit is already in the history of `origin/master`,
   so check the commit it prints. If a check fails, fix the problem on `master`
   and start again from step 2 or 3 as appropriate.

4. **Push the tag.**

       git show vX.Y.Z
       git push origin vX.Y.Z

   A pushed tag is permanent. The Go module proxy and checksum database record
   it, so never delete or move a published tag; fix the problem and release
   the next version instead. A tag that hasn't been pushed yet can be removed
   with `git tag -d vX.Y.Z`.

5. **Publish the GitHub release.** On GitHub,
   [draft a new release](https://github.com/globalsign/est/releases/new) from
   the tag, titled `vX.Y.Z`, with the changelog section as its notes.

6. **Check it.**

       go install github.com/globalsign/est/cmd/estclient@vX.Y.Z
       estclient version

   should print `GlobalSign EST Client vX.Y.Z`. The module proxy may take a
   few minutes to notice a new tag.

7. **Reopen the changelog.** On `master`, add an empty `## [Unreleased]`
   section above the new release and the link
   `[Unreleased]: https://github.com/globalsign/est/compare/vX.Y.Z...HEAD`.

## What `release.sh` checks

In order, stopping at the first failure:

- The working tree has no staged, unstaged or untracked changes, so what gets
  tagged is exactly what was tested. Untracked files count because `go build`
  and `go test` would compile them even though they aren't in the commit;
  gitignored files are fine.
- `origin` can be fetched, so the next checks see its current tags and
  branches. If it can't, this is a warning and they use the last fetched state.
- No tag `vX.Y.Z` exists.
- `HEAD` is in the history of `origin/master`, so the tag only ever points at a
  commit that is already on GitHub. `HEAD` itself may be detached.
- `X.Y.Z` is greater than the newest release tag reachable from `HEAD`.
- The module path in `go.mod` matches the major version.
- `CHANGELOG.md` has no `Unreleased` section or link; starts with
  `## [X.Y.Z] - YYYY-MM-DD` (a date other than today is only a warning); has
  at least one entry in that section; has a
  `[X.Y.Z]: .../compare/vPREV...vX.Y.Z` link; and has a section for every
  earlier release tag reachable from `HEAD`.
- `go build ./...` and `go test -count=1 ./...` succeed in a clean export of
  `HEAD` made with `git archive`, so nothing on disk that isn't in the commit,
  not even a gitignored file, can affect them. The tests are run even if a
  cached result exists.

The tests exercise an HSM and a TPM when they are available. If you don't have
SoftHSM set up as CI does in `.github/scripts/setup-softhsm.sh`, skip those
tests the way CI does on platforms without them:

    GLOBALSIGN_EST_SKIP=hsm,tpm ./release.sh vX.Y.Z

The tag is signed if `tag.gpgSign` is set in your git configuration.

## Versions in local builds

With Go 1.24 or later, `go build` records the version from the checkout:
`vX.Y.Z` when building the tagged commit with a clean tree (untracked files
count as changes), `vX.Y.Z+dirty` when there are changes, and a pseudo-version
such as `v1.0.8-0.20260101120000-abcdef123456` on later commits. Older
toolchains record `(devel)`, as do the tests.
