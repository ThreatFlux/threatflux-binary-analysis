# Release Guide

Releases are automated from conventional commits on <code>main</code> and
publish to crates.io through
[trusted publishing](https://crates.io/docs/trusted-publishing). No long-lived
crates.io token is stored in GitHub.

Only maintainers with release authority should change the release workflows or
dispatch a real release.

## One-time configuration

The release path depends on two settings outside this repository's source:

1. crates.io trusted publishing for <code>threatflux-binary-analysis</code>,
   trusting the <code>ThreatFlux</code> owner, this repository, the
   <code>release.yml</code> workflow, and the <code>crates-io</code>
   environment. The workflow file name and environment name must stay exactly
   as written or the OIDC token exchange is rejected.
2. A GitHub Actions environment named <code>crates-io</code>. Configure the
   required reviewers and deployment protections appropriate for the
   repository.

## How a release happens

1. Merge pull requests to <code>main</code> with conventional commit subjects.
   <code>fix:</code> produces a patch release, <code>feat:</code> a minor
   release, and a breaking change (<code>!</code> or
   <code>BREAKING CHANGE:</code>) a major release. <code>ci:</code>,
   <code>build:</code>, <code>chore:</code>, <code>docs:</code>, and
   <code>test:</code> do not release on their own.
2. When the <code>CI</code> and <code>Security</code> workflows both pass on
   the new <code>main</code> commit, <code>Auto Release</code> calls the
   ThreatFlux reusable auto-release workflow. It bumps
   <code>Cargo.toml</code>, pushes the version commit and the
   <code>v&lt;version&gt;</code> tag, creates the GitHub Release, and dispatches
   <code>release.yml</code> for that tag.
3. <code>release.yml</code>:
   1. checks that the tag points at the selected commit and that the manifest
      version matches the release version;
   2. builds the library with every feature for Linux (gnu, musl, arm64),
      macOS (arm64, x86-64), and Windows, and runs the release-mode test suite
      on the native targets;
   3. checks formatting and Clippy, packages the crate, and generates a
      CycloneDX SBOM;
   4. uploads the <code>.crate</code> file, its SHA-256 checksum, and the SBOM
      to the GitHub Release;
   5. enters the <code>crates-io</code> environment, exchanges the job's OIDC
      token for a short-lived crates.io token with
      <code>rust-lang/crates-io-auth-action</code>, and runs
      <code>cargo publish</code>. A version that is already on crates.io is
      skipped, so a re-run never fails on an immutable version.

Watch both workflows through completion. A GitHub Release without a successful
crates.io publication is not a complete release; a failed publish fails the
run.

## Rehearse a release

Both workflows accept a <code>dry_run</code> input that never creates a
commit, tag, GitHub Release, or crates.io version:

```console
# Report the version Auto Release would cut next.
gh workflow run auto-release.yml --ref main -f version_bump=auto -f dry_run=true

# Build every target, package the crate, generate the SBOM, and run
# `cargo publish --dry-run` for the commit on main.
gh workflow run release.yml --ref main -f version=0.3.1 -f dry_run=true
```

A dry run of <code>release.yml</code> warns, rather than fails, when the
requested version differs from the manifest; it always packages and verifies
the manifest version.

## Manual release

To release without Auto Release, first merge a pull request that sets the
<code>Cargo.toml</code> version and moves the matching entries into a dated
<code>CHANGELOG.md</code> section, then dispatch the release workflow on
<code>main</code> with that exact version:

```console
gh workflow run release.yml --ref main -f version=X.Y.Z
```

The workflow creates the <code>vX.Y.Z</code> tag on the selected commit. It
refuses to run if that tag already exists on a different commit.

## Verify

After the workflows succeed:

- confirm the exact version appears on crates.io;
- inspect the crates.io dependency/features/readme rendering;
- confirm the GitHub Release points at the tag and contains the intended
  notes, the <code>.crate</code> file, its checksum, and the SBOM;
- verify generated documentation for the new version on docs.rs;
- build the published crate in a clean temporary project.

## Failure handling

- Investigate a failed <code>release.yml</code> run and re-run it. A
  version that is already on crates.io is skipped, so a re-run completes the
  remaining steps. Do not move or recreate a published tag.
- crates.io versions are immutable. If a bad version is published, coordinate a
  yank when appropriate, prepare a new patch version, and publish a fixed
  release.
- Never work around trusted publishing by introducing a personal or
  organization crates.io token.

Record any release incident and the corrective action in the next release's
notes.
