# Release Guide

Releases are tag-driven and publish to crates.io with the protected
organization-level `CARGO_REGISTRY_TOKEN` Actions secret.

Only maintainers with release authority should perform these steps.

## One-time repository configuration

The release path depends on two protected settings:

1. A GitHub Actions environment named <code>crates-io</code>. Configure the
   required reviewers and deployment protections appropriate for the
   repository.
2. The organization-level <code>CARGO_REGISTRY_TOKEN</code> Actions secret must
   be visible to this repository and belong to an appropriately scoped
   crates.io automation identity. The workflow exposes it only to the
   <code>cargo publish</code> step; never print, persist, or pass it to
   third-party actions.

## Prepare the release in a pull request

Version and release notes land before the tag:

1. Update the package version.
2. Move the intended entries into a dated version section in
   <code>CHANGELOG.md</code>.
3. Update versioned documentation and examples.
4. Run the complete local contract:

   ```console
   make ci
   cargo package --locked --allow-dirty
   ```

   <code>--allow-dirty</code> is appropriate only while validating the release
   commit before it is merged; inspect the package file list carefully.

5. Open and merge the release-preparation pull request.
6. Confirm the merge commit is on <code>main</code> and required CI checks pass.

Do not tag a version that exists only on an unmerged branch.

## Tag the release

Start from an up-to-date, clean <code>main</code> worktree. Replace
<code>0.3.0</code> below with the version already present in the manifest and
changelog:

```console
git switch main
git pull --ff-only origin main
git status --short
git tag -a v0.3.0 -m "Release v0.3.0"
git show --stat v0.3.0
git push origin v0.3.0
```

The tag must:

- use the exact <code>v&lt;version&gt;</code> form;
- be an annotated tag, not a lightweight tag;
- point to <code>main</code>;
- match the package version exactly.

Tag protection should limit who can create or update <code>v\*</code> tags.

## Automated release sequence

The <code>Release</code> workflow triggered by the tag:

1. verifies that tag and manifest versions match;
2. formats, lints, tests, builds, and checks the package;
3. packages the crate and verifies the packaged contents;
4. enters the protected <code>crates-io</code> environment;
5. publishes the crate with the protected organization registry credential;
6. creates the GitHub release only after publication succeeds.

Watch the workflow through completion. A GitHub release without a successful
crate publication should not be treated as a complete release.

## Verify

After the workflow succeeds:

- confirm the exact version appears on crates.io;
- inspect the crates.io dependency/features/readme rendering;
- confirm the GitHub release points at the annotated tag and contains the
  intended notes/artifacts;
- verify generated documentation for the new version;
- install or build the published crate in a clean temporary project.

## Failure handling

- Before pushing a tag, correct the release commit and repeat local validation.
- After pushing a tag but before publication, investigate the failed workflow.
  Do not move or recreate a published tag silently.
- crates.io versions are immutable. If a bad version is published, coordinate a
  yank when appropriate, prepare a new patch version, and publish a fixed
  release.
- Never work around the protected environment or organization credential by
  introducing a personal crates.io token.

Record any release incident and the corrective action in the next release's
notes.
