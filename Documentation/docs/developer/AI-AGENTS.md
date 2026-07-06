# AI Agents

The project contains an `AGENTS.md` file at the root directory, which may be
consumed by AI tools to gain context about the project and its tooling and
conventions.

Read more about `AGENTS.md` at the official website: <https://agents.md/>

## Keeping AGENTS.md up to date

You may use the following prompt to keep the file up to date:

```
Read AGENTS.md at the repo root. Your job is to verify it still accurately
describes this codebase and report a diff of what needs to change. Do not edit
AGENTS.md unless explicitly told to.

Check each claim against current repo state:

1. Directory layout: every path listed under "Directory structure" exists and
matches its description. Flag top-level directories present in the tree but
missing from the doc only if they are first-class areas a contributor would
need to know about.

2. Build & test commands: make, make test, make clippy, cargo fmt --check
still work as described. Check the Makefile for renamed/added targets that
contributors are now expected to run.

3. Documentation links: every Documentation/docs/... path referenced in the
file exists.

4. Protocols table: for each row (ID, name, implementation path, purpose):
  - The file under kernel/src/protocols/ exists at the listed path.
  - Search kernel/src/protocols/ for any protocol module not in the table.
  - Cross-check protocol IDs against the registration site (grep for the
    dispatch / match table).
  - Confirm any feature = "..." gating noted in the table still applies.

5. Named symbols: confirm named symbols are still present and behave as
described (e.g. `GuestPtr`, `SvsmPlatform`, `SEVStatusFlags`, etc). A simple
grep is enough to test a symbol exists. Flag any symbol that has been renamed
or removed.

6. Verus section: *.verus.rs / *.proof.verus.rs files still exist,
the verus / verus_all features are still defined in Cargo.toml, and
cfg_attr(verus_keep_ghost, ...) is still the gating attribute in use.

7. Spec references: the AMD/Intel publication numbers and titles in the
"Reference Specifications" sections are the latest the project tracks (check
Documentation/ or recent commits touching protocol code for newer revisions
cited there).

8. New material worth adding: use `git log` to scan for recently added
protocols, new platform support, new security-relevant invariants, or new
contributor-facing build steps that a newcomer would need but the doc does not
mention. Only flag items that meet the doc's existing high-level description.

Output: a list grouped as Incorrect (claim contradicts current code), Stale
(path/symbol gone), Missing (significant new area undocumented), OK. For each
non-OK item, give the exact file/line in AGENTS.md and a suggested replacement.
Keep it under one screen unless the doc is badly out of date.
```
