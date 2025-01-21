# COCONUT-SVSM Release Process

This document describes the stages of code and releases in the COCONUT-SVSM
project and defines what users and developers can expect from each stage of
development.

## Release Stages

The COCONUT-SVSM project has three stages and a couple of sub-stages for
releasing code to its users:

* Main Development Branch
* Development Releases
* Stable Releases
  * Release Candidates
  * Final Releases
  * Release Updates

The next sections explain the expectations users can put into each stage

### Main Development Branch

This is the initial landing site for each new feature and (where applicable)
bug fixes to the COCONUT-SVSM project. The code is in the `main` branch of the
git repository at [Github](https://github.com/coconut-svsm/svsm/).

Every change must be merged to the main branch before it can be part of a
development or stable release. The only exceptions to this rule are made for
fixing bugs present in a stable release but not in the main branch.

The main branch is only intended for developers and active contributors of the
COCONUT-SVSM project.

### Development Releases

Development releases are snapshots of the main development branch. A release
is marked with a git tag in the COCONUT-SVSM Github repository. ~~Prior to a
development release the `main` branch of the project is frozen for one week and
only bug fixes will be accepted. After the week has passed and no major known
issues remain in the code base the development release is tagged.~~

A development release starts when the Technical Steering Committee (TSC) opens
a PR updating the release version and is finished with this PR being merged and
the release tag being created. Release tags need to be signed by one member of
the TSC.

Development releases are intended for testing by a wider community outside of
the active contributors group, but not recommended for production use. These
releases are a marker for COCONUT-SVSM development at a given point in time and
will not receive updates for fixing issues or adding new features. 

### Stable Releases

Stable releases are code streams intended for production use. A given release
branch is created off the `main` development branch at least 4 weeks ahead
of the planned final release. During these 4 weeks the branch will only receive bug
fixes, which are usually cherry-picked from the main development branch. Release
candidates will be provided every week until the final release is ready.

After the final release the branch will continue to receive updates for bug
fixes at least until the next stable release is finished.  Each release
candidate, the final release, and updates to the final release are marked with
git tags signed by a member of the TSC.

## Release Naming

Release names have the following form:

* `YYYY.MM[.NN][-TYPE]`

Where:

* `YYYY` - The calendar year of when the release is expected to happen.
* `MM` - The month of the year (1-12) when the release is expected to happen.
* `NN` - An optional increasing number for updates to a prior release.
* `-TYPE` - The release type. For development releases this will be `-devel`.
  Candidates of stable releases will have `-rcN` with `N` being an increasing
  number.

Some examples:

* `2025.01-devel` Marks a development release from January 2025.
* `2025.10-rc2` Marks the second release candidate for a stable release
  expected to be tagged in October 2025.
* `2025.10` Marks a stable release from October 2025
* `2025.10.4` Marks the fourth update to the stable release from October 2025.

## Release Cadence

There is no release cadence defined yet.
