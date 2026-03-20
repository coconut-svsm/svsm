GitHub Workflow Requirements
============================

The project uses GitHub actions for CI testing workflows of code changes before
they are merged. These actions need access to the project and use externally
provided code to execute.

In order to maximize security the COCONUT-SVSM project follows the
[OpenSSF scorecard](https://openssf.org/projects/scorecard/) for
project workflows, which are:

* Each workflow runs with minimal permissions
* Workflow dependencies are pinned by their git hash value, not a tag

The easiest way to enforce these rules is to write the GitHub workflow
file as usual and then use this [StepSecurity form](https://app.stepsecurity.io/secure-workflow)
to update it to match the OpenSSF security recommendations.
