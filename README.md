# Veracode Severity Gate for the GitHub Workflow Integration

Adds a configurable, build-breaking severity gate to the Veracode GitHub Workflow Integration for agent-based SCA and IaC/Secrets scans. The overlay parses the scan results and fails the job when any finding is at or above a threshold you set in `veracode.yml`. Output is a rendered severity table in the job summary plus a failing annotation.

This is an overlay on top of the Veracode GitHub Workflow Integration repo. The files in this repo are placed at the same paths as the integration repo, so you copy them in over the existing files.

-----

## How It Works

The native scans gate on platform policy, not on finding severity:

- **Agent-based SCA** honors `breakBuildOnPolicyFindings`, which acts on the SCA workspace policy, not on finding severity.
- **IaC/Secrets** has no policy connection to application profiles.

This overlay adds a configurable severity threshold on top. Each workflow runs a gate step after the scan:

1. The existing scan action still runs (kept for platform sync, PR decoration, SBOMs, and Fix-for-SCA). Its own build-break is disabled so there is a single enforcing control.
1. The gate resolves a severity threshold from `break_build_severity_threshold` in `veracode.yml`.
1. The gate parses the scan results and counts findings at or above the threshold.
1. If any are found, the gate writes a detailed table to `$GITHUB_STEP_SUMMARY`, emits a `::error::` annotation, and exits non-zero, failing the job.

The SCA gate reads the agent report the action already produces (`scaResults.txt`, or `scaResults.json` if you enable issues). The IaC gate runs its own deterministic scan with the bundled Veracode CLI to a known JSON file, because the action's JSON output path is internal and undocumented.

-----

## Repository Layout

Copy these into your Veracode integration repo at the same paths.

|Path                                          |Purpose                                                                 |
|----------------------------------------------|------------------------------------------------------------------------|
|`veracode.yml`                                |Adds the documented `break_build_severity_threshold` key per scan type  |
|`.github/workflows/veracode-sca-scan.yml`     |SCA workflow with the severity gate step (Linux and Windows)            |
|`.github/workflows/veracode-iac-secrets-scan.yml`|IaC/Secrets workflow with the deterministic re-scan and gate step    |
|`helper/cli/veracode_severity_gate.py`        |The gate parser. Dependency-free, Python 3.8+                           |
|`helper/cli/tests/test_gate.py`               |Unit tests for the gate (stdlib `unittest`, no dependencies)            |

-----

## Prerequisites

- The Veracode GitHub Workflow Integration is already installed and the template workflows are present in the target repo.
- The repo already holds the bundled Veracode CLI tarball under `helper/cli/` (shipped with the integration, named `veracode-cli_<version>_linux_x86.tar.gz`). The IaC gate resolves it by glob and runs it, so a version bump does not break the workflow.
- Existing repo secrets are in place and unchanged: `VERACODE_API_ID`, `VERACODE_API_KEY` (used by the IaC CLI scan), and `VERACODE_AGENT_TOKEN` (used by the SCA action).
- Runners are Linux for the IaC gate, because the bundled CLI is `linux_x86`. On a non-Linux runner the IaC gate fails closed with a clear message rather than passing ungated. The SCA gate has a Linux path and a PowerShell path.

No new secrets and no new GitHub Actions variables are required.

-----

## Installation

1. Copy the four files into your integration repo at the paths in [Repository Layout](#repository-layout), overwriting the two existing workflow files and merging the `veracode.yml` keys.
1. Confirm `helper/cli/veracode_severity_gate.py` is committed. The workflows already sparse-checkout `helper/cli/*`, so the script ships to the runner with no extra step.
1. Commit and push to the branch your Veracode app dispatches against (usually the integration repo default branch).
1. Trigger a scan (push, PR, or an issue comment such as `Veracode All Scans`) and confirm the new gate step runs.

```bash
git checkout -b severity-gate
git add veracode.yml \
  .github/workflows/veracode-sca-scan.yml \
  .github/workflows/veracode-iac-secrets-scan.yml \
  helper/cli/veracode_severity_gate.py
git commit -m "Add configurable severity gate for SCA and IaC/Secrets scans"
git push -u origin severity-gate
```

-----

## Configuration

Set the gate level in `veracode.yml`, per scan type, so SCA and IaC can differ:

```yaml
veracode_sca_scan:
  # ...existing keys...
  break_build_severity_threshold: medium

veracode_iac_secrets_scan:
  # ...existing keys...
  break_build_severity_threshold: high
```

|Value                              |Meaning                                                                 |
|-----------------------------------|------------------------------------------------------------------------|
|`critical` / `high` / `medium` / `low` / `info`|Band comparison. `medium` means medium and above.           |
|A CVSS number, for example `7.0`   |Exact CVSS comparison where a finding has a score; band fallback otherwise|

The key is read directly from `veracode.yml` at scan time. It is not passed through the Veracode dispatch payload, because the integration's `user_config` is assembled server-side against a fixed schema and does not forward unknown keys.

-----

## Threshold Resolution

The gate resolves the threshold in this order, first non-empty wins:

|Order|Source                                                  |Use case                                  |
|-----|--------------------------------------------------------|------------------------------------------|
|1    |`break_build_severity_threshold` in the scanned repo's `veracode.yml`|Per-repo override                         |
|2    |`break_build_severity_threshold` in the integration repo's `veracode.yml`|Org default                               |
|3    |`user_config.break_build_severity_threshold` from the dispatch payload|Only if Veracode ever forwards it          |
|4    |`VERACODE_FAIL_SEVERITY` GitHub Actions variable        |Optional UI override                      |
|5    |Built-in default `medium`                               |Fallback                                  |

A scanned repo that ships its own `veracode.yml` therefore overrides the org default without touching the workflow. The resolved value is printed in the step log as `Resolved ... severity threshold: <value>`.

-----

## What Gets Gated

**SCA (`--mode sca`)** parses the agent report and gates `Vulnerability` issues by their CVSS severity. `Outdated Library` issues are reported but do not break the build by default. Add `--include-outdated` to gate them too. When the text report is used, the gate reconciles the number of parsed vulnerability rows against the report's own summary counts and fails closed on a mismatch, so a future change to the report format cannot silently under-count.

**IaC/Secrets (`--mode iac`)** parses the Veracode CLI JSON and gates three categories: IaC misconfigurations (`configs`, status `FAIL` only; `PASS` is ignored), exposed secrets, and dependency vulnerabilities.

Every finding is gated on its effective severity, which is the higher of its explicit label and its CVSS-derived band. A finding labelled `Unknown` or `Negligible` that carries a high CVSS is therefore gated on the score, not the label. A finding with no usable severity signal at all is floored so it never silently passes: secrets floor to `high`, everything else to `medium`.

-----

## Failure Behavior

The gate fails closed. If it cannot produce a trustworthy verdict, it fails the build rather than passing silently, because a security control that passes on error gives false assurance. This includes a missing or empty results file, malformed JSON, an invalid threshold, or an SCA reconciliation mismatch. Each case prints a single actionable `::error::` and exits 2.

The workflow steps reinforce this: `set -euo pipefail`, the scan exit code is captured and a non-empty results file is required, and on a non-Linux runner the IaC gate fails with a clear message instead of being skipped. Pass `--allow-missing` if you deliberately want a missing input file to count as a pass.

-----

## Gate Output

The gate result is surfaced in three places: the job log, the GitHub job summary, and a check run on the scanned repository named "Veracode IaC Severity Gate" or "Veracode SCA Severity Gate". The check run carries the rendered severity table as its summary, so the result is visible directly in the pull request Checks panel, not only in the workflow run. Publishing the check run is best-effort and never changes the pass or fail verdict.

On every run the gate writes a count table and, when findings meet the threshold, a detail table:

```
## Veracode SCA severity gate

Threshold: medium (fail at this level or higher)

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 4 |
| Medium | 2 |
| Low | 0 |
| Info | 0 |
| Total | 7 |

### 7 finding(s) at or above threshold
| Severity | Category | ID | Finding | Location |
| Critical (9.8) | Vulnerability | 556726105 | CVE-2021-24112: Remote Code Execution (RCE) | System.Drawing.Common 4.7.0 |
...
```

It then emits `::error::Veracode SCA gate failed: 7 finding(s) at or above 'medium'.` and exits 1.

-----

## Consolidated PR Comment

A single sticky comment per pull request summarizes all three scans. Each scan owns one delimited section (pipeline, SCA, IaC) and updates only its own section, so the three scans build one combined summary even though they run as separate workflows. Each section shows a severity count table and a Passed or Failed verdict against the threshold. The comment is identified by a hidden marker (`<!-- veracode-scan-summary -->`); the first scan to finish creates it with all three sections stubbed, and later scans fill theirs in.

The comment is posted to the scanned repo's PR using `client_payload.token` and `client_payload.pr_number`, both provided by the dispatch. To enable it, the gate step passes `--pr-comment <section>` and sets `GH_TOKEN`, `SCAN_REPO`, `PR_NUMBER`, and optional `RUN_URL` in its environment (already wired in all three workflows). Posting is best-effort: if the token lacks pull-request write, or the run is not a PR, the gate prints a warning and the verdict is unaffected.

Because the three scans run concurrently, two can update the comment at nearly the same moment. The updater re-fetches and retries with small random backoff to absorb this, which covers almost all cases. The SCA and IaC gates break the build on the threshold and post their section; the pipeline gate posts its section with `--warn-only` so it reports without adding a new build break on top of the existing policy break. Remove `--warn-only` in the pipeline workflow to also break the build on severity.

-----

## Gate Script Reference

`helper/cli/veracode_severity_gate.py` has no third-party dependencies and runs on Python 3.8+.

|Flag                |Required|Description                                                        |
|--------------------|--------|-------------------------------------------------------------------|
|`--mode`            |Yes     |`iac` or `sca`                                                     |
|`--input`           |Yes     |Path to the results file                                           |
|`--threshold`       |No      |`critical|high|medium|low|info` or a CVSS number in [0, 10]. Default `medium`|
|`--include-outdated`|No      |SCA only. Also gate `Outdated Library` issues                      |
|`--warn-only`       |No      |Report but never fail the build                                    |
|`--allow-missing`   |No      |Treat a missing input file as a pass instead of failing closed     |

|Exit code|Meaning                                                                  |
|---------|-------------------------------------------------------------------------|
|`0`      |Evaluated successfully, no finding at or above the threshold, or `--warn-only`|
|`1`      |One or more findings at or above the threshold                           |
|`2`      |Could not evaluate (missing/empty/invalid input, invalid threshold, or reconciliation mismatch). Fails closed.|

Input auto-detection: in `sca` mode a file starting with `{` or `[` is parsed as JSON, otherwise as the agent text report.

-----

## Severity Mapping

CVSS scores map to bands using the standard Veracode banding:

|Band     |CVSS base score|
|---------|---------------|
|Critical |9.0 - 10.0     |
|High     |7.0 - 8.9      |
|Medium   |4.0 - 6.9      |
|Low      |0.1 - 3.9      |
|Info     |0.0 / none / negligible / unknown|

-----

## Local Testing

Validate the gate against a saved report before relying on it in CI. Exit `1` means it would break the build, `0` means pass.

```bash
# SCA: save an agent log as scaResults.txt
python3 helper/cli/veracode_severity_gate.py --mode sca --input scaResults.txt --threshold medium
echo $?

# IaC: produce JSON with the bundled CLI, then gate
./veracode scan --type directory --source ./ --format json --output veracode-iac-results.json
python3 helper/cli/veracode_severity_gate.py --mode iac --input veracode-iac-results.json --threshold high
```

Add `--warn-only` to see the report without a non-zero exit while tuning the threshold.

Run the unit tests (standard library only, no dependencies):

```bash
cd helper/cli
python3 -m unittest discover -s tests -p 'test_*.py'
```

The suite covers CVSS banding, effective-severity escalation, the secret floor, threshold validation, numeric exact comparison, fail-closed behavior on missing/empty/malformed input, SCA reconciliation, and output sanitization.

-----

## Fleet-Wide Rollout

If you manage many orgs with the bulk GitHub Workflow Integration tool, the threshold config in `veracode.yml` can be pushed across the fleet with `--update-veracode-yml`:

```bash
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --update-veracode-yml /path/to/veracode.yml
```

Note that `--update-veracode-yml` deploys only the `veracode.yml` file. The gate itself also needs the two modified workflow files and `helper/cli/veracode_severity_gate.py`. To roll the gate out fleet-wide, place those in the template the bulk tool imports from (the source for `--import-repo` and `--fix-repos`), so new and re-imported repos pick them up. Otherwise apply them per repo.

-----

## Security Notes

- No new secrets are introduced. The IaC CLI scan reuses the existing `VERACODE_API_ID` and `VERACODE_API_KEY` via HMAC environment variables.
- Untrusted dispatch and variable values reach the shell only through `env:` indirection, never inline expression interpolation in a `run:` block, which avoids script injection.
- The gate script has no network calls, no `subprocess`/shell usage, and no third-party dependencies. The threshold is passed as a single quoted argument and validated, so a hostile `veracode.yml` value cannot execute.
- Finding text is sanitized (newlines and tabs collapsed, leading `::` neutralized, pipes escaped) before it reaches the Markdown summary or the log.
- Scan artifacts (`scaResults.*`, results JSON) are git-ignored and the temp staging directory is removed on step exit.

-----

## Support

This is a community overlay for the Veracode GitHub Workflow Integration and is not officially supported by Veracode. When reporting an issue, include the failing job log (the resolved threshold line and the gate table) and the relevant `veracode.yml` section.
