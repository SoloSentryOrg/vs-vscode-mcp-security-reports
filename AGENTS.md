# Agent Instructions

## BLUF

- This is a public report-distribution repository.
- Default-deny publication: only final authoritative DOCX reports and derived
  public catalogue or checksum records may be promoted.
- Never add source snapshots, evidence, stage output, drafts, historical
  baselines, private logs, local metadata, or assessment-workspace history.
- Treat every DOCX as an untrusted archive and run the Report Publication Gate.
- Use signed commits and pull requests; do not push directly to protected
  `main`.

## Publication contract

- Use `scripts/import_publication_bundle.py` as the only supported report and
  catalogue mutation path.
- New imports and readiness checks require a policy-bound v2 bundle containing
  exactly `release.json` and one DOCX. Independently verify the exact consumer policy commit and
  digest against current protected `main` before report validation and again
  before catalogue preparation; require the local host policy to match it.
- Bundle policy metadata must not add hosts or replace independent DOCX
  validation. Keep private QA paths, approvals and evidence out of the bundle.
- Preserve read-only v1 inspection through `--inspect-legacy`; historical
  inspection must not grant current readiness or mutate the catalogue.
- Acquire report bytes once with bounded no-follow reads into private staging;
  hash, validate and import that same snapshot rather than reopening bundle bytes.
- Import one report per pull request and preserve byte identity with the
  validated bundle report.
- Treat the README report table as generated content.
- Require a separate governance pull request for new hyperlink-host or
  custom-XML allowlist entries before importing a dependent report.
- Reject unclassified or unexpected tracked paths.
- Reject symlinks, macros, embedded objects, active content, comments, tracked
  revisions, unsafe external relationships, private metadata, and non-public
  classification markers.
- Preserve old public versions in history; publish corrections as new versions.

## Security and privacy

- Do not publish credentials, personal data, private paths, internal hostnames,
  private IP addresses, confidential business information, embargoed findings,
  or identifying victim data.
- Use synthetic or public-safe examples.
- Keep GitHub Actions read-only by default and pin actions to full commit SHAs.
- Validate both repository files and effective GitHub security settings.
- Stop publication when a security review or required check has an unresolved
  finding.

## Verification

- Run `git diff --check`.
- Run `python3 scripts/validate_public_reports.py`.
- Run `python3 -m unittest discover -s scripts -p 'test_*.py'`.
- Run targeted secret and malware scans.
- Verify GitHub signature status, required checks, security controls, and
  unauthenticated access after merge or visibility changes.
