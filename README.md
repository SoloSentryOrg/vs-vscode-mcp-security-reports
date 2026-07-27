# Visual Studio, VS Code, and MCP Security Assessment Reports

[![Report Publication](https://github.com/SoloSentryOrg/vs-vscode-mcp-security-reports/actions/workflows/report-publication.yml/badge.svg)](https://github.com/SoloSentryOrg/vs-vscode-mcp-security-reports/actions/workflows/report-publication.yml)
[![Citation Link Monitor](https://github.com/SoloSentryOrg/vs-vscode-mcp-security-reports/actions/workflows/citation-link-monitor.yml/badge.svg)](https://github.com/SoloSentryOrg/vs-vscode-mcp-security-reports/actions/workflows/citation-link-monitor.yml)

This repository publishes final security assessment reports for Visual Studio,
Visual Studio Code, Model Context Protocol (MCP), and related AI developer
tooling. It is the public distribution point for completed, declassified
reports—not the private assessment workspace or evidence archive.

## Start here

- Choose the report that matches the product and assessed version you use.
- Confirm the assessment date and report version in the filename and document
  control table.
- Read the approval decision, limitations, and closure evidence before relying
  on a report.
- Treat each report as a dated assessment, not a product endorsement or a
  guarantee of future security.

## Published reports

<!-- BEGIN GENERATED REPORT CATALOGUE -->
| Assessment | Assessed version | Report |
| --- | --- | --- |
| Azure DevOps MCP Local | 2.8.1 | [DOCX](<reports/Azure DevOps MCP Local/Microsoft-Azure-DevOps-MCP-Local-2.8.1-2026-07-25-v1.1.docx>) |
| Azure DevOps MCP Remote | Preview | [DOCX](<reports/Azure DevOps MCP Remote/Microsoft-Azure-DevOps-MCP-Remote-Preview-2026-07-25-v1.1.docx>) |
| Chrome DevTools MCP | 1.6.0 | [DOCX](<reports/Chrome DevTools MCP/Google-Chrome-DevTools-MCP-1.6.0-2026-07-25-v1.1.docx>) |
| Claude Code for VS Code | 2.1.220 | [DOCX](<reports/Claude Code for VS Code/Claude-Code-for-VS-Code-2.1.220-VSCode-2026-07-26-v1.0.docx>) |
| Dynatrace MCP Server Hosted | Current at assessment | [DOCX](<reports/Dynatrace MCP Server Hosted/Dynatrace-Hosted-MCP-current-2026-07-25-v1.1.docx>) |
| Dynatrace MCP Server Local | 2.1.1 | [DOCX](<reports/Dynatrace MCP Server Local/Dynatrace-Local-MCP-2.1.1-2026-07-25-v1.1.docx>) |
| GitHub MCP | 1.7.0 | [DOCX](<reports/GitHub/GitHub-MCP-1.7.0-VSCode-VisualStudio-2026-07-25-v1.0.docx>) |
| HashiCorp Terraform for VS Code | 2.39.4 | [DOCX](<reports/HashiCorp Terraform/HashiCorp-Terraform-VS-Code-2.39.4-2026-07-17-v1.0.docx>) |
| HashiCorp Terraform MCP | 1.1.0 | [DOCX](<reports/Terraform MCP Server 1.1.0/HashiCorp-Terraform-MCP-1.1.0-2026-07-25-v1.1.docx>) |
| Microsoft Learn MCP | Current at assessment | [DOCX](<reports/Microsoft Learn MCP/Microsoft-Learn-MCP-VSCode-VisualStudio-current-2026-07-25-v1.1.docx>) |
| Microsoft MarkItDown MCP | 0.0.1a4 | [DOCX](<reports/Markitdown/Microsoft-MarkItDown-MCP-0.0.1a4-2026-07-25-v1.1.docx>) |
| Microsoft Playwright MCP 0.0.78 | 0.0.78 | [DOCX](<reports/Microsoft Playwright MCP 0.0.78/Microsoft-Playwright-MCP-0.0.78-2026-07-25-v1.1.docx>) |
| Netdata MCP | 2.10.4 | [DOCX](<reports/Netdata/Netdata-MCP-2.10.4-2026-07-25-v1.0.docx>) |
| Terraform MCP Server | 1.0.0 | [DOCX](<reports/Terraform/Terraform-MCP-Server-1.0.0-2026-07-17-v1.0.docx>) |
<!-- END GENERATED REPORT CATALOGUE -->

The machine-readable [report catalogue](reports/index.json) records product,
version, assessment date, classification, Word page count, path, and SHA-256.
Published hashes are also recorded in
[reports/SHA256SUMS.txt](reports/SHA256SUMS.txt).

## Verify a download

From a clone of this repository, verify every published report:

```shell
shasum -a 256 -c reports/SHA256SUMS.txt
python3 scripts/validate_public_reports.py
```

The validator checks the catalogue and hashes, repository allowlist, DOCX
package bounds, classification, metadata, review artefacts, active content,
external relationships, private paths, email addresses, and private network
identifiers.

## Publication model

- This is a report-distribution repository, not an assessment workspace or
  evidence archive.
- Only declassified, authoritative DOCX reports and derived public catalogue
  and checksum records are promoted here.
- Source snapshots, evidence, stage output, drafts, historical baselines,
  internal logs, and private Git history are retained outside this repository.
- A report records the scope, evidence, limitations, confidence, and decision
  applicable at its stated assessment date and version. Publication is not a
  product endorsement or a guarantee of future security.
- Superseded public reports remain in Git history. Corrections are published as
  new, versioned reports.

## Publication controls

- Changes use signed commits and protected pull requests.
- The report table above is generated from `reports/index.json`; do not edit it
  by hand.
- `python3 scripts/import_publication_bundle.py <bundle-directory>` is the only
  supported way to add a report and update the catalogue, checksums, and README.
- Publication bundles contain exactly `release.json` and one byte-identical
  DOCX. The importer validates the bundle before mutating repository content
  and never retains producer provenance or the bundle manifest.
- New hyperlink hosts or custom-XML digests require a separate reviewed
  governance pull request before a report that depends on them is imported.
- Report publication remains pull-request- and human-merge-controlled; the
  importer never commits, pushes, opens, or merges a pull request.
- The required Report Publication Gate runs offline and fail closed.
- `main` requires the strict publication check and resolved review threads.
- GitHub CodeQL, secret scanning, validity checks, and push protection provide
  additional repository-level controls.
- External citation availability is monitored weekly in a separate read-only
  workflow. Link drift does not silently change a report or its assessment
  decision.

## What is not published

Source snapshots, raw evidence, stage output, drafts, internal logs, private
paths, credentials, personal data, and private assessment Git history are
excluded from this repository.

## Reporting concerns

Use [SECURITY.md](SECURITY.md) for vulnerability or sensitive-content
reporting. Use a public issue only for non-sensitive corrections or broken
links.

## Licence

Repository-authored material is provided under the [MIT License](LICENSE).
Third-party names, trademarks, quoted material, screenshots, and referenced
content remain the property of their respective owners.
