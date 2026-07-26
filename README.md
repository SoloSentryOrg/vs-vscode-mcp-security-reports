# Visual Studio, VS Code, and MCP Security Assessment Reports

This repository publishes final security assessment reports for Visual Studio,
Visual Studio Code, Model Context Protocol (MCP), and related AI developer
tooling.

## Published reports

| Assessment | Assessed version | Report |
| --- | --- | --- |
| Azure DevOps MCP Local | 2.8.1 | [DOCX](<reports/Azure DevOps MCP Local/Microsoft-Azure-DevOps-MCP-Local-2.8.1-2026-07-25-v1.1.docx>) |
| Azure DevOps MCP Remote | Preview | [DOCX](<reports/Azure DevOps MCP Remote/Microsoft-Azure-DevOps-MCP-Remote-Preview-2026-07-25-v1.1.docx>) |
| Chrome DevTools MCP | 1.6.0 | [DOCX](<reports/Chrome DevTools MCP/Google-Chrome-DevTools-MCP-1.6.0-2026-07-25-v1.1.docx>) |
| Dynatrace MCP Server Hosted | Current at assessment | [DOCX](<reports/Dynatrace MCP Server Hosted/Dynatrace-Hosted-MCP-current-2026-07-25-v1.1.docx>) |
| Dynatrace MCP Server Local | 2.1.1 | [DOCX](<reports/Dynatrace MCP Server Local/Dynatrace-Local-MCP-2.1.1-2026-07-25-v1.1.docx>) |
| GitHub MCP | 1.7.0 | [DOCX](<reports/GitHub/GitHub-MCP-1.7.0-VSCode-VisualStudio-2026-07-25-v1.0.docx>) |
| HashiCorp Terraform for VS Code | 2.39.4 | [DOCX](<reports/HashiCorp Terraform/HashiCorp-Terraform-VS-Code-2.39.4-2026-07-17-v1.0.docx>) |
| Microsoft MarkItDown MCP | 0.0.1a4 | [DOCX](<reports/Markitdown/Microsoft-MarkItDown-MCP-0.0.1a4-2026-07-25-v1.1.docx>) |
| Microsoft Learn MCP | Current at assessment | [DOCX](<reports/Microsoft Learn MCP/Microsoft-Learn-MCP-VSCode-VisualStudio-current-2026-07-25-v1.1.docx>) |
| Microsoft Playwright MCP | 0.0.78 | [DOCX](<reports/Microsoft Playwright MCP 0.0.78/Microsoft-Playwright-MCP-0.0.78-2026-07-25-v1.1.docx>) |
| Netdata MCP | 2.10.4 | [DOCX](<reports/Netdata/Netdata-MCP-2.10.4-2026-07-25-v1.0.docx>) |
| HashiCorp Terraform MCP | 1.1.0 | [DOCX](<reports/Terraform MCP Server 1.1.0/HashiCorp-Terraform-MCP-1.1.0-2026-07-25-v1.1.docx>) |
| Terraform MCP Server | 1.0.0 | [DOCX](<reports/Terraform/Terraform-MCP-Server-1.0.0-2026-07-17-v1.0.docx>) |

The machine-readable catalogue is [reports/index.json](reports/index.json).
Published file hashes are recorded in
[reports/SHA256SUMS.txt](reports/SHA256SUMS.txt).

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

## Verification

Run:

```shell
python3 scripts/validate_public_reports.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

## Reporting concerns

Use [SECURITY.md](SECURITY.md) for vulnerability or sensitive-content
reporting. Use a public issue only for non-sensitive corrections or broken
links.

## Licence

Repository-authored material is provided under the [MIT License](LICENSE).
Third-party names, trademarks, quoted material, screenshots, and referenced
content remain the property of their respective owners.
