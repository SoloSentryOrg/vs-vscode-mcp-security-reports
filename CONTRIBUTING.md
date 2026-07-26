# Contributing

## Non-sensitive corrections

Open an issue for typographical errors, broken public links, version
clarifications, or other non-sensitive report corrections.

## Sensitive concerns

Follow [SECURITY.md](SECURITY.md). Never include credentials, personal data,
private paths, embargoed findings, or exploit details in a public issue or pull
request.

## Report publication

New and materially updated assessment reports are accepted only through the
authorised assessment and declassification workflow. Direct public uploads of
assessment reports, evidence, source snapshots, or generated findings are not
accepted.

Repository changes must:

- preserve the report-only publication boundary;
- update `reports/index.json` and `reports/SHA256SUMS.txt` atomically;
- pass the Report Publication Gate;
- use signed commits and a pull request; and
- avoid unrelated formatting or generated-file churn.
