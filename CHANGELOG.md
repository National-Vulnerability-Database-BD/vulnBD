# Changelog

All notable changes to this project are documented here. Data updates (new
or modified CVE records) are tracked via git commit history on `data/`, not
here — this file is for the website/tooling itself.

## [0.1.0] — Initial release

- Normalized CVE schema (`src/types/cve.ts`), schema version 1.
- `cve.org` ingestion adapter using the CVE Program's GitHub-hosted delta log
  for incremental updates.
- Optional CISA KEV enrichment adapter.
- JSONL storage (`data/YYYY/MM.jsonl`) with idempotent, sorted, atomic writes.
- Validation pipeline (`npm run validate`).
- Index/statistics builder (`npm run index`): `cve-index.json`, per-year
  search shards, year/severity/CWE/vendor indexes, `statistics.json`,
  `metadata.json`.
- Astro + React + Tailwind static site: homepage, client-side search, browse,
  CVE detail pages with raw JSON endpoints, statistics, year/CWE/vendor
  pages, downloads, about.
- GitHub Actions: scheduled `update-cves.yml`, `deploy.yml` for Pages.
- Unit tests for normalization, validation, JSONL idempotency, and CVSS
  scoring.
