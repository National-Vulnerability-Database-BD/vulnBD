# Security Policy

## Reporting a vulnerability in this project's code

If you find a security issue in this project's own code (the website, the
ingestion scripts, or the GitHub Actions workflows) — as opposed to a
vulnerability *described by* a CVE record in the database — please report it
privately via GitHub's "Report a vulnerability" flow under this repository's
Security tab, rather than opening a public issue.

We'll acknowledge reports within a few business days.

## This project's threat model

This is a static site with no traditional backend, no user accounts, and no
server-side database. The main attack surfaces we actively defend are:

- **Untrusted upstream data.** Every CVE record we ingest originates from a
  third party. We treat all of it as untrusted input:
  - Descriptions and other free text are rendered as plain text, never as
    raw HTML (no `dangerouslySetInnerHTML`/`set:html` on source-derived
    content).
  - Reference URLs are validated to be `http(s)://` before storage or
    rendering; anything else (e.g. `javascript:`) is dropped during
    normalization.
  - Oversized or malformed records are rejected by `npm run validate`
    before they can be committed.
- **Supply chain.** GitHub Actions workflows pin actions to major versions
  from verified publishers and never echo secrets into logs. No secrets are
  used in the frontend build; the site needs no API keys to function at all.
- **Path safety.** All file writes in `scripts/` are constrained to computed
  paths under `data/` and `index/` — no user- or source-controlled string is
  ever used directly as a filesystem path.

## Reporting a vulnerability *described by* CVE data in this database

This project does not manage disclosure for vulnerabilities in third-party
software. To report or discuss a vulnerability that a CVE record here
describes, contact the vendor or the CNA credited on that CVE's page.
