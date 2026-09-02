# BD Vuln Database

Bangladesh's open, community-run CVE (Common Vulnerabilities and Exposures)
database and search website — built to run **entirely on GitHub**. No
server, no hosted database, no paid API. GitHub Actions ingests and
normalizes vulnerability data on a schedule; the data is committed straight
into this repository as newline-delimited JSON; GitHub Pages serves a fast,
static search interface built on top of it.

> Want to run your own mirror? Fork this repo and edit `config/site.ts` —
> nothing in the codebase hardcodes a username or repository name, so it
> rebrands and repoints itself from that one file.

---

## Table of contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Data format](#data-format)
- [Quick start](#quick-start)
- [Development](#development)
- [Data ingestion](#data-ingestion)
- [Updating CVEs](#updating-cves)
- [Search architecture](#search-architecture)
- [GitHub Pages deployment](#github-pages-deployment)
- [GitHub Actions](#github-actions)
- [API / static data access](#api--static-data-access)
- [Contributing](#contributing)
- [Data sources](#data-sources)
- [Licensing](#licensing)
- [Troubleshooting](#troubleshooting)

## Overview

```
CVE Program / CISA KEV  ->  GitHub Actions  ->  Normalize + Validate  ->
data/YYYY/MM.jsonl (committed to git)  ->  Build indexes  ->  Astro static
build  ->  GitHub Pages  ->  Search, browse, CVE detail pages, statistics
```

The repository **is** the database. There's no export step and no
synchronization to worry about — what you see in `data/` is exactly what the
website serves, byte for byte.

## Architecture

```
/
├── .github/workflows/     update-cves.yml, build.yml, deploy.yml
├── data/YYYY/MM.jsonl     the database — one JSON record per line
├── index/                 generated: cve-index.json, search shards,
│                          year/severity/CWE/vendor indexes, statistics.json,
│                          metadata.json
├── scripts/
│   ├── fetch/             source adapters (cve.org, cisa-kev, ...)
│   ├── normalize/         raw upstream JSON -> our schema (pure functions)
│   ├── validate/          schema + integrity checks
│   ├── index/             builds every index/statistics file
│   ├── utils/             JSONL I/O, CVSS helpers
│   └── ingest.ts          orchestrates fetch -> normalize -> validate -> write
├── src/
│   ├── pages/             Astro routes (homepage, search, /cve/[id], ...)
│   ├── components/        Astro + React components
│   ├── layouts/           base HTML layout
│   ├── lib/                build-time data loaders, formatting helpers
│   └── types/cve.ts       the normalized schema (source of truth)
├── config/site.ts         all deployment config — no hardcoded repo name
└── tests/                 vitest suite mirroring scripts/
```

**Stack:** TypeScript (strict mode), Astro (static output) with a React
island for client-side search/browse, Tailwind CSS v4, MiniSearch for
in-browser full-text search, Vitest for testing. Node scripts (run via
`tsx`, no separate compile step) handle all data processing.

## Data format

The database lives at `data/YYYY/MM.jsonl` — one JSON object per line, sorted
by CVE ID, one file per calendar month **of the CVE's publication date**.

```
data/2026/01.jsonl
data/2026/02.jsonl
...
```

Each line is one normalized record matching `src/types/cve.ts`
(`CveRecord`). The schema is versioned (`schemaVersion` field, currently
`1`) and deliberately does **not** mirror any single upstream feed — every
source adapter normalizes into this shape, with per-field source
attribution preserved (see `sources` / `primarySource` on each record, and
`source` on individual CVSS metrics, CWE entries, references, and credits).

An ingestion run only rewrites the month files it actually touched — it
never rewrites the entire historical dataset. Writes are atomic
(temp-file-then-rename) and idempotent: running the pipeline twice against
identical source data produces byte-identical output.

If a single month's file ever gets too large for comfortable diffs, the
reader abstraction (`scripts/utils/jsonl.ts`) already supports splitting it
into `data/YYYY/MM/part-01.jsonl`, `part-02.jsonl`, ... transparently — no
application code needs to change.

## Quick start

```bash
git clone https://github.com/0xROI/nvdbd.git
cd nvdbd
npm install
npm run dev
```

That's it — `npm run dev` starts a local dev server against whatever data is
already in `data/` (the repository ships with real seed data fetched from
the CVE Program's GitHub mirror so it works out of the box).

## Development

| Command | What it does |
|---|---|
| `npm run dev` | Local dev server with hot reload |
| `npm run build` | Full production pipeline: validate -> index -> copy-index -> `astro build` |
| `npm run preview` | Serve the production build locally |
| `npm run fetch` | Ingest new/updated CVEs (see below) |
| `npm run validate` | Validate every record currently on disk |
| `npm run index` | Rebuild `index/*.json` from `data/` |
| `npm run cve -- CVE-2026-12345` | Print one normalized record to stdout |
| `npm test` | Run the Vitest suite |

## Data ingestion

```bash
npm run fetch                 # incremental, since the last recorded update
npm run fetch -- --limit=1000 # cap how many CVEs this run pulls
npm run fetch -- --full       # ignore the incremental cursor
```

Ingestion (`scripts/ingest.ts`) runs the full pipeline:

1. **Fetch** — the `cve.org` adapter (`scripts/fetch/cve-org.ts`) reads
   `cves/deltaLog.json` from the CVE Program's official GitHub mirror,
   [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) — an
   append-only log of exactly which CVE records were created or updated
   since the previous run. This is what makes incremental daily updates
   possible without diffing the whole dataset.
2. **Normalize** — `scripts/normalize/cve-org.ts` converts each raw CVE
   JSON 5.x record into our schema. Pure function, no I/O, fully unit
   tested (`tests/normalization/`).
3. **Validate** — `scripts/validate/validate.ts` checks CVE ID format,
   dates, CVSS ranges/vectors, CWE format, reference URL safety, duplicate
   IDs, and record size, before anything is written to disk.
4. **Merge + write** — records are merged into their destination
   `data/YYYY/MM.jsonl` by CVE ID (new CVE -> append, existing CVE -> replace
   in place). Only files that actually changed are rewritten.

Adding a new source means implementing the `SourceAdapter` interface
(`scripts/fetch/types.ts`) — see `CONTRIBUTING.md`.

### Withdrawn / rejected CVEs

`state` is preserved exactly as the source reports it
(`PUBLISHED` / `REJECTED` / `WITHDRAWN` / `RESERVED` / `UNKNOWN`).
Rejected/withdrawn records are never deleted — they stay in the database
with their state clearly shown, since a CVE ID disappearing silently is
itself useful information.

## Updating CVEs

In production, `.github/workflows/update-cves.yml` runs on a daily schedule
(and via manual `workflow_dispatch`) and performs: fetch -> validate -> index
-> checksum -> test -> commit (only if something changed) -> push -> trigger
the deploy workflow. Commits use the format:

```
data: update CVE database 2026-08-26
```

No commit is created when a run finds no changes.

## Historical backfill

The daily update job only pulls *recent* changes — it's built for staying
current, not for populating decades of history. To backfill older CVEs
(1999 through whenever your `data/` currently starts), use `npm run backfill`
instead, which downloads a full snapshot of the CVE Program's mirror and
extracts specific years directly:

```bash
npm run backfill -- --years=1999-2005     # a range
npm run backfill -- --years=2015,2016     # a list
npm run backfill -- --years=2020          # a single year
npm run backfill && npm run validate && npm run index   # then rebuild indexes
```

This is safe to run repeatedly, including with overlapping years — matching
CVE IDs are simply overwritten in place with the latest source data, never
duplicated.

**From GitHub Actions (no local machine needed):** go to **Actions ->
Backfill historical CVEs -> Run workflow**, enter a year or range (e.g.
`1999-2010`), and it runs the same tool on GitHub's infrastructure, commits
the result, and triggers a redeploy — nothing to install locally.

Each run downloads the CVE Program's full repository snapshot once
(~150-250 MB) before extracting just the years you asked for, so backfilling
a handful of years at a time is efficient; backfilling every year since 1999
in one run works too, but expect it to take a while and produce a large
single commit — doing it in a few batches (e.g. by decade) is usually more
manageable to review.

## Search architecture

Search runs **entirely client-side** against a compact index — the browser
never downloads the full JSONL database:

- `index/cve-index.json` — one lightweight entry per CVE (severity, CVSS,
  short summary, dates) used by the browse page.
- `index/search-index/<year>.json` — one shard per year of richer search
  documents (summary, description, vendors, products, CWE). The search page
  loads the 3 most recent years up front and fetches additional years
  on demand when you filter by year — so search stays fast even as the
  database grows into the hundreds of thousands of records.
- Full-text matching, fuzzy matching, and relevance ranking are handled by
  [MiniSearch](https://github.com/lucaong/minisearch) in the browser.
- Exact/partial CVE ID lookup (`CVE-2026-12345`, `CVE-2026`), vendor/CWE
  filters, and `vendor:x severity:y` advanced syntax are all supported —
  see `src/components/SearchWidget.tsx`.
- Filters and query state are reflected in the URL, so searches are
  shareable/bookmarkable (`/search?q=apache&severity=critical`).

Statistics and per-CWE/vendor/year pages are computed **at build time**
(`scripts/index/build-index.ts` -> `index/statistics.json`), so nothing
crunches the dataset in the visitor's browser.

## GitHub Pages deployment

`.github/workflows/deploy.yml` builds and deploys on every push to `main`
(and via manual dispatch). It uses `actions/deploy-pages`, so make sure
**Settings -> Pages -> Source** is set to **GitHub Actions** in your repo.

The site correctly handles being served from a repository subpath
(`https://username.github.io/cve-db/`) — `config/site.ts` infers the right
`base` path automatically from `GITHUB_REPOSITORY` at build time. If your
repo is named `<username>.github.io`, or you set a `SITE_CNAME` repository
variable for a custom domain, it serves from the root instead.

To use a custom domain: set a repository variable named `SITE_CNAME` (e.g.
`cve.example.com`) under **Settings -> Secrets and variables -> Actions ->
Variables**, and add a `CNAME` file via GitHub Pages settings as usual.

## GitHub Actions

| Workflow | Trigger | Does |
|---|---|---|
| `update-cves.yml` | daily cron + manual | fetch, validate, index, checksum, test, commit, push, trigger deploy |
| `backfill.yml` | manual only | historical backfill of specific years, then same validate/index/commit/deploy chain |
| `build.yml` | pull requests | validate, test, build — no deploy, just a CI gate |
| `deploy.yml` | push to `main` + manual | build and publish to GitHub Pages |

No API keys or secrets are required for any of these — the CVE Program's
GitHub mirror and CISA's KEV feed are both public.

## API / static data access

Every CVE has a machine-readable JSON endpoint at build time:

```
GET /cve/CVE-2026-12345.json
```

```json
{
  "id": "CVE-2026-12345",
  "state": "PUBLISHED",
  "severity": { "overall": "CRITICAL", "cvss": 9.8 },
  "cvss": { "v3_1": { "vectorString": "CVSS:3.1/AV:N/...", "baseScore": 9.8 } }
}
```

The generated indexes are also public static assets, useful if you want to
build your own tooling against this mirror without cloning the whole repo:

- `/index/cve-index.json` — every CVE ID -> lightweight summary
- `/index/search-index/<year>.json` — full search documents for one year
- `/index/statistics.json` — precomputed aggregate statistics
- `/index/metadata.json` — record counts, per-source freshness, schema version

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Short version: `npm install`,
make your change, `npm test`, `npm run build`, open a PR. Adding a new data
source has its own section in there.

## Data sources

See [ATTRIBUTION.md](./ATTRIBUTION.md) for full details, terms of use, and
what this project does and doesn't claim about the data. In short:
CVE Records come from the CVE Program via its official GitHub mirror;
CISA's KEV catalog is used only as optional, explicitly-attributed
enrichment. Nothing is ever fabricated — a missing field is `null` or `[]`,
never a guess.

## Licensing

Project code: MIT (see [LICENSE](./LICENSE)). CVE data: redistributed under
the CVE Program's published terms (CC0 1.0) — see
[ATTRIBUTION.md](./ATTRIBUTION.md). This project is an independent
community mirror, not affiliated with MITRE, the CVE Program, NVD, or CISA.

## Troubleshooting

**`npm run build` fails on `validate`.** Something in `data/` doesn't pass
schema validation — the output tells you which CVE ID and field. This is
usually a sign of a bug in a normalizer, not bad luck; please open an issue
with the CVE ID.

**The site 404s on every CVE page after deploying to Pages.** Check that
`config/site.ts`'s inferred `basePath` matches how your repo is actually
served — this is automatic for standard Project Pages and User/Org Pages
setups, but if you're doing something unusual (e.g. serving from a
non-root path on a custom domain), set `SITE_CNAME` or adjust
`config/site.ts` directly.

**Search returns nothing.** Confirm `public/index/` exists in your build
output (`npm run build` runs `copy-index` automatically) and that
`/index/search-index/manifest.json` is reachable at your deployed base
path.

**A CVE I know exists isn't in the database.** `npm run fetch` (the daily
workflow) only pulls *recent* changes from the CVE Program's delta log — it
does not reach back into history. For older CVEs, use the dedicated
backfill tool instead (see [Historical backfill](#historical-backfill)
below).
