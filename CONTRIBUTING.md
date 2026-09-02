# Contributing

Thanks for considering a contribution. This project has two very different
kinds of surface area — please read the section that matches what you're
touching.

## Website / tooling code (`src/`, `scripts/`, `config/`)

1. `npm install`
2. `npm run dev` — local dev server
3. Make your change.
4. `npm test` — unit tests must pass
5. `npm run build` — the full pipeline (`validate` → `index` → `copy-index`
   → `astro build`) must succeed
6. Open a PR.

Code style: TypeScript strict mode, small focused modules, no giant files.
Prefer pure functions in `scripts/*` (fetch/normalize/validate/index) so
they stay easy to unit test — network and filesystem I/O should stay at the
edges (`scripts/fetch/*.ts`'s `fetch()` methods, `scripts/utils/jsonl.ts`).

## Adding a new data source

See `ATTRIBUTION.md` for the provenance rules every source must follow, and
`scripts/fetch/types.ts` for the `SourceAdapter` interface. In short:

- One file per source under `scripts/fetch/`.
- A pure `normalize()` function under `scripts/normalize/` that's unit
  testable without network access (see `tests/normalization/`).
- Never invent a field. Missing data is `null` or `[]`.
- Tag every contributed field with the source's `SourceId` so provenance is
  never lost when sources are merged.

## Reporting a bad or missing CVE record

This project does not edit CVE data directly — everything here is mirrored
and normalized from upstream sources (see `ATTRIBUTION.md`). If a record
looks wrong:

- If the *data itself* is wrong, the fix belongs upstream — please report it
  to the CNA or source listed in that record's "Data sources" panel.
- If our *normalization* of otherwise-correct upstream data is wrong (e.g. a
  parsing bug, a dropped field, a bad severity mapping), please open an
  issue here with the CVE ID and a link to the source record.

## Commit conventions

Data-only commits produced by the automated ingestion workflow follow the
format:

```
data: update CVE database 2026-08-26
```

Please use a normal descriptive message for code/doc changes.

## Code of conduct

Be respectful, assume good faith, and keep discussion focused on the
project. Harassment of any kind will result in removal from the project.
