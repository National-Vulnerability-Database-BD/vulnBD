# Data Attribution

This project does not create vulnerability data. It ingests, normalizes, and
indexes data published by authoritative third parties, and always preserves
where each field came from (`sources` / `primarySource` on every record, and
per-field `source` tags on CVSS metrics, CWE entries, references, and
credits).

## CVE Program (cve.org)

Primary source. CVE Record data is produced by CVE Numbering Authorities
(CNAs) and published by the CVE Program. This project consumes it via the
Program's official GitHub mirror, [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5),
using its `cves/deltaLog.json` change feed for incremental updates.

- Terms of use: https://www.cve.org/Legal/TermsOfUse
- CVE Record data is made available under **CC0 1.0** by MITRE / the CVE Program.
- "CVE" and the CVE logo are trademarks of The MITRE Corporation.

**This project is not affiliated with, endorsed by, or officially connected
to MITRE or the CVE Program.**

## CISA Known Exploited Vulnerabilities (KEV) Catalog

Optional enrichment only. When present, a CVE record's `exploit.kev` field is
populated strictly from CISA's published catalog and is never inferred.

- Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **This project is not affiliated with, endorsed by, or officially connected
  to the Cybersecurity and Infrastructure Security Agency (CISA).**

## No fabricated data

Per the project's implementation rules (see `AGENTS.md` / repository
conventions), no CVSS score, CWE classification, affected-version range,
exploit status, or reference is ever invented. Where a source does not
supply a field, this project stores `null` or an empty array rather than a
guess.

## Adding a new source

See `scripts/fetch/types.ts` for the `SourceAdapter` interface. Every new
adapter must:

1. Tag every field it contributes with its own `SourceId`.
2. Never overwrite a more authoritative source's data without preserving
   provenance.
3. Be documented here with its terms of use before being merged.
