/**
 * Optional enrichment source: CISA's Known Exploited Vulnerabilities (KEV)
 * catalog. Unlike the other adapters, this doesn't produce new CveRecords
 * by itself — it produces a lookup table used to *enrich* records already
 * ingested from cve.org with an authoritative "known exploited" flag.
 *
 * We never infer exploitation ourselves (see docs/DATA_FORMAT.md §Exploit
 * information) — this is the only source allowed to set
 * `exploit.maturity === "known-exploited"`, and only because CISA is an
 * authoritative catalog, not our own inference.
 *
 * Not run automatically as part of the seed build in this environment
 * (cisa.gov is outside this sandbox's network allowlist), but is wired up
 * for use in GitHub Actions, which has unrestricted egress.
 */
import type { ExploitInfo } from "../../src/types/cve.js";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevEntry {
  cveID: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
}

interface KevCatalog {
  vulnerabilities: KevEntry[];
}

export async function fetchKevLookup(): Promise<Map<string, ExploitInfo>> {
  const res = await fetch(KEV_URL, { headers: { "User-Agent": "cve-db-ingest/1.0" } });
  if (!res.ok) throw new Error(`CISA KEV fetch failed: HTTP ${res.status}`);
  const catalog = (await res.json()) as KevCatalog;

  const lookup = new Map<string, ExploitInfo>();
  for (const entry of catalog.vulnerabilities ?? []) {
    if (!entry.cveID) continue;
    lookup.set(entry.cveID, {
      maturity: "known-exploited",
      kev: {
        dateAdded: entry.dateAdded ?? "",
        dueDate: entry.dueDate ?? null,
        requiredAction: entry.requiredAction ?? null,
        vulnerabilityName: entry.vulnerabilityName ?? null,
      },
      referenceUrls: [],
      source: "cisa-kev",
    });
  }
  return lookup;
}
