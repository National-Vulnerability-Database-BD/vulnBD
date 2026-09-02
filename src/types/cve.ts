/**
 * Normalized CVE record schema.
 *
 * This is OUR schema — a stable, source-agnostic representation that every
 * ingestion adapter (scripts/fetch/*) must normalize into. It intentionally
 * does not mirror any single upstream feed (CVE JSON 5.0, NVD API 2.0, OSV,
 * GHSA, ...) so that adding a new source never requires a breaking schema
 * change here.
 *
 * SCHEMA_VERSION must be bumped whenever a field is added, removed, or
 * changes meaning. It is stamped onto every record (`schemaVersion`) so
 * older records on disk remain self-describing.
 */

export const SCHEMA_VERSION = 1;

export type CveState = "PUBLISHED" | "REJECTED" | "WITHDRAWN" | "RESERVED" | "UNKNOWN";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";

/** Where a specific piece of data came from, so provenance is never lost. */
export type SourceId = "cve.org" | "nvd" | "osv" | "github-advisory" | "cisa-kev" | "unknown";

export interface CvssMetric {
  /** Raw vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" */
  vectorString: string;
  baseScore: number;
  baseSeverity: Severity;
  /** Optional decomposed metrics when the source provides them structured. */
  exploitabilityScore?: number | null;
  impactScore?: number | null;
  source: SourceId;
}

export interface CvssBlock {
  v2: CvssMetric | null;
  v3_0: CvssMetric | null;
  v3_1: CvssMetric | null;
  v4_0: CvssMetric | null;
}

export interface WeaknessRef {
  /** e.g. "CWE-79" */
  cweId: string;
  /** Human-readable name, if the source provided one; otherwise resolved from a local CWE catalog at render time. */
  name?: string | null;
  source: SourceId;
}

export interface VersionRange {
  /** Exact version string when known ("1.2.3"), otherwise null if only a range applies. */
  version: string | null;
  status: "affected" | "unaffected" | "unknown";
  versionStartIncluding?: string | null;
  versionStartExcluding?: string | null;
  versionEndIncluding?: string | null;
  versionEndExcluding?: string | null;
}

export interface AffectedProduct {
  vendor: string;
  product: string;
  /** CPE 2.3 URI when available. */
  cpe?: string | null;
  versions: VersionRange[];
  platforms?: string[];
}

export interface Reference {
  url: string;
  source: SourceId;
  /** Free-text tags from the upstream source, e.g. ["patch", "vendor-advisory"]. Never rendered as raw HTML. */
  tags: string[];
}

export type ExploitMaturity =
  | "known-exploited" // Confirmed via an authoritative catalog (e.g. CISA KEV)
  | "public-poc" // A public proof-of-concept reference exists
  | "advisory-only" // Only vendor/researcher advisories exist, no known code
  | "unknown";

export interface ExploitInfo {
  maturity: ExploitMaturity;
  /** Present only when maturity === "known-exploited", sourced from CISA KEV. */
  kev?: {
    dateAdded: string;
    dueDate: string | null;
    requiredAction: string | null;
    vulnerabilityName: string | null;
  } | null;
  /** References that are specifically exploit/PoC related (subset of `references`). */
  referenceUrls: string[];
  source: SourceId;
}

export interface Credit {
  name: string;
  type?: string | null;
  source: SourceId;
}

export interface Configuration {
  /** Free-text description of the applicability logic (e.g. "AND", "OR" node summary) preserved from the source. */
  operator: string | null;
  cpeMatch: {
    cpe: string;
    vulnerable: boolean;
    versionStartIncluding?: string | null;
    versionStartExcluding?: string | null;
    versionEndIncluding?: string | null;
    versionEndExcluding?: string | null;
  }[];
}

/** A single normalized CVE record — one line in a data/YYYY/MM.jsonl file. */
export interface CveRecord {
  schemaVersion: typeof SCHEMA_VERSION;

  id: string; // "CVE-2026-12345"
  state: CveState;

  summary: string | null;
  description: string | null;

  published: string | null; // ISO-8601
  lastModified: string | null; // ISO-8601
  withdrawn: string | null; // ISO-8601, null unless state === "WITHDRAWN"

  severity: {
    overall: Severity;
    /** The single "best" CVSS base score picked by preference order v4 > v3.1 > v3.0 > v2. */
    cvss: number | null;
  };

  cvss: CvssBlock;
  cwe: WeaknessRef[];
  affected: AffectedProduct[];
  configurations: Configuration[];
  references: Reference[];
  exploit: ExploitInfo | null;
  credits: Credit[];

  /** Every upstream source that contributed to this record, in the order they were merged. */
  sources: SourceId[];
  /** Which source is considered authoritative for `state`/`published`/`description` in this record. */
  primarySource: SourceId;
}

/** Lightweight entry stored in the master index (index/cve-index.json). */
export interface CveIndexEntry {
  year: number;
  month: number;
  state: CveState;
  severity: Severity;
  cvss: number | null;
  summary: string;
  published: string | null;
  lastModified: string | null;
}

export type CveIndex = Record<string, CveIndexEntry>;

/** A row in the flattened client-side search index (index/search-index/*.json). */
export interface SearchDocument {
  id: string;
  summary: string;
  description: string;
  vendors: string[];
  products: string[];
  cwe: string[];
  severity: Severity;
  cvss: number | null;
  year: number;
  published: string | null;
  lastModified: string | null;
}

export interface DatabaseMetadata {
  lastUpdate: string; // ISO-8601, generation timestamp — isolated here so data files stay deterministic
  schemaVersion: typeof SCHEMA_VERSION;
  records: number;
  years: Record<string, number>;
  sources: Partial<Record<SourceId, { lastFetched: string | null; recordsContributed: number }>>;
}

export interface StatisticsData {
  generatedAt: string;
  totalCves: number;
  byYear: Record<string, number>;
  byMonth: Record<string, number>; // "YYYY-MM" -> count
  bySeverity: Record<Severity, number>;
  byCwe: { cweId: string; name: string | null; count: number }[];
  byVendor: { vendor: string; count: number }[];
  byProduct: { vendor: string; product: string; count: number }[];
  cvssDistribution: { bucket: string; count: number }[]; // "0-1", "1-2", ... "9-10"
  recentlyAdded: string[]; // CVE IDs
  recentlyModified: string[]; // CVE IDs
}
