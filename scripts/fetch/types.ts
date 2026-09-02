import type { CveRecord } from "../../src/types/cve.js";

/**
 * Contract every ingestion source must implement. Keeping this narrow means
 * adding a new source (OSV, GitHub Security Advisories, a vendor feed, ...)
 * never touches the storage/index/validate/build layers.
 */
export interface SourceAdapter<TRaw = unknown> {
  id: string;

  /** Fetches raw upstream data. Should honor `since` for incremental updates when the source supports it. */
  fetch(opts: { since?: Date | null; limit?: number }): Promise<TRaw[]>;

  /** Normalizes one raw upstream item into our schema, or null to skip it (e.g. unparseable record). */
  normalize(raw: TRaw): CveRecord | null;
}

export interface FetchStats {
  source: string;
  fetched: number;
  normalized: number;
  skipped: number;
}
