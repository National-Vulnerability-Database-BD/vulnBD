import type { Severity } from "../../src/types/cve.js";

/** Maps a numeric CVSS base score to a qualitative severity per FIRST.org's published ranges (CVSS v3.x/v4.0). */
export function severityFromScore(score: number | null | undefined): Severity {
  if (score === null || score === undefined || Number.isNaN(score)) return "UNKNOWN";
  if (score === 0) return "NONE";
  if (score < 4) return "LOW";
  if (score < 7) return "MEDIUM";
  if (score < 9) return "HIGH";
  if (score <= 10) return "CRITICAL";
  return "UNKNOWN";
}

/** CVSS v2 uses a different, source-provided severity band; only used when a source didn't supply one. */
export function severityFromScoreV2(score: number | null | undefined): Severity {
  if (score === null || score === undefined || Number.isNaN(score)) return "UNKNOWN";
  if (score < 4) return "LOW";
  if (score < 7) return "MEDIUM";
  return "HIGH";
}

export function isValidCvssVector(vector: string): boolean {
  return /^CVSS:(2\.0|3\.0|3\.1|4\.0)\//.test(vector) || /^AV:[NALP]\//.test(vector);
}

/** Picks the single "best" score to surface as the record's headline severity/CVSS, preferring the newest spec version. */
export function pickOverallScore(cvss: {
  v4_0?: { baseScore: number; baseSeverity: Severity } | null;
  v3_1?: { baseScore: number; baseSeverity: Severity } | null;
  v3_0?: { baseScore: number; baseSeverity: Severity } | null;
  v2?: { baseScore: number; baseSeverity: Severity } | null;
}): { cvss: number | null; severity: Severity } {
  const preferred = cvss.v4_0 ?? cvss.v3_1 ?? cvss.v3_0 ?? cvss.v2 ?? null;
  if (!preferred) return { cvss: null, severity: "UNKNOWN" };
  return { cvss: preferred.baseScore, severity: preferred.baseSeverity };
}
