import type { CveRecord } from "../../src/types/cve.js";
import { isValidCvssVector } from "../utils/cvss.js";

export interface ValidationIssue {
  cveId: string;
  field: string;
  message: string;
  severity: "error" | "warning";
}

const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;
const CWE_ID_RE = /^CWE-\d+$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function isValidUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/** Validates a single normalized record. Pure — no I/O — so it's cheap to unit test exhaustively. */
export function validateRecord(record: CveRecord): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const err = (field: string, message: string) => issues.push({ cveId: record.id, field, message, severity: "error" });
  const warn = (field: string, message: string) => issues.push({ cveId: record.id, field, message, severity: "warning" });

  if (!CVE_ID_RE.test(record.id)) err("id", `"${record.id}" does not match CVE-YYYY-NNNN+`);

  if (!["PUBLISHED", "REJECTED", "WITHDRAWN", "RESERVED", "UNKNOWN"].includes(record.state)) {
    err("state", `unrecognized state "${record.state}"`);
  }

  for (const [field, value] of [
    ["published", record.published],
    ["lastModified", record.lastModified],
    ["withdrawn", record.withdrawn],
  ] as const) {
    if (value !== null && !ISO_DATE_RE.test(value)) err(field, `"${value}" is not a valid ISO-8601 timestamp`);
  }

  if (record.state === "WITHDRAWN" && !record.withdrawn) warn("withdrawn", "state is WITHDRAWN but no withdrawn date is set");

  if (record.published && record.lastModified) {
    if (new Date(record.lastModified).getTime() < new Date(record.published).getTime()) {
      warn("lastModified", "lastModified is earlier than published");
    }
  }

  for (const [key, metric] of Object.entries(record.cvss)) {
    if (!metric) continue;
    if (!isValidCvssVector(metric.vectorString)) err(`cvss.${key}.vectorString`, `invalid vector "${metric.vectorString}"`);
    if (metric.baseScore < 0 || metric.baseScore > 10) err(`cvss.${key}.baseScore`, `score ${metric.baseScore} out of range 0-10`);
  }

  if (record.severity.cvss !== null && (record.severity.cvss < 0 || record.severity.cvss > 10)) {
    err("severity.cvss", `score ${record.severity.cvss} out of range 0-10`);
  }

  for (const cwe of record.cwe) {
    if (!CWE_ID_RE.test(cwe.cweId)) err("cwe", `invalid CWE id "${cwe.cweId}"`);
  }

  for (const ref of record.references) {
    if (!isValidUrl(ref.url)) err("references", `invalid/unsafe reference URL "${ref.url}"`);
  }

  for (const aff of record.affected) {
    if (!aff.vendor) warn("affected.vendor", "missing vendor name");
    if (!aff.product) warn("affected.product", "missing product name");
  }

  if (record.state === "PUBLISHED" && !record.description && !record.summary) {
    warn("description", "published record has no description or summary");
  }

  // Defends the repo against pathological upstream payloads bloating history.
  const approxBytes = Buffer.byteLength(JSON.stringify(record), "utf-8");
  if (approxBytes > 2_000_000) err("record", `record is ${approxBytes} bytes — suspiciously large, refusing to store`);

  return issues;
}

export interface ValidationSummary {
  recordsChecked: number;
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
}

export function validateRecords(records: CveRecord[]): ValidationSummary {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];
  const seenIds = new Set<string>();

  for (const record of records) {
    if (seenIds.has(record.id)) {
      errors.push({ cveId: record.id, field: "id", message: "duplicate CVE ID within the same batch", severity: "error" });
    }
    seenIds.add(record.id);

    for (const issue of validateRecord(record)) {
      (issue.severity === "error" ? errors : warnings).push(issue);
    }
  }

  return { recordsChecked: records.length, errors, warnings };
}
