import type { Severity } from "../types/cve";

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  NONE: "None",
  UNKNOWN: "Unknown",
};

/** Tailwind class fragments — text/background colors, never the only signal (always paired with the text label). */
export const SEVERITY_CLASSES: Record<Severity, { bg: string; text: string; border: string; dot: string }> = {
  CRITICAL: { bg: "bg-critical/15", text: "text-critical", border: "border-critical/30", dot: "bg-critical" },
  HIGH: { bg: "bg-high/15", text: "text-high", border: "border-high/30", dot: "bg-high" },
  MEDIUM: { bg: "bg-medium/15", text: "text-medium", border: "border-medium/30", dot: "bg-medium" },
  LOW: { bg: "bg-low/15", text: "text-low", border: "border-low/30", dot: "bg-low" },
  NONE: { bg: "bg-muted/15", text: "text-muted", border: "border-muted/30", dot: "bg-muted" },
  UNKNOWN: { bg: "bg-muted/15", text: "text-muted", border: "border-muted/30", dot: "bg-muted" },
};

export function formatDate(iso: string | null): string {
  if (!iso) return "Unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Unknown";
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

export function formatDateTime(iso: string | null): string {
  if (!iso) return "Unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Unknown";
  return d.toLocaleString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
}
