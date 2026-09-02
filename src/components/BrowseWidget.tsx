import { useEffect, useMemo, useState } from "react";
import type { CveIndex, Severity } from "../types/cve";

interface Props {
  basePath: string;
}

const PAGE_SIZE = 30;
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function readParams() {
  const p = new URLSearchParams(window.location.search);
  return {
    severity: p.get("severity") ?? "",
    year: p.get("year") ?? "",
    sort: p.get("sort") ?? "newest",
    page: Number(p.get("page") ?? "1") || 1,
  };
}

export default function BrowseWidget({ basePath }: Props) {
  const [index, setIndex] = useState<CveIndex | null>(null);
  const [state, setState] = useState(() => (typeof window !== "undefined" ? readParams() : { severity: "", year: "", sort: "newest", page: 1 }));

  useEffect(() => {
    let cancelled = false;
    fetch(`${basePath}/index/cve-index.json`)
      .then((r) => r.json())
      .then((d) => {
        if (!cancelled) setIndex(d);
      });
    return () => {
      cancelled = true;
    };
  }, [basePath]);

  useEffect(() => {
    const p = new URLSearchParams();
    if (state.severity) p.set("severity", state.severity);
    if (state.year) p.set("year", state.year);
    if (state.sort !== "newest") p.set("sort", state.sort);
    if (state.page > 1) p.set("page", String(state.page));
    const qs = p.toString();
    window.history.replaceState(null, "", `${window.location.pathname}${qs ? "?" + qs : ""}`);
  }, [state]);

  const entries = useMemo(() => {
    if (!index) return [];
    let list = Object.entries(index).filter(([, e]) => e.state === "PUBLISHED");
    if (state.severity) list = list.filter(([, e]) => e.severity === state.severity);
    if (state.year) list = list.filter(([, e]) => String(e.year) === state.year);

    switch (state.sort) {
      case "oldest":
        list.sort((a, b) => (a[1].published ?? "").localeCompare(b[1].published ?? ""));
        break;
      case "cvss-desc":
        list.sort((a, b) => (b[1].cvss ?? -1) - (a[1].cvss ?? -1));
        break;
      case "cvss-asc":
        list.sort((a, b) => (a[1].cvss ?? 11) - (b[1].cvss ?? 11));
        break;
      case "modified":
        list.sort((a, b) => (b[1].lastModified ?? "").localeCompare(a[1].lastModified ?? ""));
        break;
      default:
        list.sort((a, b) => (b[1].published ?? "").localeCompare(a[1].published ?? ""));
    }
    return list;
  }, [index, state.severity, state.year, state.sort]);

  const years = useMemo(() => {
    if (!index) return [];
    return [...new Set(Object.values(index).map((e) => e.year))].sort((a, b) => b - a);
  }, [index]);

  const totalPages = Math.max(1, Math.ceil(entries.length / PAGE_SIZE));
  const safePage = Math.min(state.page, totalPages);
  const pageEntries = entries.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  if (!index) {
    return <p className="font-mono text-xs text-muted">Loading index…</p>;
  }

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <p className="text-sm text-muted">{new Intl.NumberFormat("en-US").format(entries.length)} published record{entries.length === 1 ? "" : "s"} match your filters.</p>
        <div className="flex flex-wrap gap-2">
          <select
            value={state.severity}
            onChange={(e) => setState((s) => ({ ...s, severity: e.target.value, page: 1 }))}
            className="border border-border bg-surface px-2 py-2 font-mono text-xs uppercase text-text"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select
            value={state.year}
            onChange={(e) => setState((s) => ({ ...s, year: e.target.value, page: 1 }))}
            className="border border-border bg-surface px-2 py-2 font-mono text-xs text-text"
          >
            <option value="">All years</option>
            {years.map((y) => (
              <option key={y} value={y}>{y}</option>
            ))}
          </select>
          <select
            value={state.sort}
            onChange={(e) => setState((s) => ({ ...s, sort: e.target.value, page: 1 }))}
            className="border border-border bg-surface px-2 py-2 font-mono text-xs text-text"
          >
            <option value="newest">Newest</option>
            <option value="oldest">Oldest</option>
            <option value="cvss-desc">Highest CVSS</option>
            <option value="cvss-asc">Lowest CVSS</option>
            <option value="modified">Last modified</option>
          </select>
        </div>
      </div>

      <div className="mt-6 space-y-3">
        {pageEntries.map(([id, e]) => (
          <a key={id} href={`${basePath}/cve/${id}`} className="group block border border-border bg-surface p-4 transition-colors hover:border-accent">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-semibold group-hover:text-accent">{id}</span>
              <SeverityChip severity={e.severity} cvss={e.cvss} />
            </div>
            {e.summary && <p className="mt-2 line-clamp-2 text-sm text-muted">{e.summary}</p>}
            <div className="mt-3 flex gap-4 font-mono text-[11px] text-muted">
              <span>Published {e.published ? new Date(e.published).toLocaleDateString() : "Unknown"}</span>
              {e.lastModified && <span>Modified {new Date(e.lastModified).toLocaleDateString()}</span>}
            </div>
          </a>
        ))}
        {pageEntries.length === 0 && <div className="border border-border bg-surface p-8 text-center text-sm text-muted">No CVEs match these filters.</div>}
      </div>

      {totalPages > 1 && (
        <nav className="mt-8 flex items-center justify-between font-mono text-xs" aria-label="Pagination">
          <button
            type="button"
            disabled={safePage <= 1}
            onClick={() => setState((s) => ({ ...s, page: safePage - 1 }))}
            className="border border-border px-3 py-2 hover:border-accent disabled:pointer-events-none disabled:opacity-40"
          >
            ← Previous
          </button>
          <span className="text-muted">Page {safePage} of {totalPages}</span>
          <button
            type="button"
            disabled={safePage >= totalPages}
            onClick={() => setState((s) => ({ ...s, page: safePage + 1 }))}
            className="border border-border px-3 py-2 hover:border-accent disabled:pointer-events-none disabled:opacity-40"
          >
            Next →
          </button>
        </nav>
      )}
    </div>
  );
}

function SeverityChip({ severity, cvss }: { severity: Severity; cvss: number | null }) {
  const classes: Record<Severity, string> = {
    CRITICAL: "bg-critical/15 text-critical border-critical/30",
    HIGH: "bg-high/15 text-high border-high/30",
    MEDIUM: "bg-medium/15 text-medium border-medium/30",
    LOW: "bg-low/15 text-low border-low/30",
    NONE: "bg-muted/15 text-muted border-muted/30",
    UNKNOWN: "bg-muted/15 text-muted border-muted/30",
  };
  return (
    <span className={`inline-flex items-center gap-1.5 border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase ${classes[severity]}`}>
      {severity}
      {cvss !== null && <span className="opacity-80">· {cvss.toFixed(1)}</span>}
    </span>
  );
}
