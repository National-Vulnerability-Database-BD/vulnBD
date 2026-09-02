import { useEffect, useMemo, useRef, useState } from "react";
import MiniSearch from "minisearch";
import type { SearchDocument, Severity } from "../types/cve";

interface Props {
  basePath: string;
  initialQuery?: string;
  initialSeverity?: string;
  initialYear?: string;
}

interface Filters {
  severity: string;
  year: string;
  sort: "relevance" | "newest" | "oldest" | "cvss-desc" | "cvss-asc" | "modified";
}

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function parseAdvancedQuery(input: string): { text: string; vendor?: string; severity?: string } {
  const vendorMatch = input.match(/\bvendor:(\S+)/i);
  const severityMatch = input.match(/\bseverity:(\S+)/i);
  const text = input
    .replace(/\bvendor:\S+/i, "")
    .replace(/\bseverity:\S+/i, "")
    .trim();
  return {
    text,
    vendor: vendorMatch?.[1]?.toLowerCase(),
    severity: severityMatch?.[1]?.toUpperCase(),
  };
}

export default function SearchWidget({ basePath, initialQuery = "", initialSeverity = "", initialYear = "" }: Props) {
  const fromUrl = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
  const [query, setQuery] = useState(fromUrl?.get("q") ?? initialQuery);
  const [filters, setFilters] = useState<Filters>({
    severity: fromUrl?.get("severity") ?? initialSeverity,
    year: fromUrl?.get("year") ?? initialYear,
    sort: "relevance",
  });
  const [manifest, setManifest] = useState<{ years: number[]; counts: Record<string, number> } | null>(null);
  const [docs, setDocs] = useState<SearchDocument[]>([]);
  const [loadedYears, setLoadedYears] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const miniSearchRef = useRef<MiniSearch<SearchDocument> | null>(null);

  // Load the manifest, then the most relevant shard(s) first so results
  // appear fast without ever downloading the whole database up front.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const res = await fetch(`${basePath}/index/search-index/manifest.json`);
      const m = await res.json();
      if (cancelled) return;
      setManifest(m);

      const ms = new MiniSearch<SearchDocument>({
        fields: ["id", "summary", "description", "vendors", "products", "cwe"],
        storeFields: ["id", "summary", "vendors", "products", "cwe", "severity", "cvss", "year", "published", "lastModified"],
        searchOptions: { boost: { id: 4, summary: 2 }, fuzzy: 0.15, prefix: true },
        extractField: (doc, field) => {
          const value = (doc as unknown as Record<string, unknown>)[field];
          return Array.isArray(value) ? value.join(" ") : String(value ?? "");
        },
      });
      miniSearchRef.current = ms;

      const yearsToLoad: number[] = filters.year ? [Number(filters.year)] : m.years.slice(0, 3);
      for (const year of yearsToLoad) {
        const shardRes = await fetch(`${basePath}/index/search-index/${year}.json`);
        const shard: SearchDocument[] = await shardRes.json();
        if (cancelled) return;
        ms.addAll(shard);
        setDocs((prev) => [...prev, ...shard]);
        setLoadedYears((prev) => new Set(prev).add(year));
      }
      setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [basePath]);

  // Lazily load additional year shards when the user picks a year filter
  // that hasn't been fetched yet.
  useEffect(() => {
    if (!filters.year || !manifest) return;
    const year = Number(filters.year);
    if (loadedYears.has(year)) return;
    let cancelled = false;
    (async () => {
      const res = await fetch(`${basePath}/index/search-index/${year}.json`);
      const shard: SearchDocument[] = await res.json();
      if (cancelled) return;
      miniSearchRef.current?.addAll(shard);
      setDocs((prev) => [...prev, ...shard]);
      setLoadedYears((prev) => new Set(prev).add(year));
    })();
    return () => {
      cancelled = true;
    };
  }, [filters.year, manifest, basePath, loadedYears]);

  const { text, vendor, severity: severityFromQuery } = useMemo(() => parseAdvancedQuery(query), [query]);

  const results = useMemo(() => {
    const ms = miniSearchRef.current;
    let matched: SearchDocument[];

    const cveIdMatch = text.toUpperCase().match(/^CVE-\d{4}(-\d*)?$/);
    if (cveIdMatch) {
      matched = docs.filter((d) => d.id.startsWith(text.toUpperCase()));
    } else if (text.length > 0 && ms) {
      const found = ms.search(text);
      const byId = new Map(docs.map((d) => [d.id, d]));
      matched = found.map((r) => byId.get(r.id)).filter((d): d is SearchDocument => Boolean(d));
    } else {
      matched = docs;
    }

    const effectiveSeverity = (filters.severity || severityFromQuery || "").toUpperCase();
    if (effectiveSeverity) matched = matched.filter((d) => d.severity === effectiveSeverity);
    if (vendor) matched = matched.filter((d) => d.vendors.some((v) => v.toLowerCase().includes(vendor)));
    if (filters.year) matched = matched.filter((d) => d.year === Number(filters.year));

    const sorted = [...matched];
    switch (filters.sort) {
      case "newest":
        sorted.sort((a, b) => (b.published ?? "").localeCompare(a.published ?? ""));
        break;
      case "oldest":
        sorted.sort((a, b) => (a.published ?? "").localeCompare(b.published ?? ""));
        break;
      case "cvss-desc":
        sorted.sort((a, b) => (b.cvss ?? -1) - (a.cvss ?? -1));
        break;
      case "cvss-asc":
        sorted.sort((a, b) => (a.cvss ?? 11) - (b.cvss ?? 11));
        break;
      case "modified":
        sorted.sort((a, b) => (b.lastModified ?? "").localeCompare(a.lastModified ?? ""));
        break;
      default:
        break; // relevance order from MiniSearch (or insertion order if no query)
    }

    return sorted.slice(0, 100);
  }, [docs, text, vendor, severityFromQuery, filters]);

  // Keep the URL bookmarkable/shareable.
  useEffect(() => {
    const params = new URLSearchParams();
    if (query) params.set("q", query);
    if (filters.severity) params.set("severity", filters.severity);
    if (filters.year) params.set("year", filters.year);
    const url = `${window.location.pathname}${params.toString() ? "?" + params.toString() : ""}`;
    window.history.replaceState(null, "", url);
  }, [query, filters]);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-center">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="CVE-2026-12345, apache, CWE-79, vendor:microsoft severity:critical…"
          className="flex-1 border border-border bg-surface px-3 py-2.5 font-mono text-sm text-text placeholder:text-muted focus:border-accent"
          aria-label="Search CVEs"
        />
        <div className="flex flex-wrap gap-2">
          <select
            value={filters.severity}
            onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}
            className="border border-border bg-surface px-2 py-2 font-mono text-xs uppercase text-text"
            aria-label="Filter by severity"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={filters.year}
            onChange={(e) => setFilters((f) => ({ ...f, year: e.target.value }))}
            className="border border-border bg-surface px-2 py-2 font-mono text-xs text-text"
            aria-label="Filter by year"
          >
            <option value="">All years</option>
            {manifest?.years.map((y) => (
              <option key={y} value={y}>
                {y}
              </option>
            ))}
          </select>
          <select
            value={filters.sort}
            onChange={(e) => setFilters((f) => ({ ...f, sort: e.target.value as Filters["sort"] }))}
            className="border border-border bg-surface px-2 py-2 font-mono text-xs text-text"
            aria-label="Sort results"
          >
            <option value="relevance">Relevance</option>
            <option value="newest">Newest</option>
            <option value="oldest">Oldest</option>
            <option value="cvss-desc">Highest CVSS</option>
            <option value="cvss-asc">Lowest CVSS</option>
            <option value="modified">Last modified</option>
          </select>
        </div>
      </div>

      {loading && <p className="font-mono text-xs text-muted">Loading search index…</p>}

      {!loading && results.length === 0 && (
        <div className="border border-border bg-surface p-8 text-center">
          <p className="font-mono text-sm text-text">No results.</p>
          <p className="mt-1 text-sm text-muted">Try a different CVE ID, keyword, vendor, or CWE — or widen your filters.</p>
        </div>
      )}

      <ul className="space-y-3">
        {results.map((doc) => (
          <li key={doc.id}>
            <a href={`${basePath}/cve/${doc.id}`} className="group block border border-border bg-surface p-4 transition-colors hover:border-accent">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-semibold group-hover:text-accent">{doc.id}</span>
                <SeverityChip severity={doc.severity} cvss={doc.cvss} />
                {doc.cwe.slice(0, 2).map((c) => (
                  <span key={c} className="border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted">
                    {c}
                  </span>
                ))}
                {doc.vendors[0] && <span className="text-[11px] text-muted">{doc.vendors[0]}</span>}
              </div>
              {doc.summary && <p className="mt-2 line-clamp-2 text-sm text-muted">{doc.summary}</p>}
              <div className="mt-3 flex gap-4 font-mono text-[11px] text-muted">
                <span>Published {doc.published ? new Date(doc.published).toLocaleDateString() : "Unknown"}</span>
              </div>
            </a>
          </li>
        ))}
      </ul>

      {!loading && manifest && !filters.year && manifest.years.length > 3 && (
        <p className="text-center font-mono text-xs text-muted">
          Showing results from the {Math.min(3, manifest.years.length)} most recent years. Pick a year above to search further back.
        </p>
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
