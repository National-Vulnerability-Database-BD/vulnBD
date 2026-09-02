/**
 * Central site configuration.
 *
 * Nothing in the app should hardcode the project name, GitHub username, or
 * repository path — everything reads from here (and, in turn, from
 * environment variables set by GitHub Actions / GitHub Pages).
 *
 * When forking this project, this is the only file you should need to edit
 * to rebrand and repoint the deployment.
 */

export interface SiteConfig {
  /** Human-readable project name. */
  name: string;
  /** Short tagline shown under the name. */
  description: string;
  /** "owner/repo" on GitHub, used for source links and Pages base path inference. */
  repository: string;
  /** URL path the site is served under, e.g. "/cve-db" for a Project Pages site, "/" for a custom domain or User/Org page. */
  basePath: string;
  /** Canonical site origin used for absolute URLs, sitemap, and SEO metadata. */
  siteUrl: string;
  /** GitHub Discussions/Issues URL for "report an issue" links. */
  issuesUrl: string;
  /** License identifier shown in the footer. */
  license: string;
}

function inferBasePath(): string {
  // GITHUB_REPOSITORY is provided automatically inside GitHub Actions,
  // e.g. "octocat/cve-db". A Project Pages site is served from
  // https://octocat.github.io/cve-db/, so the base path is "/cve-db".
  // A User/Org Pages repo (named "<owner>.github.io") or a custom domain
  // (CNAME present) is served from the root instead.
  const repo = process.env.GITHUB_REPOSITORY ?? "your-username/cve-db";
  const [owner, name] = repo.split("/");
  const isUserOrgPages = name?.toLowerCase() === `${owner?.toLowerCase()}.github.io`;
  const hasCustomDomain = process.env.SITE_CNAME && process.env.SITE_CNAME.length > 0;
  if (isUserOrgPages || hasCustomDomain) return "/";
  return `/${name ?? "cve-db"}`;
}

function inferSiteUrl(): string {
  if (process.env.SITE_CNAME) return `https://${process.env.SITE_CNAME}`;
  const repo = process.env.GITHUB_REPOSITORY ?? "your-username/cve-db";
  const [owner, name] = repo.split("/");
  const isUserOrgPages = name?.toLowerCase() === `${owner?.toLowerCase()}.github.io`;
  if (isUserOrgPages) return `https://${owner}.github.io`;
  return `https://${owner}.github.io/${name}`;
}

export const siteConfig: SiteConfig = {
  name: process.env.SITE_NAME ?? "BD Vuln Database",
  description:
    process.env.SITE_DESCRIPTION ??
    "Bangladesh's national vulnerability database and search engine for tracking software security issues affecting the country's technology ecosystem.",
  repository: process.env.GITHUB_REPOSITORY ?? "your-username/cve-db",
  basePath: inferBasePath(),
  siteUrl: inferSiteUrl(),
  issuesUrl: `https://github.com/${process.env.GITHUB_REPOSITORY ?? "your-username/cve-db"}/issues`,
  license: "CC0-1.0 (data) / MIT (code)",
};
