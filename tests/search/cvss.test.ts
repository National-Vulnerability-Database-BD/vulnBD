import { describe, expect, it } from "vitest";
import { isValidCvssVector, pickOverallScore, severityFromScore } from "../../scripts/utils/cvss.js";

describe("severityFromScore", () => {
  it.each([
    [0, "NONE"],
    [1.2, "LOW"],
    [3.9, "LOW"],
    [4.0, "MEDIUM"],
    [6.9, "MEDIUM"],
    [7.0, "HIGH"],
    [8.9, "HIGH"],
    [9.0, "CRITICAL"],
    [10, "CRITICAL"],
  ])("maps score %s to %s", (score, expected) => {
    expect(severityFromScore(score)).toBe(expected);
  });

  it("returns UNKNOWN for null/undefined", () => {
    expect(severityFromScore(null)).toBe("UNKNOWN");
    expect(severityFromScore(undefined)).toBe("UNKNOWN");
  });
});

describe("isValidCvssVector", () => {
  it("accepts valid v3.1 and v4.0 vectors", () => {
    expect(isValidCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(true);
    expect(isValidCvssVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBe(true);
  });

  it("rejects garbage", () => {
    expect(isValidCvssVector("not-a-vector")).toBe(false);
    expect(isValidCvssVector("")).toBe(false);
  });
});

describe("pickOverallScore", () => {
  it("prefers v4.0 over older versions", () => {
    const result = pickOverallScore({
      v2: { baseScore: 5, baseSeverity: "MEDIUM" },
      v3_1: { baseScore: 6, baseSeverity: "MEDIUM" },
      v4_0: { baseScore: 9, baseSeverity: "CRITICAL" },
    });
    expect(result).toEqual({ cvss: 9, severity: "CRITICAL" });
  });

  it("falls back through the chain when newer versions are absent", () => {
    const result = pickOverallScore({ v2: { baseScore: 5, baseSeverity: "MEDIUM" } });
    expect(result).toEqual({ cvss: 5, severity: "MEDIUM" });
  });

  it("returns nulls when no CVSS data exists at all", () => {
    expect(pickOverallScore({})).toEqual({ cvss: null, severity: "UNKNOWN" });
  });
});
