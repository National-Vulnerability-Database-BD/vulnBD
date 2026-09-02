const METRIC_LABELS: Record<string, string> = {
  AV: "Attack Vector",
  AC: "Attack Complexity",
  AT: "Attack Requirements",
  PR: "Privileges Required",
  UI: "User Interaction",
  S: "Scope",
  C: "Confidentiality Impact",
  I: "Integrity Impact",
  A: "Availability Impact",
  VC: "Confidentiality Impact (Vulnerable System)",
  VI: "Integrity Impact (Vulnerable System)",
  VA: "Availability Impact (Vulnerable System)",
  SC: "Confidentiality Impact (Subsequent System)",
  SI: "Integrity Impact (Subsequent System)",
  SA: "Availability Impact (Subsequent System)",
  E: "Exploit Maturity",
  RL: "Remediation Level",
  RC: "Report Confidence",
  Au: "Authentication",
};

const VALUE_LABELS: Record<string, string> = {
  N: "Network",
  A: "Adjacent",
  L: "Local",
  P: "Physical",
  H: "High",
  M: "Medium",
  R: "Required",
  U: "Unchanged/None",
  C: "Changed",
  X: "Not Defined",
  F: "Functional",
  W: "Workaround",
  T: "Temporary Fix",
  O: "Official Fix",
  UR: "Unreported",
  UC: "Unconfirmed",
  UK: "Unknown",
  CR: "Confirmed",
  S: "Single",
  m: "Multiple",
  Y: "Yes",
};

export interface ParsedCvssMetric {
  code: string;
  label: string;
  value: string;
  valueLabel: string;
}

export function parseCvssVector(vector: string): { version: string; metrics: ParsedCvssMetric[] } {
  const parts = vector.split("/");
  let version = "Unknown";
  const metrics: ParsedCvssMetric[] = [];

  for (const part of parts) {
    if (part.startsWith("CVSS:")) {
      version = part.replace("CVSS:", "");
      continue;
    }
    const [code, value] = part.split(":");
    if (!code || !value) continue;
    metrics.push({
      code,
      label: METRIC_LABELS[code] ?? code,
      value,
      valueLabel: VALUE_LABELS[value] ?? value,
    });
  }

  return { version, metrics };
}
