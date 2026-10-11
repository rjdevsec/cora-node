// Rule catalogue: hygiene (T1–T9, P1, P2, H1), backups (B1–B4), open risks (R1–R4) and recovery (D1–D4).
// Every check is deterministic: the same evidence always gives the same result.

const check = (id, perspective, name, failsWhen, group, level = "asset") => ({ id, perspective, name, fails_when: failsWhen, group, level });

export const CHECKS = Object.fromEntries([
  check("T1", "Technology", "Asset registered", "Asset found in discovery but not in the register", "inventory"),
  check("T2", "Technology", "Asset seen", "Registered asset absent from discovery, or not seen recently", "inventory"),
  check("T3", "Technology", "Categorisation aligned", "Asset criticality is lower than the service tier", "inventory"),
  check("T4", "Technology", "Patched within SLA", "Open vulnerability older than the SLA for its severity", "prevention"),
  check("T5", "Technology", "Supported software", "Operating system or database is end of life", "prevention"),
  check("T6", "Technology", "Antivirus installed", "No agent, or agent not reporting", "prevention"),
  check("T7", "Technology", "Antivirus signatures current", "Signature age exceeds the threshold", "prevention"),
  check("T8", "Technology", "Privileged accounts in PAM", "A local or service privileged account is not onboarded", "access"),
  check("T9", "Technology", "Logs in SIEM", "No log source, or no events within the threshold period", "detection"),
  check("B1", "Recovery", "Backup scheduled", "No active backup job covers the asset", "backup"),
  check("B2", "Recovery", "Backup succeeding", "The last successful backup is older than its schedule allows", "backup"),
  check("B3", "Recovery", "Backup copy protected", "No immutable or offsite copy, so ransomware could destroy the backups", "backup"),
  check("B4", "Recovery", "Restore tested", "No passed restore test within the policy period, or the restore took longer than the tolerance", "backup"),
  check("P1", "Process", "Exception validity", "Exception is expired, unapproved, or lacks a compensating control", "process"),
  check("P2", "Process", "Patch SLA adherence", "Percentage patched within SLA is below the policy target", "process"),
  check("H1", "People", "Ownership assigned", "Asset or application has no named owner, or the owner has left", "people"),
  check("R4", "Open risk", "Gaps recorded as risks", "A failed hygiene check has no matching risk or exception", "risk"),
  check("R1", "Open risk", "Open risks within appetite", "An open risk rated above the appetite threshold is linked to the application or its assets", "risk", "application"),
  check("R2", "Open risk", "Risk treatment on time", "A treatment action is past its due date, or the risk has no owner", "risk", "application"),
  check("R3", "Open risk", "Risk acceptance valid", "An accepted risk lacks approval at the right level, or is past its review date", "risk", "application"),
  check("D1", "Recovery", "DR test performed", "No passed, full-scope DR test within the policy period", "recovery", "application"),
  check("D2", "Recovery", "Recovery time within tolerance", "Achieved recovery time exceeds the RTO or the service impact tolerance", "recovery", "application"),
  check("D3", "Recovery", "Data loss within objective", "Achieved data loss exceeds the recovery point objective", "recovery", "application"),
  check("D4", "Recovery", "DR issues closed", "Issues raised in the last DR test are still open past their due date", "recovery", "application"),
].map((c) => [c.id, c]));

export const CHECK_ORDER = Object.keys(CHECKS);
export const ASSET_CHECKS = CHECK_ORDER.filter((c) => CHECKS[c].level === "asset");
export const APP_CHECKS = CHECK_ORDER.filter((c) => CHECKS[c].level === "application");
export const HYGIENE_CHECKS = ASSET_CHECKS.filter((c) => c !== "R4");
export const PREVENTION = new Set(CHECK_ORDER.filter((c) => CHECKS[c].group === "prevention"));

export const STATUS_LABELS = { pass: "Pass", fail: "Fail", excepted: "Excepted", no_data: "No data", "n/a": "N/A" };

export const result = (checkId, status, detail, evidence = [], extra = {}) =>
  ({ check_id: checkId, status, raw_status: status, detail, evidence: evidence || [], ...extra });
