/*
 * Evidence sources: what each upload must contain, column mapping, storage and parsing.
 *
 * Every source is read through a column mapping (internal field -> header in the client's file), so the
 * client's export format does not need to match a template. Headers are auto-mapped using aliases; any
 * required field left unmapped must be mapped by the analyst before the file is used.
 *
 * INTEGRATION SEAM (CSV uploads today, API connectors in Phase 5)
 * ----------------------------------------------------------------
 * Today every source arrives as a CSV export that an analyst uploads on the Data sources screen
 * (`storeUpload`). In Phase 5 each source gets a connector that pulls the same records directly from the
 * external tool (CMDB, vulnerability scanner, EDR, PAM, SIEM, GRC, backup tool, ...).
 *
 * The rest of the application never sees the transport. The engine only consumes what `loadRows()` /
 * `loadAll()` return: for each source kind, an array of plain objects keyed by the field `key` names declared in
 * SOURCES below, with values already typed (dates as "YYYY-MM-DD", date-times as Date, booleans, numbers,
 * arrays), plus `_row` (a stable reference back to the source record, used as evidence). A connector must produce
 * exactly that shape; nothing in engine/ or the screens needs to change.
 *
 * Connector contract, per source kind:
 *   - fetch      -> raw records from the tool's API, filtered to what an assessment needs;
 *   - map        -> each record to the field keys below (the connector's mapping replaces the column-mapping
 *                   screen; keep the `aliases` as a hint for field names);
 *   - type       -> convert values with the same helpers (`convert`, built on parseDate / parseDatetime /
 *                   parseBool / parseList in util.js) so CSV and API data behave identically;
 *   - provenance -> record what was pulled, from where and when, as a `source_files` document: the pull time
 *                   becomes `export_date`, so the freshness flag and run snapshots keep working, and the raw
 *                   response is stored like an uploaded file so every finding still traces to evidence.
 * Suggested shape: a connector module per kind with `fetch(since) -> rows`, registered by kind; then
 * `loadRows()` asks the registry first and falls back to the latest CSV upload when no connector is set up.
 * Search for "CONNECTOR" in the code base for every place this affects.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parse } from "csv-parse/sync";

import { nextId } from "./db.js";
import { parseBool, parseDate, parseDatetime, parseList, parseNumber } from "./util.js";

const field = (key, label, { required = true, type = "text", aliases = [] } = {}) => ({ key, label, required, type, aliases });
const spec = (kind, label, usedBy, description, fields) => ({ kind, label, used_by: usedBy, description, fields });

export const SOURCES = Object.fromEntries([
  // CONNECTOR (Phase 5): business impact analysis / BCM tool or the CMDB's service map (for example the
  // BIA module of the GRC platform, or CMDB "business service -> application" relationships).
  // Pull: services with tier and impact tolerance, and their application relationships. Refresh: on change.
  spec("dependencies", "Application dependency list", "Step 1",
    "Critical services, their tier and impact tolerance, and the applications each depends on.", [
      field("service", "Service", { aliases: ["service name", "business service", "critical service"] }),
      field("service_tier", "Service tier", { type: "number", aliases: ["tier", "criticality tier"] }),
      field("impact_tolerance_hours", "Impact tolerance (hours)", { type: "number", aliases: ["impact tolerance", "tolerance hours", "max tolerable outage"] }),
      field("application_id", "Application ID", { aliases: ["app id", "application", "app"] }),
      field("application_name", "Application name", { aliases: ["app name", "name"] }),
      field("application_owner", "Application owner", { required: false, aliases: ["app owner", "owner"] }),
    ]),
  // CONNECTOR (Phase 5): CMDB API (for example ServiceNow CMDB, BMC Helix). Pull: server and database CIs
  // related to the in-scope applications, with criticality, owner, OS and end-of-support date.
  // Matching to every other source is by hostname, then IP, so keep the CI's FQDN/short name and primary IP.
  spec("asset_register", "Asset register", "Step 1, T3, H1; step 2, T5",
    "Servers and databases with the applications they support.", [
      field("asset_id", "Asset ID", { aliases: ["ci id", "asset", "id"] }),
      field("hostname", "Hostname", { aliases: ["host", "host name", "server name", "name", "fqdn"] }),
      field("ip", "IP address", { required: false, aliases: ["ip address", "ipaddress", "primary ip"] }),
      field("asset_type", "Type (server or database)", { aliases: ["type", "class", "ci class"] }),
      field("application_id", "Application ID(s)", { type: "list", aliases: ["application", "applications", "app id", "app"] }),
      field("environment", "Environment", { required: false, aliases: ["env"] }),
      field("criticality", "Criticality", { aliases: ["tier", "asset criticality", "business criticality"] }),
      field("owner", "Owner", { required: false, aliases: ["asset owner", "technical owner", "support owner"] }),
      field("os", "Operating system / platform", { required: false, aliases: ["operating system", "platform", "os version"] }),
      field("os_end_of_support", "End of support date", { required: false, type: "date", aliases: ["eol", "end of life", "eos date", "end of support"] }),
      field("internet_facing", "Internet facing", { required: false, type: "bool", aliases: ["internet facing", "exposed", "dmz"] }),
    ]),
  // CONNECTOR (Phase 5): network discovery tool (for example the CMDB's discovery module, Lansweeper or a
  // scanner's asset inventory). Pull: hosts seen in the scanned ranges with last-seen time and MAC.
  // Pull whole subnets, not only known hosts: unregistered hosts (check T1) are found by subnet.
  spec("discovery", "Discovery scan results", "Step 1, T1, T2",
    "Hosts seen on the network by the asset discovery tool.", [
      field("hostname", "Hostname", { aliases: ["host", "host name", "dns name", "fqdn"] }),
      field("ip", "IP address", { aliases: ["ip address", "ipaddress"] }),
      field("mac", "MAC address", { required: false, aliases: ["mac address"] }),
      field("os", "Operating system", { required: false, aliases: ["operating system"] }),
      field("last_seen", "Last seen", { type: "date", aliases: ["last seen date", "last scan"] }),
    ]),
  // CONNECTOR (Phase 5): vulnerability management API (for example Tenable, Qualys, Rapid7). Pull: open and
  // recently fixed findings per host with severity, first-detected date, exploit availability and fix date.
  // Include fixed findings for the SLA period: patch SLA adherence (P2) needs both open and closed items.
  spec("vulnerabilities", "Vulnerability or patch report", "Step 2, T4, T5, P2",
    "Vulnerabilities and missing patches per host, open and fixed.", [
      field("hostname", "Hostname", { aliases: ["host", "host name", "asset", "dns name"] }),
      field("ip", "IP address", { required: false, aliases: ["ip address"] }),
      field("vuln_id", "Vulnerability ID", { aliases: ["cve", "plugin id", "qid", "vulnerability"] }),
      field("title", "Title", { required: false, aliases: ["name", "vulnerability name", "description"] }),
      field("severity", "Severity", { aliases: ["risk", "criticality"] }),
      field("first_detected", "First detected", { type: "date", aliases: ["first seen", "first found", "detected"] }),
      field("exploit_available", "Exploit available", { required: false, type: "bool", aliases: ["exploitable", "known exploit"] }),
      field("status", "Status (open / fixed)", { aliases: ["state", "patch status"] }),
      field("fixed_date", "Fixed date", { required: false, type: "date", aliases: ["remediated", "closed date", "patched date"] }),
    ]),
  // CONNECTOR (Phase 5): EDR / anti-malware console API (for example Microsoft Defender for Endpoint,
  // CrowdStrike, Trellix). Pull: device inventory with agent health, signature/definition date, last check-in.
  // A host missing from this feed is treated as "no agent" (T6), so pull the full device list, not alerts.
  spec("antivirus", "Antivirus or EDR export", "Step 3, T6, T7",
    "Agent status, signature date and last check-in per host.", [
      field("hostname", "Hostname", { aliases: ["host", "computer name", "device name", "endpoint"] }),
      field("agent_status", "Agent status", { aliases: ["status", "health"] }),
      field("signature_date", "Signature date", { type: "date", aliases: ["definition date", "dat date", "signatures"] }),
      field("last_checkin", "Last check-in", { type: "date", aliases: ["last seen", "last contact", "last communication"] }),
    ]),
  // CONNECTOR (Phase 5): PAM vault API (for example CyberArk, BeyondTrust, Delinea). Pull: managed accounts
  // with target address, onboarding state and last password rotation.
  spec("pam", "PAM export", "Step 4, T8",
    "Privileged accounts onboarded to the PAM vault.", [
      field("hostname", "Hostname", { aliases: ["host", "address", "target"] }),
      field("account", "Account", { aliases: ["username", "user name", "account name"] }),
      field("onboarded", "Onboarded", { type: "bool", aliases: ["managed", "in vault", "vaulted"] }),
      field("last_rotation", "Last rotation", { required: false, type: "date", aliases: ["last password change", "last changed"] }),
    ]),
  // CONNECTOR (Phase 5): the privileged accounts that exist ON each server, to compare with the vault: PAM
  // discovery scans, endpoint management (local admin / sudoers / DB role enumeration) or AD group members.
  spec("privileged_accounts", "Server privileged account list", "Step 4, T8",
    "Local and service accounts with privileged rights on each host.", [
      field("hostname", "Hostname", { aliases: ["host", "server"] }),
      field("account", "Account", { aliases: ["username", "user name", "account name"] }),
      field("privilege_level", "Privilege level", { required: false, aliases: ["privilege", "group", "role"] }),
    ]),
  // CONNECTOR (Phase 5): SIEM log source inventory API (for example Splunk, Microsoft Sentinel, QRadar).
  // Pull: log sources with host and last event time (not the events themselves).
  spec("siem", "SIEM log source list", "Step 5, T9",
    "Log sources feeding the SIEM and when each last sent an event.", [
      field("hostname", "Hostname", { aliases: ["host", "log source", "source name", "device"] }),
      field("source_type", "Source type", { required: false, aliases: ["type", "log source type"] }),
      field("last_event", "Last event received", { type: "datetime", aliases: ["last event", "last seen", "last event time"] }),
    ]),
  // CONNECTOR (Phase 5): GRC platform policy-exception records (for example ServiceNow IRM, Archer,
  // MetricStream). Pull: exceptions for in-scope assets, with control, approver, compensating control, expiry.
  // The control must map to a CORA check ID (T4, T5, B3, ...); keep that mapping in the connector.
  spec("exceptions", "Exception register", "Step 6, P1",
    "Approved exceptions to hygiene controls.", [
      field("exception_id", "Exception ID", { required: false, aliases: ["id", "reference"] }),
      field("asset", "Asset (hostname or asset ID)", { aliases: ["hostname", "asset id", "host"] }),
      field("control", "Control (check ID)", { aliases: ["check", "check id", "control id"] }),
      field("reason", "Reason", { required: false, aliases: ["justification"] }),
      field("compensating_control", "Compensating control", { required: false, aliases: ["mitigation", "compensating controls"] }),
      field("approver", "Approver", { required: false, aliases: ["approved by"] }),
      field("expiry", "Expiry date", { type: "date", aliases: ["expiry date", "expires", "valid until"] }),
    ]),
  // CONNECTOR (Phase 5): HR system feed of leavers (for example Workday, SAP SuccessFactors), names and
  // leave dates only. Better: match on employee ID if the CMDB stores owners by ID rather than name.
  spec("hr_leavers", "HR leaver list", "Step 1, H1",
    "People who have left the organisation, to catch owners who are no longer here.", [
      field("name", "Name", { aliases: ["full name", "employee name", "employee"] }),
      field("leave_date", "Leave date", { required: false, type: "date", aliases: ["termination date", "last day"] }),
    ]),
  // CONNECTOR (Phase 5): GRC risk register API (same platform as the exception register). Pull: open,
  // accepted and recently closed risks with category (application / asset), linked applications and assets,
  // related controls, ratings, treatment, owner and acceptance details.
  // Risks without a clean application or asset link are where Phase 3's AI-suggested mapping helps.
  spec("risk_register", "Information security risk register", "Step 7, R1–R4",
    "Risks with the applications or assets they relate to, rating, treatment and acceptance details.", [
      field("risk_id", "Risk ID", { aliases: ["id", "reference", "risk reference"] }),
      field("title", "Title / description", { aliases: ["risk title", "description", "risk description", "risk"] }),
      field("category", "Category (application / asset)", { required: false, aliases: ["risk category", "risk type", "type", "perspective", "label", "risk label"] }),
      field("applications", "Applications (IDs or names, semicolon separated)", { required: false, type: "list", aliases: ["application", "application id", "app", "apps", "affected applications"] }),
      field("assets", "Assets (hostnames or asset IDs)", { required: false, type: "list", aliases: ["asset", "hosts", "affected assets", "hostname"] }),
      field("related_controls", "Related checks (e.g. T4;T5)", { required: false, type: "list", aliases: ["controls", "control", "check ids", "related checks"] }),
      field("inherent_rating", "Inherent rating", { required: false, aliases: ["inherent", "inherent risk"] }),
      field("residual_rating", "Residual rating", { aliases: ["residual", "residual risk", "rating", "current rating"] }),
      field("status", "Status", { aliases: ["risk status", "state"] }),
      field("treatment_plan", "Treatment plan", { required: false, aliases: ["treatment", "action plan", "mitigation"] }),
      field("owner", "Owner", { required: false, aliases: ["risk owner"] }),
      field("due_date", "Treatment due date", { required: false, type: "date", aliases: ["due", "target date", "treatment due"] }),
      field("acceptance_approver", "Acceptance approver", { required: false, aliases: ["accepted by", "approver"] }),
      field("review_date", "Acceptance review date", { required: false, type: "date", aliases: ["review", "next review", "review due"] }),
    ]),
  // CONNECTOR (Phase 5): backup platform API (for example Veeam, Commvault, Rubrik, Cohesity). Pull: protected
  // clients with job/policy, schedule, last successful backup, immutability/offsite copy and restore tests.
  spec("backups", "Backup management export", "Step 8, B1–B4",
    "Backup jobs per host: schedule, last successful backup, protected copy, and the latest restore test.", [
      field("hostname", "Hostname", { aliases: ["client", "host", "client name", "server", "asset"] }),
      field("job_name", "Job / policy", { required: false, aliases: ["job", "policy", "backup policy", "backup job"] }),
      field("schedule", "Schedule (hourly / daily / weekly / monthly)", { aliases: ["frequency", "backup schedule"] }),
      field("job_status", "Job status (active / disabled)", { required: false, aliases: ["job state", "enabled", "state"] }),
      field("last_success", "Last successful backup", { type: "datetime", aliases: ["last successful backup", "last good backup", "last backup"] }),
      field("last_result", "Last run result", { required: false, aliases: ["last status", "last backup result", "result"] }),
      field("retention_days", "Retention (days)", { required: false, type: "number", aliases: ["retention"] }),
      field("immutable", "Immutable copy", { required: false, type: "bool", aliases: ["immutable copy", "worm", "locked"] }),
      field("offsite", "Offsite / air-gapped copy", { required: false, type: "bool", aliases: ["offsite copy", "air gapped", "air-gapped", "vault copy"] }),
      field("restore_test_date", "Last restore test", { required: false, type: "date", aliases: ["restore test date", "last restore test", "restore tested"] }),
      field("restore_result", "Restore test result", { required: false, aliases: ["restore status", "restore outcome"] }),
      field("restore_hours", "Restore time (hours)", { required: false, type: "number", aliases: ["restore time", "restore duration", "time to restore"] }),
    ]),
  // CONNECTOR (Phase 5): DR test records from the BCM/GRC tool, or reports from DR orchestration (for example
  // VMware SRM, Zerto). Pull: latest tests per application with scope, achieved recovery time and data loss,
  // result and open issues. Narrative-only DR reports are what Phase 3's AI extraction is for.
  spec("dr_tests", "DR test results", "Step 9, D1–D4",
    "Disaster recovery tests per application: objectives, achieved recovery time and data loss, open issues.", [
      field("application", "Application (ID or name)", { aliases: ["application id", "app", "application name", "system"] }),
      field("test_date", "Test date", { type: "date", aliases: ["date", "test performed", "exercise date"] }),
      field("test_type", "Test type", { required: false, aliases: ["type", "test scenario"] }),
      field("scope", "Scope (hostnames tested)", { required: false, type: "list", aliases: ["assets tested", "hosts", "servers in scope"] }),
      field("rto_hours", "RTO (hours)", { type: "number", aliases: ["rto", "recovery time objective"] }),
      field("achieved_rto_hours", "Achieved recovery time (hours)", { type: "number", aliases: ["achieved rto", "actual rto", "recovery time achieved", "actual recovery time"] }),
      field("rpo_hours", "RPO (hours)", { required: false, type: "number", aliases: ["rpo", "recovery point objective"] }),
      field("achieved_rpo_hours", "Achieved data loss (hours)", { required: false, type: "number", aliases: ["achieved rpo", "actual rpo", "data loss", "actual data loss", "data loss hours"] }),
      field("result", "Result (pass / fail / partial)", { aliases: ["outcome", "status", "test result"] }),
      field("open_issues", "Open issues", { required: false, aliases: ["issues", "open actions", "findings"] }),
      field("issue_due_date", "Issue due date", { required: false, type: "date", aliases: ["issues due", "action due date"] }),
    ]),
].map((s) => [s.kind, s]));

export const KIND_ORDER = Object.keys(SOURCES);

export class SourceError extends Error {}

// --- Typing --------------------------------------------------------------------------------------------

export function convert(f, raw) {
  switch (f.type) {
    case "date": return parseDate(raw);
    case "datetime": return parseDatetime(raw);
    case "bool": return parseBool(raw);
    case "number": return parseNumber(raw);
    case "list": return parseList(raw);
    default: return String(raw ?? "").trim();
  }
}

// --- Mapping -------------------------------------------------------------------------------------------

const normHeader = (text) => String(text ?? "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

export function autoMap(sourceSpec, headers) {
  const byNorm = new Map(headers.map((h) => [normHeader(h), h]));
  const mapping = {};
  const used = new Set();
  for (const f of sourceSpec.fields) { // exact key or label first, then aliases
    for (const candidate of [f.key, f.label, ...f.aliases]) {
      const header = byNorm.get(normHeader(candidate));
      if (header && !used.has(header)) {
        mapping[f.key] = header;
        used.add(header);
        break;
      }
    }
  }
  return mapping;
}

export function missingRequired(sourceSpec, mapping) {
  return sourceSpec.fields.filter((f) => f.required && !(mapping || {})[f.key]);
}

// --- Storage -------------------------------------------------------------------------------------------

function decode(buffer) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer).replace(/^﻿/, "");
  } catch {
    return new TextDecoder("windows-1252").decode(buffer);
  }
}

export function readCsv(buffer) {
  const records = parse(decode(buffer), { relax_column_count: true, skip_empty_lines: true });
  if (!records.length) throw new SourceError("The file has no header row.");
  const rawHeaders = records[0].map((h) => String(h ?? "").trim());
  const headers = rawHeaders.filter(Boolean);
  if (!headers.length) throw new SourceError("The file has no header row.");
  const rows = records.slice(1)
    .map((rec) => Object.fromEntries(rawHeaders.map((h, i) => [h, rec[i] ?? ""])))
    .filter((row) => Object.values(row).some((v) => String(v).trim()));
  return { headers, rows };
}

/**
 * Store a CSV upload as the active file for its source kind.
 *
 * CONNECTOR (Phase 5): this is the manual entry point that a connector pull replaces. A connector should still
 * record each pull through the same path: store the raw response (or a CSV/JSON rendering of the mapped
 * records) as the file, the pull time as `export_date`, and deactivate the previous record, so run snapshots,
 * fingerprints and freshness flags work the same for uploaded and pulled data.
 */
export async function storeUpload(db, uploadDir, kind, filename, buffer, exportDate, { uploadedBy = null } = {}) {
  if (!Object.hasOwn(SOURCES, kind)) throw new SourceError(`Unknown source: ${kind}`);
  if (!String(filename).toLowerCase().endsWith(".csv")) throw new SourceError("Only CSV files are accepted.");
  const { headers, rows } = readCsv(buffer);
  if (!rows.length) throw new SourceError("The file has a header row but no data rows.");
  const digest = crypto.createHash("sha256").update(buffer).digest("hex");
  const folder = path.join(uploadDir, kind);
  fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
  const base = path.basename(String(filename));
  const safeName = base.replace(/[^A-Za-z0-9._-]+/g, "_");
  const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
  const storedPath = path.join(folder, `${stamp}_${digest.slice(0, 8)}_${safeName}`);
  fs.writeFileSync(storedPath, buffer, { mode: 0o600 }); // evidence files: readable by the service account only
  const id = await nextId(db, "source_files");
  const record = {
    id, kind, filename: base, stored_path: storedPath, sha256: digest, row_count: rows.length, headers,
    mapping: autoMap(SOURCES[kind], headers), export_date: exportDate, uploaded_at: new Date(), uploaded_by: uploadedBy, active: true,
  };
  await db.collection("source_files").updateMany({ kind, active: true }, { $set: { active: false } });
  await db.collection("source_files").insertOne(record);
  return record;
}

export async function activeFile(db, kind) {
  // CONNECTOR (Phase 5): with connectors this is "the latest successful pull" for the kind.
  return db.collection("source_files").findOne({ kind, active: true }, { sort: { id: -1 } });
}

export function isReady(record) {
  // CONNECTOR (Phase 5): a pulled source is ready when the last pull succeeded; it needs no column mapping.
  return Boolean(record) && missingRequired(SOURCES[record.kind], record.mapping).length === 0;
}

/**
 * Rows as objects keyed by internal field name, plus `_row` (line number in the file, header = 1).
 *
 * CONNECTOR (Phase 5): THE integration seam. Everything downstream (routes, engine, evidence drill-down) reads
 * source data only through this function and `loadAll()`. A connector returns the same array of objects: the
 * field `key` names of the source's spec, typed with `convert`, and `_row` set to a stable reference to the
 * source record (for example the tool's record ID) so evidence links still point at something real.
 */
export function loadRows(record) {
  if (!isReady(record)) return [];
  const { rows } = readCsv(fs.readFileSync(record.stored_path));
  const fields = SOURCES[record.kind].fields;
  return rows.map((raw, i) => {
    const row = { _row: i + 2 };
    for (const f of fields) {
      const header = record.mapping[f.key];
      row[f.key] = convert(f, header ? raw[header] : "");
    }
    return row;
  });
}

/** Every source's latest file and rows: kind -> [record, rows]. */
export async function loadAll(db) {
  // CONNECTOR (Phase 5): the snapshot an assessment run takes of every source. With connectors, either use the
  // latest stored pulls (as now) or trigger a fresh pull of each source here before the run starts.
  const out = {};
  for (const kind of KIND_ORDER) {
    const rec = await activeFile(db, kind);
    out[kind] = [rec, loadRows(rec)];
  }
  return out;
}
