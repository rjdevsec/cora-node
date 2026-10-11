/*
 * Assessment pipeline: steps 1–11 for one critical service.
 *
 * `assess()` is pure: it takes the service definition, the parsed source rows and the settings, and returns plain
 * data. `saveRun()` (store.js) persists that result as a dated snapshot.
 */
import { backupChecks } from "./backup.js";
import { APP_CHECKS, ASSET_CHECKS, HYGIENE_CHECKS, PREVENTION, result } from "./checks.js";
import { evidence } from "./common.js";
import { appResolver, coveringRisks, drAssessment, linkRisks, riskChecks } from "./riskRecovery.js";
import { generateScenarios } from "./scenarios.js";
import { SOURCES } from "../sources.js";
import { ageDays, daysBetween, endOfDayMs, fmtDateTime, maxBy, normHost, round, subnet } from "../util.js";

export { APP_CHECKS, ASSET_CHECKS };

const HEALTHY_AV = new Set(["running", "active", "healthy", "protected", "online", "ok", "enabled", "up to date", "connected"]);
const OPEN_VULN = new Set(["open", "active", "new", "reopened", "missing", "not patched", "unpatched", "outstanding"]);
const SEVERITIES = ["critical", "high", "medium", "low"];
const isOpen = (v) => OPEN_VULN.has((v.status || "").toLowerCase());

// --- Step 1: service catalogue from the dependency list -----------------------------------------------

export function catalogue(depRows) {
  const services = {};
  for (const row of depRows) {
    const name = row.service;
    if (!name) continue;
    const svc = (services[name] ??= { name, tier: Math.trunc(row.service_tier || 3), tolerance_hours: row.impact_tolerance_hours || 0, applications: [] });
    if (row.application_id && !svc.applications.some((a) => a.id === row.application_id)) {
      svc.applications.push({ id: row.application_id, name: row.application_name || row.application_id, owner: row.application_owner || "" });
    }
  }
  return Object.fromEntries(Object.keys(services).sort().map((k) => [k, services[k]]));
}

/** Every application known to the dependency list or the asset register, for adding to a service. */
export function allApplications(depRows, registerRows) {
  const apps = new Map();
  for (const row of depRows) {
    if (row.application_id && !apps.has(row.application_id)) {
      apps.set(row.application_id, { id: row.application_id, name: row.application_name || row.application_id, owner: row.application_owner || "" });
    }
  }
  for (const row of registerRows) for (const id of row.application_id) if (!apps.has(id)) apps.set(id, { id, name: id, owner: "" });
  return [...apps.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

// --- Helpers -------------------------------------------------------------------------------------------

/** Map 'Tier 1', '1', 'Critical', 'High'… onto a tier number (1 is most critical). */
export function tierOf(criticality) {
  const text = String(criticality ?? "").trim().toLowerCase();
  const m = text.match(/\d/);
  if (m) return Number(m[0]);
  return { critical: 1, "very high": 1, high: 2, medium: 3, moderate: 3, low: 4 }[text] ?? null;
}

/**
 * Index source rows by normalised hostname and by IP, for hostname-first-then-IP matching.
 *
 * CONNECTOR (Phase 5): tools often expose a stable asset or agent ID as well. If the CMDB stores those IDs, matching
 * on them first would be more reliable than hostnames; add them as optional fields and index here.
 */
export class HostIndex {
  constructor(rows) {
    this.byHost = new Map();
    this.byIp = new Map();
    const push = (map, k, row) => (map.get(k) ?? map.set(k, []).get(k)).push(row);
    for (const row of rows) {
      const host = normHost(row.hostname || row.asset);
      if (host) push(this.byHost, host, row);
      const ip = String(row.ip ?? "").trim();
      if (ip) push(this.byIp, ip, row);
    }
  }

  /** Returns [rows, matched on] — matched on "hostname", "asset id" or "ip", or [[], null]. */
  find(hostname, ip = null, assetId = null) {
    let rows = this.byHost.get(normHost(hostname));
    if (rows?.length) return [rows, "hostname"];
    if (assetId && (rows = this.byHost.get(normHost(assetId)))?.length) return [rows, "asset id"];
    if (ip && (rows = this.byIp.get(ip) || this.byHost.get(ip))?.length) return [rows, "ip"];
    return [[], null];
  }
}

export function exceptionProblems(exc, asOf) {
  const problems = [];
  if (!exc.expiry) problems.push("no expiry date");
  else if (exc.expiry < asOf) problems.push(`expired ${exc.expiry}`);
  if (!(exc.approver || "").trim()) problems.push("not approved");
  if (!(exc.compensating_control || "").trim()) problems.push("no compensating control");
  return problems;
}

export function findingSeverity(weight, factor) {
  const effective = weight * factor;
  return effective >= 7.5 ? "Critical" : effective >= 4 ? "High" : effective >= 2 ? "Medium" : "Low";
}

// --- Assessment ----------------------------------------------------------------------------------------

/**
 * Run steps 1–11 for one service.
 *
 * `data` is `loadAll()`: source kind -> [source file record, rows keyed by field key]. The engine does not know or
 * care whether rows came from a CSV upload or (Phase 5) a connector; it relies only on the field names and types
 * declared in SOURCES. CONNECTOR implementers: keep hostnames and IPs populated on every host-based source, since
 * all cross-source matching below is hostname first, then IP.
 *
 * defn: { name, tier, tolerance_hours, applications: [{id, name, owner}], as_of: "YYYY-MM-DD" }
 */
export function assess(defn, data, settings) {
  const rows = Object.fromEntries(Object.entries(data).map(([k, [, r]]) => [k, r]));
  const records = Object.fromEntries(Object.entries(data).map(([k, [rec]]) => [k, rec]));
  const asOf = defn.as_of;
  const appIds = defn.applications.map((a) => a.id);
  const inScope = new Set(appIds);

  // Services each application supports (for the concentration modifier).
  const appServices = new Map();
  for (const row of rows.dependencies) {
    if (row.application_id) (appServices.get(row.application_id) ?? appServices.set(row.application_id, new Set()).get(row.application_id)).add(row.service);
  }

  // --- Step 1: resolve assets from the register ----------------------------------------------------
  const assets = {};
  const keyOf = (row) => row.asset_id || normHost(row.hostname);
  for (const row of rows.asset_register) {
    if (!row.application_id.some((a) => inScope.has(a))) continue;
    const key = keyOf(row);
    let asset = assets[key];
    if (!asset) {
      asset = assets[key] = {
        asset_id: row.asset_id, hostname: row.hostname, ip: row.ip, asset_type: row.asset_type,
        applications: [], all_applications: new Set(), environment: row.environment, criticality: row.criticality,
        owner: row.owner, os: row.os, os_end_of_support: row.os_end_of_support,
        internet_facing: Boolean(row.internet_facing), registered: true, register_rows: [],
      };
    }
    asset.register_rows.push(evidence("asset_register", row));
    for (const id of row.application_id) {
      asset.all_applications.add(id);
      if (inScope.has(id) && !asset.applications.includes(id)) asset.applications.push(id);
    }
  }
  // An asset can be registered once per application; collect its other applications from every row.
  for (const row of rows.asset_register) {
    const a = assets[keyOf(row)];
    if (a) for (const id of row.application_id) a.all_applications.add(id);
  }
  for (const asset of Object.values(assets)) {
    const others = new Set();
    for (const id of asset.all_applications) for (const s of appServices.get(id) ?? []) others.add(s);
    others.delete(defn.name);
    asset.other_services = [...others].sort();
  }
  const appsWithoutAssets = defn.applications.filter((a) => !Object.values(assets).some((x) => x.applications.includes(a.id)));

  // --- Reconcile with discovery ----------------------------------------------------------------------
  const discoveryLoaded = Boolean(records.discovery) && rows.discovery.length > 0;
  const discIndex = new HostIndex(rows.discovery);
  const matchedDiscoveryRows = new Set();
  for (const asset of Object.values(assets)) {
    const [found, key] = discIndex.find(asset.hostname, asset.ip, asset.asset_id);
    if (found.length) {
      const latest = maxBy(found, (r) => r.last_seen || "");
      asset.discovery = latest;
      asset.discovery_match_key = key;
      for (const r of found) matchedDiscoveryRows.add(r._row);
      const age = ageDays(asOf, latest.last_seen);
      asset.discovery_status = age !== null && age > settings.discovery_max_age_days ? "stale" : "matched";
    } else {
      asset.discovery = null;
      asset.discovery_match_key = null;
      asset.discovery_status = discoveryLoaded ? "not_seen" : "no_data";
    }
  }

  // Discovered but not registered: hosts absent from the whole register that sit in an in-scope subnet.
  const registerIndex = new HostIndex(rows.asset_register.map((r) => ({ hostname: r.hostname, ip: r.ip, _row: r._row })));
  const subnetApps = new Map();
  for (const a of Object.values(assets)) {
    const s = subnet(a.ip);
    if (s) for (const id of a.applications) (subnetApps.get(s) ?? subnetApps.set(s, new Set()).get(s)).add(id);
  }
  const unregistered = [];
  for (const row of rows.discovery) {
    if (matchedDiscoveryRows.has(row._row) || registerIndex.find(row.hostname, row.ip)[0].length) continue;
    const s = subnet(row.ip);
    if (!s || !subnetApps.has(s)) continue;
    const key = `unreg:${normHost(row.hostname) || row.ip}`;
    if (assets[key]) continue;
    assets[key] = {
      asset_id: "", hostname: row.hostname || row.ip, ip: row.ip, asset_type: "Unknown",
      applications: [], all_applications: new Set(), environment: "", criticality: "", owner: "",
      os: row.os, os_end_of_support: null, internet_facing: false, registered: false,
      register_rows: [], other_services: [], discovery: row, discovery_match_key: null,
      subnet_applications: [...subnetApps.get(s)].sort(), discovery_status: "unregistered",
    };
    unregistered.push(row);
  }

  // --- Indexes for the hygiene sources -----------------------------------------------------------------
  const HOST_KINDS = ["vulnerabilities", "antivirus", "pam", "privileged_accounts", "siem", "backups", "exceptions"];
  const idx = Object.fromEntries(HOST_KINDS.map((k) => [k, new HostIndex(rows[k])]));
  const leavers = new Map(rows.hr_leavers.filter((r) => r.name).map((r) => [r.name.trim().toLowerCase(), r]));
  const loaded = Object.fromEntries(Object.keys(SOURCES).map((k) => [k, Boolean(records[k]) && rows[k].length > 0]));
  const sla = settings.patch_sla_days;

  // --- Steps 1–8: checks per asset ---------------------------------------------------------------------
  const serviceVulns = { total: 0, within: 0 };
  for (const asset of Object.values(assets)) {
    const results = {};
    const { hostname: host, ip, asset_id: aid } = asset;
    const disc = asset.discovery;
    const firstRegisterRow = asset.register_rows.slice(0, 1);

    // T1 Asset registered
    results.T1 = asset.registered
      ? result("T1", "pass", "In the asset register.", firstRegisterRow)
      : result("T1", "fail", `Seen by discovery on ${disc.last_seen || "unknown date"} at ${disc.ip || "no IP"} in an in-scope subnet, but not in the asset register.`,
        [evidence("discovery", disc)]);

    // T2 Asset seen
    if (!asset.registered) results.T2 = result("T2", "n/a", "Not in the register; covered by T1.");
    else if (!discoveryLoaded) results.T2 = result("T2", "no_data", "Discovery scan results not loaded.");
    else if (asset.discovery_status === "not_seen") results.T2 = result("T2", "fail", "Registered but not found in the discovery scan by hostname or IP.");
    else {
      const age = ageDays(asOf, disc.last_seen);
      const ev = [evidence("discovery", disc)];
      results.T2 = asset.discovery_status === "stale"
        ? result("T2", "fail", `Last seen ${age} days ago (threshold ${settings.discovery_max_age_days}).`, ev)
        : result("T2", "pass", `Seen ${age} days ago, matched on ${asset.discovery_match_key}.`, ev);
    }

    // T3 Categorisation aligned
    if (!asset.registered) results.T3 = result("T3", "n/a", "Not in the register; criticality unknown (see T1).");
    else {
      const t = tierOf(asset.criticality);
      if (t === null) results.T3 = result("T3", "no_data", `Criticality '${asset.criticality || "blank"}' is not recognised.`, firstRegisterRow);
      else if (t > defn.tier) results.T3 = result("T3", "fail", `Recorded as '${asset.criticality}' but supports a Tier ${defn.tier} service.`, firstRegisterRow);
      else results.T3 = result("T3", "pass", `Recorded as '${asset.criticality}', aligned with Tier ${defn.tier}.`, firstRegisterRow);
    }

    // T4 Patched within SLA, and P2 Patch SLA adherence
    const [vulns] = idx.vulnerabilities.find(host, ip, aid);
    asset.exploitable = false;
    if (!loaded.vulnerabilities) {
      results.T4 = result("T4", "no_data", "Vulnerability report not loaded.");
      results.P2 = result("P2", "no_data", "Vulnerability report not loaded.");
    } else if (!vulns.length) {
      results.T4 = result("T4", "no_data", "Host not in the vulnerability report; it may not be scanned.");
      results.P2 = result("P2", "no_data", "Host not in the vulnerability report.");
    } else {
      const overdue = [];
      let openWithin = 0;
      let within = 0;
      let total = 0;
      for (const v of vulns) {
        const sev = (v.severity || "low").toLowerCase();
        const limit = sla[sev] ?? sla.low;
        if (isOpen(v)) {
          const age = ageDays(asOf, v.first_detected) || 0;
          if (v.exploit_available) asset.exploitable = true;
          if (age > limit) overdue.push([v, age, limit]);
          else { openWithin += 1; within += 1; }
        } else if (v.fixed_date && v.first_detected) {
          within += daysBetween(v.first_detected, v.fixed_date) <= limit ? 1 : 0;
        } else {
          within += 1;
        }
        total += 1;
      }
      serviceVulns.total += total;
      serviceVulns.within += within;
      if (overdue.length) {
        const rank = ([v]) => { const i = SEVERITIES.indexOf((v.severity || "low").toLowerCase()); return i < 0 ? 9 : i; };
        const worst = [...overdue].sort((a, b) => rank(a) - rank(b));
        const summary = worst.slice(0, 4).map(([v, age, limit]) => `${v.vuln_id} (${v.severity}, ${age}d > ${limit}d SLA${v.exploit_available ? ", exploit available" : ""})`).join("; ");
        const more = overdue.length > 4 ? ` and ${overdue.length - 4} more` : "";
        results.T4 = result("T4", "fail", `${overdue.length} open past SLA: ${summary}${more}.`, worst.map(([v]) => evidence("vulnerabilities", v)));
      } else {
        results.T4 = result("T4", "pass", `No open vulnerabilities past SLA (${openWithin} open within SLA).`, vulns.filter(isOpen).map((v) => evidence("vulnerabilities", v)));
      }
      const pct = total ? round((100 * within) / total, 1) : 100;
      const target = settings.patch_sla_target_pct;
      results.P2 = result("P2", pct >= target ? "pass" : "fail", `${pct}% of ${total} vulnerabilities fixed or open within SLA (target ${target}%).`,
        vulns.map((v) => evidence("vulnerabilities", v)), { pct });
    }

    // T5 Supported software
    const eol = asset.os_end_of_support;
    const eolVulns = vulns.filter((v) => isOpen(v) && /end of life|unsupported|end-of-life|eol/i.test(v.title || ""));
    if (eol && eol < asOf) results.T5 = result("T5", "fail", `${asset.os || "Platform"} reached end of support on ${eol}.`, firstRegisterRow);
    else if (eolVulns.length) results.T5 = result("T5", "fail", `Vulnerability report flags unsupported software: ${eolVulns[0].title}.`, eolVulns.map((v) => evidence("vulnerabilities", v)));
    else if (eol) results.T5 = result("T5", "pass", `${asset.os || "Platform"} supported until ${eol}.`, firstRegisterRow);
    else results.T5 = result("T5", "no_data", "No end-of-support date in the asset register.");

    // T6 Antivirus installed, T7 signatures current
    const [avRows] = idx.antivirus.find(host, ip, aid);
    if (!loaded.antivirus) {
      results.T6 = result("T6", "no_data", "Antivirus or EDR export not loaded.");
      results.T7 = result("T7", "no_data", "Antivirus or EDR export not loaded.");
    } else if (!avRows.length) {
      results.T6 = result("T6", "fail", "No antivirus or EDR agent recorded for this host.");
      results.T7 = result("T7", "n/a", "No agent; covered by T6.");
    } else {
      const av = maxBy(avRows, (r) => r.last_checkin || "");
      const ev = [evidence("antivirus", av)];
      const checkinAge = ageDays(asOf, av.last_checkin);
      if (!HEALTHY_AV.has((av.agent_status || "").trim().toLowerCase())) results.T6 = result("T6", "fail", `Agent status is '${av.agent_status || "blank"}'.`, ev);
      else if (checkinAge === null || checkinAge > settings.av_checkin_max_age_days) {
        results.T6 = result("T6", "fail", `Agent last checked in ${checkinAge ?? "never"} days ago (threshold ${settings.av_checkin_max_age_days}).`, ev);
      } else results.T6 = result("T6", "pass", `Agent '${av.agent_status}', checked in ${checkinAge} days ago.`, ev);
      const sigAge = ageDays(asOf, av.signature_date);
      if (sigAge === null) results.T7 = result("T7", "no_data", "No signature date in the export.", ev);
      else if (sigAge > settings.av_signature_max_age_days) results.T7 = result("T7", "fail", `Signatures are ${sigAge} days old (threshold ${settings.av_signature_max_age_days}).`, ev);
      else results.T7 = result("T7", "pass", `Signatures are ${sigAge} days old.`, ev);
    }

    // T8 Privileged accounts in PAM
    const [priv] = idx.privileged_accounts.find(host, ip, aid);
    const [pamRows] = idx.pam.find(host, ip, aid);
    if (!loaded.privileged_accounts) results.T8 = result("T8", "no_data", "Server privileged account list not loaded.");
    else if (!priv.length) results.T8 = result("T8", "no_data", "No privileged accounts listed for this host.");
    else {
      const vaulted = new Set(pamRows.filter((r) => r.onboarded).map((r) => (r.account || "").toLowerCase()));
      const missing = priv.filter((p) => !vaulted.has((p.account || "").toLowerCase()));
      const ev = [...priv.map((p) => evidence("privileged_accounts", p)), ...pamRows.map((r) => evidence("pam", r))];
      results.T8 = missing.length
        ? result("T8", "fail", `${missing.length} of ${priv.length} privileged accounts not onboarded to PAM: ${missing.map((p) => p.account).join(", ")}.`, ev)
        : result("T8", "pass", `All ${priv.length} privileged accounts onboarded to PAM.`, ev);
    }

    // T9 Logs in SIEM
    const [siemRows] = idx.siem.find(host, ip, aid);
    if (!loaded.siem) results.T9 = result("T9", "no_data", "SIEM log source list not loaded.");
    else if (!siemRows.length) results.T9 = result("T9", "fail", "No SIEM log source for this host.");
    else {
      const latest = maxBy(siemRows, (r) => (r.last_event ? r.last_event.getTime() : -Infinity));
      const ev = siemRows.map((r) => evidence("siem", r));
      if (!latest.last_event) results.T9 = result("T9", "fail", "Log source exists but has never sent an event.", ev);
      else {
        const hours = (endOfDayMs(asOf) - latest.last_event.getTime()) / 3_600_000;
        results.T9 = hours > settings.siem_max_silence_hours
          ? result("T9", "fail", `Last event ${fmtDateTime(latest.last_event)}, ${Math.round(hours / 24)} days ago (threshold ${settings.siem_max_silence_hours}h).`, ev)
          : result("T9", "pass", `Last event ${fmtDateTime(latest.last_event)}.`, ev);
      }
    }

    // B1–B4 Backups — from the backup management tool, including the latest restore test
    const [jobs] = idx.backups.find(host, ip, aid);
    Object.assign(results, backupChecks(jobs, evidence, asOf, defn.tolerance_hours, settings, loaded.backups, asset.registered));

    // P1 Exception validity — every exception recorded against this asset
    const [excRows] = idx.exceptions.find(host, ip, aid);
    asset.exceptions = excRows;
    if (!excRows.length) results.P1 = result("P1", "n/a", "No exceptions recorded for this asset.");
    else {
      const problems = excRows.map((e) => [e, exceptionProblems(e, asOf)]).filter(([, p]) => p.length)
        .map(([e, p]) => `${e.exception_id || e.control}: ${p.join(", ")}`);
      const ev = excRows.map((e) => evidence("exceptions", e));
      results.P1 = problems.length
        ? result("P1", "fail", `Invalid exceptions — ${problems.join("; ")}.`, ev)
        : result("P1", "pass", `${excRows.length} exception(s), all approved, in date and with a compensating control.`, ev);
    }

    // H1 Ownership assigned
    const owner = (asset.owner || "").trim();
    if (!asset.registered) results.H1 = result("H1", "n/a", "Not in the register; no owner recorded (see T1).");
    else if (!owner) results.H1 = result("H1", "fail", "No owner recorded in the asset register.", firstRegisterRow);
    else if (leavers.has(owner.toLowerCase())) {
      const left = leavers.get(owner.toLowerCase());
      results.H1 = result("H1", "fail", `Owner ${owner} left the organisation${left.leave_date ? ` on ${left.leave_date}` : ""}.`,
        [...firstRegisterRow, evidence("hr_leavers", left)]);
    } else if (!loaded.hr_leavers) results.H1 = result("H1", "pass", `Owner ${owner} (HR leaver list not loaded, so not checked for leavers).`, firstRegisterRow);
    else results.H1 = result("H1", "pass", `Owner ${owner}, not on the leaver list.`, firstRegisterRow);

    // --- Step 6: apply exceptions to failed checks -------------------------------------------------------
    for (const [checkId, res] of Object.entries(results)) {
      if (res.status !== "fail" || checkId === "P1") continue;
      const matching = excRows.filter((e) => (e.control || "").trim().toUpperCase() === checkId);
      if (!matching.length) continue;
      const valid = matching.filter((e) => !exceptionProblems(e, asOf).length);
      const chosen = valid[0] ?? matching[0];
      res.exception = { ...evidence("exceptions", chosen), valid: valid.length > 0, problems: exceptionProblems(chosen, asOf) };
      if (valid.length) {
        res.status = "excepted";
        res.detail += ` Covered by exception ${chosen.exception_id || ""} until ${chosen.expiry}.`;
      } else {
        res.detail += ` Exception ${chosen.exception_id || ""} does not apply: ${res.exception.problems.join(", ")}.`;
      }
    }
    asset.results = results;
  }

  // --- Step 7: open risks, and R4 (gaps recorded as risks) per asset --------------------------------------
  const resolve = appResolver(rows.dependencies, rows.asset_register);
  const appNames = Object.fromEntries(defn.applications.map((a) => [a.id, a.name]));
  const [risks, unmappedRisks] = linkRisks(rows.risk_register, rows.asset_register, assets, resolve, inScope, asOf, settings);
  for (const [key, asset] of Object.entries(assets)) {
    const unrecorded = [];
    for (const checkId of HYGIENE_CHECKS) {
      const res = asset.results[checkId];
      if (res.status !== "fail") continue;
      const cover = coveringRisks(key, asset, checkId, risks);
      res.risk_ids = cover.map((r) => r.id);
      res.risk_in_date = cover.some((r) => r.in_date);
      if (!cover.length) unrecorded.push(checkId);
    }
    if (!loaded.risk_register) asset.results.R4 = result("R4", "no_data", "Risk register not loaded.");
    else if (unrecorded.length) asset.results.R4 = result("R4", "fail", `Unrecorded risk: ${unrecorded.join(", ")} failed with no matching risk or valid exception.`, [], { unrecorded });
    else if (HYGIENE_CHECKS.some((c) => asset.results[c].status === "fail")) asset.results.R4 = result("R4", "pass", "Every failed check is recorded in the risk register.");
    else asset.results.R4 = result("R4", "n/a", "No failed checks to record.");
  }

  // --- Step 9: DR test results per application ------------------------------------------------------------
  const appLevel = {};
  const dr = {};
  for (const app of defn.applications) {
    const appAssets = Object.values(assets).filter((a) => a.registered && a.applications.includes(app.id));
    appLevel[app.id] = loaded.risk_register
      ? riskChecks(app.id, risks, settings)
      : Object.fromEntries(["R1", "R2", "R3"].map((c) => [c, result(c, "no_data", "Risk register not loaded.")]));
    dr[app.id] = loaded.dr_tests
      ? drAssessment(app, rows.dr_tests, resolve, appAssets, defn.tolerance_hours, asOf, settings, risks)
      : {
        id: app.id, name: app.name, test: null, test_count: 0,
        results: Object.fromEntries(["D1", "D2", "D3", "D4"].map((c) => [c, result(c, "no_data", "DR test results not loaded.")])),
        recovery: { status: "untested", achieved: null, margin_pct: null },
      };
    Object.assign(appLevel[app.id], dr[app.id].results);
  }

  // --- Scoring -----------------------------------------------------------------------------------------------
  const weights = settings.check_weights;
  const mods = settings.modifiers;
  const tier1 = defn.tier === 1;
  const dataQuality = [];
  for (const asset of Object.values(assets)) {
    let base = 0;
    for (const res of Object.values(asset.results)) {
      const w = Number(weights[res.check_id] ?? 1);
      if (res.status === "fail") res.weight = w;
      else if (res.status === "excepted") res.weight = w * settings.excepted_weight_factor;
      else if (res.status === "no_data") { res.weight = tier1 ? w : 0; dataQuality.push([asset, res]); }
      else res.weight = 0;
      base += res.weight;
    }
    const failing = new Set(Object.entries(asset.results).filter(([, r]) => r.status === "fail").map(([c]) => c));
    const applied = [];
    if (asset.internet_facing) applied.push("exposure");
    if (asset.exploitable) applied.push("exploitability");
    if (asset.other_services.length) applied.push("concentration");
    if ([...failing].some((c) => PREVENTION.has(c)) && failing.has("T9") && failing.has("T8")) applied.push("compounding");
    const factor = applied.reduce((f, m) => f * mods[m], 1);
    asset.modifiers = applied;
    asset.factor = factor;
    asset.score = base ? round(base * factor, 2) : 0;
  }
  // Application-level results carry a score too, so every risk in the run can be ranked together.
  for (const [appId, results] of Object.entries(appLevel)) {
    const others = [...(appServices.get(appId) ?? [])].filter((s) => s !== defn.name);
    const factor = others.length ? mods.concentration : 1;
    for (const res of Object.values(results)) {
      res.weight = res.status === "fail" ? Number(weights[res.check_id] ?? 1) : 0;
      res.score = round(res.weight * factor, 2);
      res.factor = factor;
    }
  }

  // --- Step 11: plausible scenarios, generated from the issues and risks found, then rated -------------------
  const scenarioResults = generateScenarios(assets, appLevel, dr, risks, defn, settings, appNames);
  const worstScore = Math.max(0, ...scenarioResults.map((s) => s.score));
  let rating;
  let reason;
  if (scenarioResults.length) {
    const top = scenarioResults[0];
    rating = top.rating;
    reason = `Worst scenario “${top.name}”: ${top.reasons.join("; ")}.`;
  } else {
    rating = "Low";
    reason = "No issue or risk found makes a scenario plausible that could breach the impact tolerance.";
  }
  if (dataQuality.length && tier1) reason += ` ${dataQuality.length} check(s) returned no data and are counted as fails for a Tier 1 service.`;

  // Application-level ownership (H1)
  const appResults = defn.applications.map((app) => {
    const owner = (app.owner || "").trim();
    const [status, detail] = !owner ? ["fail", "No application owner in the dependency list."]
      : leavers.has(owner.toLowerCase()) ? ["fail", `Owner ${owner} has left the organisation.`]
        : ["pass", `Owner ${owner}.`];
    return { id: app.id, name: app.name, owner, status, detail, asset_count: Object.values(assets).filter((a) => a.applications.includes(app.id)).length };
  });

  const pct = serviceVulns.total ? round((100 * serviceVulns.within) / serviceVulns.total, 1) : null;
  const serviceChecks = {
    P2: { pct, total: serviceVulns.total, target: settings.patch_sla_target_pct,
      status: pct === null ? "no_data" : pct >= settings.patch_sla_target_pct ? "pass" : "fail" },
  };

  // Upload coverage: how many in-scope assets each source has a row for, and file freshness.
  const registeredAssets = Object.values(assets).filter((a) => a.registered);
  const sources = Object.entries(SOURCES).map(([kind, spec]) => {
    const rec = records[kind];
    let covered = null;
    if (idx[kind] && kind !== "exceptions") covered = registeredAssets.filter((a) => idx[kind].find(a.hostname, a.ip, a.asset_id)[0].length).length;
    else if (kind === "discovery") covered = registeredAssets.filter((a) => ["matched", "stale"].includes(a.discovery_status)).length;
    else if (kind === "dr_tests") covered = Object.values(dr).filter((d) => d.test !== null).length;
    const age = rec ? ageDays(asOf, rec.export_date) : null;
    return {
      kind, label: spec.label, file_id: rec?.id ?? null, filename: rec?.filename ?? null, sha256: rec?.sha256 ?? null,
      export_date: rec?.export_date ?? null, rows: rows[kind].length, covered,
      asset_total: kind === "dr_tests" ? defn.applications.length : registeredAssets.length,
      unit: kind === "dr_tests" ? "applications" : "assets",
      stale: age !== null && age > settings.file_max_age_days, age_days: age,
    };
  });

  // Review queue: rows in hygiene sources that match no asset anywhere in the register.
  const unmatched = [];
  const registerIds = new Set(rows.asset_register.filter((r) => r.asset_id).map((r) => normHost(r.asset_id)));
  for (const kind of HOST_KINDS) {
    const seen = new Set();
    for (const row of rows[kind]) {
      const h = row.hostname || row.asset;
      if (registerIndex.find(h, row.ip)[0].length || registerIds.has(normHost(h))) continue;
      if (seen.has(normHost(h))) continue;
      seen.add(normHost(h));
      unmatched.push({ source: kind, source_label: SOURCES[kind].label, row: row._row, host: h, reason: "Hostname / IP not found in the asset register" });
    }
  }

  const reconciliation = {
    registered_in_scope: registeredAssets.length,
    matched: registeredAssets.filter((a) => a.discovery_status === "matched").length,
    stale: registeredAssets.filter((a) => a.discovery_status === "stale").length,
    not_seen: registeredAssets.filter((a) => a.discovery_status === "not_seen").length,
    unregistered: unregistered.length,
    discovery_loaded: discoveryLoaded,
    apps_without_assets: appsWithoutAssets.map((a) => a.id),
    miscategorised: registeredAssets.filter((a) => a.results.T3.status === "fail").length,
  };

  return {
    assets: Object.values(assets), scenario_results: scenarioResults, rating, reason, score: worstScore,
    app_results: appResults, service_checks: serviceChecks, sources, unmatched, reconciliation,
    risks, unmapped_risks: unmappedRisks, app_level: appLevel, dr: defn.applications.map((a) => dr[a.id]),
  };
}

