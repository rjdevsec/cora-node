/*
 * Open risks (step 7, checks R1–R4) and DR test results (step 9, checks D1–D4).
 *
 * Reads the `risk_register` and `dr_tests` sources through the rows `loadAll()` provides, so it works the same for
 * CSV uploads and (Phase 5) GRC / DR-tool connectors. Applications are matched by ID or name and assets by
 * hostname or asset ID; a connector that supplies IDs from the CMDB makes this matching exact.
 */
import { result } from "./checks.js";
import { evidence } from "./common.js";
import { ageDays, g, maxBy, normHost, round } from "../util.js";

const RATING_RANK = { "very low": 1, low: 1, minor: 1, medium: 2, moderate: 2, high: 3, major: 3, "very high": 4, critical: 4, severe: 4, extreme: 4 };
export const RATING_NAMES = { 1: "Low", 2: "Medium", 3: "High", 4: "Critical" };
const CLOSED = new Set(["closed", "retired", "resolved", "cancelled", "canceled", "withdrawn", "superseded"]);
export const PASSED = new Set(["pass", "passed", "success", "successful", "met", "complete", "completed"]);
export const RECOVERY_RANK = { proven: 1, thin: 2, unproven: 3, untested: 4, exceeds: 5 };

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

export function ratingRank(text) {
  const t = String(text ?? "").trim().toLowerCase();
  if (t in RATING_RANK) return RATING_RANK[t];
  if (t === "" || !Number.isFinite(Number(t))) return null;
  const n = Number(t);
  if (n <= 5) return { 1: 1, 2: 1, 3: 2, 4: 3 }[Math.trunc(n)] ?? 4; // 1–5 scale
  return n >= 20 ? 4 : n >= 12 ? 3 : n >= 6 ? 2 : 1; // 5x5 matrix score
}

/** Map an application reference (ID or name, any case) to its application ID. */
export function appResolver(depRows, registerRows) {
  const lookup = new Map();
  for (const row of depRows) {
    if (!row.application_id) continue;
    lookup.set(row.application_id.trim().toLowerCase(), row.application_id);
    if (row.application_name) lookup.set(row.application_name.trim().toLowerCase(), row.application_id);
  }
  for (const row of registerRows) {
    for (const appId of row.application_id) {
      const k = appId.trim().toLowerCase();
      if (!lookup.has(k)) lookup.set(k, appId);
    }
  }
  return (ref) => lookup.get(String(ref ?? "").trim().toLowerCase()) ?? null;
}

// --- Step 7: open risks --------------------------------------------------------------------------------

/** Returns [risks linked to in-scope applications or assets, open risks that map to nothing known]. */
export function linkRisks(rows, registerRows, assets, resolve, inScope, asOf, settings) {
  const hostKey = new Map();
  for (const [key, a] of Object.entries(assets)) {
    for (const ref of [a.hostname, a.asset_id]) if (ref) hostKey.set(normHost(ref), key);
  }
  const knownHosts = new Set([...registerRows.map((r) => normHost(r.hostname)), ...registerRows.filter((r) => r.asset_id).map((r) => normHost(r.asset_id))]);
  const appetite = ratingRank(settings.risk_appetite) || 2;
  const seniors = new Set(String(settings.senior_approvers).split(/[,;]/).map((s) => s.trim().toLowerCase()).filter(Boolean));

  const linked = [];
  const unmapped = [];
  for (const row of rows) {
    const status = (row.status || "").trim();
    if (CLOSED.has(status.toLowerCase())) continue;
    const appIds = row.applications.map(resolve).filter(Boolean);
    const assetKeys = [...new Set(row.assets.filter((h) => hostKey.has(normHost(h))).map((h) => hostKey.get(normHost(h))))].sort();
    if (!appIds.length && !row.assets.some((h) => knownHosts.has(normHost(h)))) {
      unmapped.push({
        id: row.risk_id, title: row.title, rating: row.residual_rating, status,
        applications: row.applications.join("; ") || "—", assets: row.assets.join("; ") || "—",
        evidence: evidence("risk_register", row),
        reason: "No application or asset reference matches the dependency list or the asset register",
      });
      continue;
    }
    const apps = new Set(appIds.filter((a) => inScope.has(a)));
    for (const key of assetKeys) for (const a of (assets[key].applications.length ? assets[key].applications : assets[key].subnet_applications || [])) apps.add(a);
    for (const a of [...apps]) if (!inScope.has(a)) apps.delete(a);
    if (!apps.size && !assetKeys.length) continue;
    const rank = ratingRank(row.residual_rating) || ratingRank(row.inherent_rating);
    const accepted = status.toLowerCase().includes("accept");
    const owner = (row.owner || "").trim();
    const overdue = !accepted && Boolean(row.due_date) && row.due_date < asOf;
    const acceptanceProblems = [];
    if (accepted) {
      const approver = (row.acceptance_approver || "").trim();
      if (!approver) acceptanceProblems.push("no approver recorded");
      else if (rank && rank >= 3 && !seniors.has(approver.toLowerCase())) acceptanceProblems.push(`${RATING_NAMES[rank]} risk accepted by ${approver}, not a senior approver`);
      if (!row.review_date) acceptanceProblems.push("no review date");
      else if (row.review_date < asOf) acceptanceProblems.push(`review overdue since ${row.review_date}`);
    }
    let category = (row.category || "").trim().toLowerCase();
    category = category.startsWith("app") ? "Application"
      : ["asset", "infra", "tech"].some((p) => category.startsWith(p)) ? "Asset"
        : (assetKeys.length ? "Asset" : "Application");
    linked.push({
      id: row.risk_id, title: row.title, status: status || "Open", accepted, category,
      rating: RATING_NAMES[rank] ?? (row.residual_rating || "Unrated"), rank: rank || 0,
      above: Boolean(rank) && rank > appetite, owner, no_owner: !owner,
      due_date: row.due_date || "", overdue,
      approver: row.acceptance_approver || "", review_date: row.review_date || "",
      acceptance_problems: acceptanceProblems, treatment: row.treatment_plan || "",
      apps: [...apps].sort(), asset_keys: assetKeys, hosts: assetKeys.map((k) => assets[k].hostname),
      controls: row.related_controls.map((c) => c.trim().toUpperCase()),
      in_date: !overdue && Boolean(owner) && !acceptanceProblems.length,
      evidence: evidence("risk_register", row),
    });
  }
  linked.sort((a, b) => (b.rank - a.rank) || cmp(String(a.id || ""), String(b.id || "")));
  return [linked, unmapped];
}

export function riskChecks(appId, risks, settings) {
  const mine = risks.filter((r) => r.apps.includes(appId));
  const ev = mine.map((r) => r.evidence);
  const out = {};
  const above = mine.filter((r) => r.above);
  if (above.length) {
    out.R1 = result("R1", "fail", `${above.length} open risk(s) above the ${settings.risk_appetite} appetite: `
      + above.map((r) => `${r.id} ${r.title} (${r.rating}, ${r.status})`).join("; ") + ".",
    above.map((r) => r.evidence), { risk_ids: above.map((r) => r.id), top_rank: Math.max(...above.map((r) => r.rank)) });
  } else if (mine.length) {
    out.R1 = result("R1", "pass", `${mine.length} open risk(s), none above the ${settings.risk_appetite} appetite.`, ev);
  } else {
    out.R1 = result("R1", "pass", "No open risks recorded for this application or its assets.");
  }

  const late = mine.filter((r) => r.overdue || r.no_owner);
  if (late.length) {
    const parts = late.map((r) => `${r.id}: ` + [r.overdue ? `treatment due ${r.due_date}` : "", r.no_owner ? "no owner" : ""].filter(Boolean).join(", "));
    out.R2 = result("R2", "fail", "Treatment late or unowned — " + parts.join("; ") + ".", late.map((r) => r.evidence), { risk_ids: late.map((r) => r.id) });
  } else if (mine.length) {
    out.R2 = result("R2", "pass", "Every open risk has an owner and an in-date treatment or a valid acceptance.", ev);
  } else {
    out.R2 = result("R2", "n/a", "No open risks.");
  }

  const accepted = mine.filter((r) => r.accepted);
  const bad = accepted.filter((r) => r.acceptance_problems.length);
  if (bad.length) {
    out.R3 = result("R3", "fail", "Invalid acceptance — " + bad.map((r) => `${r.id}: ${r.acceptance_problems.join(", ")}`).join("; ") + ".",
      bad.map((r) => r.evidence), { risk_ids: bad.map((r) => r.id) });
  } else if (accepted.length) {
    out.R3 = result("R3", "pass", `${accepted.length} accepted risk(s), approved at the right level and within review date.`, accepted.map((r) => r.evidence));
  } else {
    out.R3 = result("R3", "n/a", "No accepted risks.");
  }
  return out;
}

/** Risks that record this gap: linked to the asset or its application and naming the check, or linked to the
 *  asset directly with no checks named. */
export function coveringRisks(assetKey, asset, checkId, risks) {
  const apps = new Set(asset.applications.length ? asset.applications : asset.subnet_applications || []);
  return risks.filter((r) => {
    const onAsset = r.asset_keys.includes(assetKey);
    const onApp = r.apps.some((a) => apps.has(a));
    return (r.controls.includes(checkId) && (onAsset || onApp)) || (onAsset && !r.controls.length);
  });
}

// --- Step 9: DR test results ---------------------------------------------------------------------------

export function drAssessment(app, rows, resolve, appAssets, tolerance, asOf, settings, risks) {
  const tests = rows.filter((r) => resolve(r.application) === app.id);
  const latest = maxBy(tests, (r) => r.test_date || "");
  const res = {};
  let recovery;
  let test = null;
  if (!latest) {
    for (const c of ["D2", "D3", "D4"]) res[c] = result(c, "no_data", "No DR test recorded.");
    res.D1 = result("D1", "fail", "No DR test recorded for this application.");
    recovery = { status: "untested", achieved: null, margin_pct: null };
  } else {
    const ev = [evidence("dr_tests", latest)];
    const age = latest.test_date ? ageDays(asOf, latest.test_date) : null;
    const resultText = (latest.result || "").trim();
    const hosts = appAssets.map((a) => a.hostname);
    const scope = new Set(latest.scope.map(normHost));
    const missing = hosts.filter((h) => scope.size && !scope.has(normHost(h)));
    const problems = [];
    if (age === null) problems.push("test date missing");
    else if (age > settings.dr_test_max_age_days) problems.push(`last test ${age} days ago (policy ${g(settings.dr_test_max_age_days)} days)`);
    if (!PASSED.has(resultText.toLowerCase())) problems.push(`result '${resultText || "blank"}'`);
    if (missing.length) problems.push(`partial scope, not tested: ${missing.join(", ")}`);
    res.D1 = problems.length
      ? result("D1", "fail", `Last test ${latest.test_date} (${latest.test_type || "type not stated"}): ${problems.join("; ")}.`, ev)
      : result("D1", "pass", `${latest.test_type || "Test"} on ${latest.test_date} passed, covering all ${hosts.length} assets.`, ev);

    const achieved = latest.achieved_rto_hours;
    const rto = latest.rto_hours;
    if (achieved === null) res.D2 = result("D2", "no_data", "Achieved recovery time not recorded.", ev);
    else if (achieved > tolerance) {
      res.D2 = result("D2", "fail", `Recovered in ${g(achieved)}h, beyond the ${g(tolerance)}h service impact tolerance`
        + `${rto !== null && achieved > rto ? ` and the ${g(rto)}h RTO` : ""}.`, ev, { exceeds_tolerance: true });
    } else if (rto !== null && achieved > rto) {
      res.D2 = result("D2", "fail", `Recovered in ${g(achieved)}h, beyond the ${g(rto)}h RTO (within the ${g(tolerance)}h tolerance).`, ev);
    } else {
      res.D2 = result("D2", "pass", `Recovered in ${g(achieved)}h against a ${rto !== null ? g(rto) : "—"}h RTO and ${g(tolerance)}h tolerance.`, ev);
    }

    const loss = latest.achieved_rpo_hours;
    const rpo = latest.rpo_hours;
    if (loss === null || rpo === null) res.D3 = result("D3", "no_data", "Recovery point objective or achieved data loss not recorded.", ev);
    else if (loss > rpo) res.D3 = result("D3", "fail", `Lost ${g(loss)}h of data against a ${g(rpo)}h RPO.`, ev);
    else res.D3 = result("D3", "pass", `Lost ${g(loss)}h of data, within the ${g(rpo)}h RPO.`, ev);

    const issues = (latest.open_issues || "").trim();
    if (!issues || ["none", "0", "n/a", "-"].includes(issues.toLowerCase())) res.D4 = result("D4", "pass", "No open issues from the last test.", ev);
    else if (latest.issue_due_date && latest.issue_due_date < asOf) res.D4 = result("D4", "fail", `Open since the test and past due ${latest.issue_due_date}: ${issues}.`, ev);
    else res.D4 = result("D4", "pass", `Open but within due date ${latest.issue_due_date || "(none set)"}: ${issues}.`, ev);

    // A demonstrated breach of tolerance outranks an incomplete test.
    let status;
    if (achieved !== null && achieved > tolerance) status = "exceeds";
    else if (res.D1.status === "fail" || achieved === null) status = "unproven";
    else {
      const margin = tolerance ? (100 * (tolerance - achieved)) / tolerance : 0;
      status = margin < settings.thin_margin_pct ? "thin" : "proven";
    }
    recovery = { status, achieved, margin_pct: achieved !== null && tolerance ? round((100 * (tolerance - achieved)) / tolerance, 1) : null };
    test = Object.fromEntries(["test_date", "test_type", "scope", "rto_hours", "achieved_rto_hours", "rpo_hours", "achieved_rpo_hours",
      "result", "open_issues", "issue_due_date"].map((k) => [k, ev[0].values[k] ?? ""]));
    test.age_days = age;
  }

  for (const [c, r] of Object.entries(res)) {
    if (r.status === "fail") r.risk_ids = risks.filter((x) => x.apps.includes(app.id) && x.controls.includes(c)).map((x) => x.id);
  }
  return { id: app.id, name: app.name, test, results: res, recovery, test_count: tests.length };
}

/** Scenario recovery = its worst application; all of them must be back for the scenario to end. */
export function combineRecovery(perApp, tolerance, appNames) {
  if (!perApp.length) return { status: "untested", achieved: null, label: "No applications with recovery data.", apps: [] };
  const worst = maxBy(perApp, (d) => RECOVERY_RANK[d.recovery.status]);
  const achieved = perApp.map((d) => d.recovery.achieved).filter((v) => v !== null && v !== undefined);
  const status = worst.recovery.status;
  const name = appNames[worst.id] ?? worst.id;
  const tol = `${g(tolerance)}h`;
  let label;
  if (status === "untested") label = `${name} has no DR test, so recovery within ${tol} is unproven`;
  else if (status === "unproven") {
    const detail = worst.results.D1.detail;
    const i = detail.indexOf(": ");
    label = `${name}'s DR test does not prove recovery (${(i >= 0 ? detail.slice(i + 2) : detail).replace(/\.+$/, "")})`;
  } else if (status === "exceeds") label = `${name} took ${g(worst.recovery.achieved)}h to recover in its last DR test, beyond the ${tol} tolerance`;
  else if (status === "thin") label = `recovery is proven but on a thin margin: ${name} took ${g(worst.recovery.achieved)}h of the ${tol} tolerance`;
  else label = `recovery is proven within ${g(Math.max(...achieved))}h against the ${tol} tolerance`;
  return {
    status, achieved: achieved.length ? Math.max(...achieved) : null, label,
    apps: perApp.map((d) => ({ id: d.id, status: d.recovery.status, achieved: d.recovery.achieved })),
  };
}
