// Screens and actions. Route names match the templates' url("name", {...}) calls.
import express from "express";
import multer from "multer";

import { checkCsrf } from "./app.js";
import { DEFAULT_SETTINGS } from "./config.js";
import { CHECK_ORDER, CHECKS } from "./engine/checks.js";
import { businessImpact } from "./engine/narrative.js";
import { HostIndex, allApplications, assess, catalogue, findingSeverity } from "./engine/pipeline.js";
import { appResolver } from "./engine/riskRecovery.js";
import { FILES, generate } from "./sampleData.js";
import { KIND_ORDER, SOURCES, SourceError, activeFile, isReady, loadAll, loadRows, missingRequired, storeUpload } from "./sources.js";
import { getResult, getRun, getSettings, listRuns, previousRun, resetSettings, saveRun, saveSettings, setProgress } from "./store.js";
import { addDays, ageDays, normHost, parseDate, today } from "./util.js";
import path from "node:path";

export const ROUTES = {
  start: "/", service_panel: "/service-panel", preview: "/preview", run_assessment: "/run",
  data_sources: "/data", upload: "/data/{kind}/upload", mapping: "/data/{kind}/mapping", reset_samples: "/data/reset-samples",
  runs: "/runs", run_overview: "/runs/{run_id}", run_step: "/runs/{run_id}/step/{n}", run_step_next: "/runs/{run_id}/step/{n}/next",
  run_all_risks: "/runs/{run_id}/all-risks", run_matrix: "/runs/{run_id}/matrix", result_detail: "/runs/{run_id}/result/{result_id}",
  findings_csv: "/runs/{run_id}/findings.csv", settings_page: "/settings",
  // Earlier tab addresses; each redirects to its step.
  run_impact: "/runs/{run_id}/impact", run_assets: "/runs/{run_id}/assets", run_risks: "/runs/{run_id}/risks",
  run_dr: "/runs/{run_id}/dr", run_exceptions: "/runs/{run_id}/exceptions", run_findings: "/runs/{run_id}/findings",
};

// The assessment flow. Steps 1–9 each check one source; 10 and 11 build on everything before them.
export const STEPS = [
  { n: 1, key: "assets", title: "Assets", source: "Asset register and discovery scan", checks: ["T1", "T2", "T3", "H1"],
    intro: "Servers and databases behind the selected applications, reconciled with discovery, with categorisation and ownership checked." },
  { n: 2, key: "patch", title: "Patch compliance", source: "Vulnerability scanner", checks: ["T4", "T5", "P2"],
    intro: "Open vulnerabilities against the patch SLA, unsupported software, and patching performance." },
  { n: 3, key: "malware", title: "Anti-malware", source: "Antivirus / EDR console", checks: ["T6", "T7"],
    intro: "Whether each asset has a healthy, reporting agent with current signatures." },
  { n: 4, key: "pam", title: "Privileged access", source: "PAM tool and server account lists", checks: ["T8"],
    intro: "Whether the privileged accounts on application and database servers are onboarded to the PAM vault." },
  { n: 5, key: "siem", title: "SIEM log flow", source: "SIEM log sources", checks: ["T9"],
    intro: "Whether logs are flowing from each asset to the SIEM." },
  { n: 6, key: "exceptions", title: "Exceptions", source: "Exception register", checks: ["P1"],
    intro: "Exceptions raised for these assets in any of the categories above, and whether they are still valid." },
  { n: 7, key: "risks", title: "Open risks", source: "Information security risk register", checks: ["R1", "R2", "R3", "R4"],
    intro: "Open application security and asset risks for the applications, and gaps found above that are not recorded as risks." },
  { n: 8, key: "backups", title: "Backups and restores", source: "Backup management tool", checks: ["B1", "B2", "B3", "B4"],
    intro: "Whether backups are scheduled and succeeding, have a protected copy, and have been restore-tested within the tolerance." },
  { n: 9, key: "dr", title: "DR tests", source: "DR test results", checks: ["D1", "D2", "D3", "D4"],
    intro: "The latest DR test per application, against its objectives and the service impact tolerance." },
  { n: 10, key: "impact", title: "Business impact", source: "All steps", checks: [],
    intro: "What the issues and risks found mean for the service and its impact tolerance, in business language." },
  { n: 11, key: "scenarios", title: "Plausible scenarios", source: "Generated from the risks", checks: [],
    intro: "Scenarios to test, generated from the issues and risks found, each rated against the impact tolerance." },
];
const FINAL_STEP = STEPS.length + 1; // progress beyond the last step: the run is complete and every view is open
const STEP_OF = Object.fromEntries(STEPS.flatMap((s) => s.checks.map((c) => [c, s])));
const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, "Data quality": 4 };
const SEVERITY_POINTS = { Critical: 9, High: 6, Medium: 3, Low: 1, "Data quality": 0 };

const countBy = (items, fn) => items.reduce((acc, x) => { const k = fn(x); acc[k] = (acc[k] || 0) + 1; return acc; }, {});
const titleCase = (s) => String(s).toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
// Lookups keyed by user input must not reach Object.prototype ("__proto__", "constructor", ...).
const ownKey = (obj, key) => (typeof key === "string" && Object.hasOwn(obj, key) ? obj[key] : undefined);
const one = (v) => (Array.isArray(v) ? v[0] : v); // a repeated form field counts once
const RISK_LEVELS = ["Low", "Medium", "High", "Critical"];

/** Some application-level failures are Critical whatever their score. */
function appSeverityFloor(run, r) {
  const extra = r.extra || {};
  if (r.check_id === "R1" && extra.top_rank === 4) return "Critical";
  if (r.check_id === "D1" && run.service_tier === 1) return "Critical";
  if (r.check_id === "D2" && extra.exceeds_tolerance) return "Critical";
  return null;
}

/** Every risk the run identified: failed, excepted and (for Tier 1) no-data results, scored and ranked. */
export function findingsOf(run) {
  const out = [];
  for (const asset of run.assets) {
    const factor = asset.modifiers.reduce((f, m) => f * run.settings.modifiers[m], 1);
    for (const r of asset.results) {
      if (!(["fail", "excepted"].includes(r.status) || (r.status === "no_data" && run.service_tier === 1))) continue;
      const base = run.settings.check_weights[r.check_id] ?? 1;
      const severity = r.status === "fail" ? (r.check_id === "R4" ? "Medium" : findingSeverity(base, factor))
        : r.status === "excepted" ? "Low" : "Data quality";
      out.push({ result: r, asset, app: null, subject: asset.hostname, owner: asset.owner,
        applications: asset.applications.length ? asset.applications : asset.subnet_applications, modifiers: asset.modifiers,
        severity, effective: Math.round(r.weight * factor * 100) / 100 });
    }
  }
  const apps = Object.fromEntries(run.applications.map((a) => [a.id, a]));
  for (const r of run.results) {
    if (!r.application_id || !["fail", "no_data"].includes(r.status)) continue;
    if (r.status === "no_data" && run.service_tier !== 1) continue;
    const app = apps[r.application_id] ?? { id: r.application_id, name: r.application_id, owner: "" };
    const factor = r.extra?.factor ?? 1;
    const weight = r.weight || (r.status === "fail" ? Number(run.settings.check_weights[r.check_id] ?? 0) : 0);
    let severity = "Data quality";
    if (r.status === "fail") {
      severity = findingSeverity(weight, factor);
      const floor = appSeverityFloor(run, r);
      if (floor && SEVERITY_ORDER[floor] < SEVERITY_ORDER[severity]) severity = floor;
    }
    out.push({ result: r, asset: null, app, subject: app.name, owner: app.owner || "", applications: [app.id],
      modifiers: factor > 1 ? ["concentration"] : [], severity, effective: Math.round(weight * factor * 100) / 100 });
  }
  return out.sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || (b.effective - a.effective) || (a.subject < b.subject ? -1 : a.subject > b.subject ? 1 : 0));
}

const isComplete = (run) => (run.mode || "full") !== "step" || (run.progress || 0) >= FINAL_STEP;

export function buildRoutes({ db, config, authorize = () => true }) {
  const router = express.Router();
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: config.maxUploadBytes, files: 1, fields: 10, fieldSize: 10_000, parts: 12 } });
  // Authorisation by action: "view" (results), "assess" (start and step through runs), "manage" (data sources, settings).
  const need = (action) => (req, res, next) => (authorize(req, action) ? next() : res.status(403).send("You do not have access to this page."));
  router.use(need("view"));

  async function cataloguePair() {
    const deps = loadRows(await activeFile(db, "dependencies"));
    return [catalogue(deps), allApplications(deps, loadRows(await activeFile(db, "asset_register")))];
  }

  async function missingSources() {
    // CONNECTOR (Phase 5): with connectors, "missing" means "no successful pull yet" rather than "no upload".
    const out = [];
    for (const k of KIND_ORDER) if (!isReady(await activeFile(db, k))) out.push(SOURCES[k].label);
    return out;
  }

  /**
   * What will be extracted for these applications: assets from the register and matching rows in each source.
   * CONNECTOR (Phase 5): reads the latest stored data for every source. A connector could instead query the tool
   * here for just the selected hosts and applications, but keep the counts the same shape.
   */
  async function preview(appIds) {
    const scope = new Set(appIds);
    const registerRows = loadRows(await activeFile(db, "asset_register"));
    const register = registerRows.filter((r) => r.application_id.some((a) => scope.has(a)));
    const perApp = {};
    const hosts = new Map();
    for (const r of register) {
      const k = r.asset_id || r.hostname;
      if (!hosts.has(k)) hosts.set(k, r);
      for (const a of r.application_id) if (scope.has(a)) perApp[a] = (perApp[a] || 0) + 1;
    }
    const types = countBy([...hosts.values()], (r) => titleCase(r.asset_type || "Unknown"));
    const sources = [];
    for (const kind of ["discovery", "vulnerabilities", "antivirus", "pam", "privileged_accounts", "siem", "backups", "exceptions"]) {
      const index = new HostIndex(loadRows(await activeFile(db, kind)));
      let matched = 0;
      let covered = 0;
      for (const r of hosts.values()) {
        const [found] = index.find(r.hostname, r.ip, r.asset_id);
        matched += found.length;
        covered += found.length ? 1 : 0;
      }
      // Most assets have no exception, so coverage means nothing for the exception register.
      sources.push({ label: SOURCES[kind].label, rows: matched, covered: kind === "exceptions" ? null : covered });
    }
    const resolve = appResolver(loadRows(await activeFile(db, "dependencies")), registerRows);
    const hostKeys = new Set([...hosts.values()].flatMap((r) => [normHost(r.hostname), r.asset_id ? normHost(r.asset_id) : null]).filter(Boolean));
    const riskRows = loadRows(await activeFile(db, "risk_register"))
      .filter((r) => r.applications.some((x) => scope.has(resolve(x))) || r.assets.some((x) => hostKeys.has(normHost(x))));
    const drRows = loadRows(await activeFile(db, "dr_tests")).filter((r) => scope.has(resolve(r.application)));
    sources.push({ label: SOURCES.risk_register.label, rows: riskRows.length, covered: null });
    sources.push({ label: SOURCES.dr_tests.label, rows: drRows.length, covered: new Set(drRows.map((r) => resolve(r.application))).size, of: scope.size, unit: "apps" });
    return { app_count: scope.size, asset_count: hosts.size, types, per_app: perApp, sources, apps_without_assets: appIds.filter((a) => !perApp[a]) };
  }

  async function panelContext(name, services, apps) {
    const svc = ownKey(services, name);
    if (!svc) return { svc: null };
    const own = new Set(svc.applications.map((a) => a.id));
    return { svc, other_apps: apps.filter((a) => !own.has(a.id)), today: today(), preview: await preview(svc.applications.map((a) => a.id)) };
  }

  async function loadRun(req, res) {
    const run = await getRun(db, req.params.run_id);
    if (!run) { res.status(404).send("Not found"); return null; }
    return run;
  }

  function guardComplete(run, req, res) {
    if (isComplete(run)) return false;
    req.flash("info", "Finish the steps first; the summary and all risks open after step 11.");
    res.redirect(res.locals.url("run_step", { run_id: run.id, n: run.progress || 1 }));
    return true;
  }

  // --- New assessment -------------------------------------------------------------------------------
  router.get("/", asyncRoute(async (req, res) => {
    const [services, apps] = await cataloguePair();
    const selected = String(one(req.query.service) || "");
    res.render("start.html", { services, selected, runs: await listRuns(db, 8), missing: await missingSources(), ...(await panelContext(selected, services, apps)), endpoint: "start" });
  }));

  router.get("/service-panel", asyncRoute(async (req, res) => {
    const [services, apps] = await cataloguePair();
    res.render("_service_panel.html", await panelContext(String(one(req.query.service) || ""), services, apps));
  }));

  router.post("/preview", need("assess"), asyncRoute(async (req, res) => {
    res.render("_preview.html", { preview: await preview([].concat(req.body.apps || []).map(String).slice(0, 500)) });
  }));

  router.post("/run", need("assess"), asyncRoute(async (req, res) => {
    const [services, apps] = await cataloguePair();
    const name = String(one(req.body.service) || "");
    const svc = ownKey(services, name);
    if (!svc) { req.flash("error", "Choose a critical service first."); return res.redirect(res.locals.url("start")); }
    const appIds = [...new Set([].concat(req.body.apps || []).map(String))].slice(0, 500);
    if (!appIds.length) { req.flash("error", "Select at least one application the service depends on."); return res.redirect(res.locals.url("start", { service: name })); }
    const byId = new Map([...apps, ...svc.applications].map((a) => [a.id, a]));
    const mode = one(req.body.mode) === "step" ? "step" : "full";
    const tier = Number(one(req.body.tier) || svc.tier);
    const tolerance = Number(one(req.body.tolerance) || svc.tolerance_hours);
    if (!Number.isInteger(tier) || tier < 1 || tier > 4 || !Number.isFinite(tolerance) || tolerance <= 0 || tolerance > 8760) {
      req.flash("error", "Tier must be 1 to 4 and the impact tolerance between 0 and 8,760 hours.");
      return res.redirect(res.locals.url("start", { service: name }));
    }
    const defn = { name, tier, tolerance_hours: tolerance, applications: appIds.filter((a) => byId.has(a)).map((a) => byId.get(a)), as_of: parseDate(one(req.body.as_of)) || today() };
    if (!defn.applications.length) { req.flash("error", "Select at least one application the service depends on."); return res.redirect(res.locals.url("start", { service: name })); }
    const settings = await getSettings(db);
    // CONNECTOR (Phase 5): loadAll() is the evidence snapshot this run is assessed on. To assess live data, trigger a
    // pull from each connector here (or in a background job before the run) and then loadAll().
    const result = assess(defn, await loadAll(db), settings);
    const runId = await saveRun(db, defn, result, settings, mode, req.coraUser());
    if (mode === "step") {
      req.flash("success", `Evidence extracted for ${result.assets.length} assets. Review each step, then select Next.`);
      return res.redirect(res.locals.url("run_step", { run_id: runId, n: 1 }));
    }
    req.flash("success", `Assessment complete: ${result.assets.length} assets checked against ${CHECK_ORDER.length} rules.`);
    return res.redirect(res.locals.url("run_overview", { run_id: runId }));
  }));

  // --- Data sources -------------------------------------------------------------------------------------
  router.get("/data", need("manage"), asyncRoute(async (req, res) => {
    const settings = await getSettings(db);
    const rows = [];
    for (const kind of KIND_ORDER) {
      const rec = await activeFile(db, kind);
      const age = rec ? ageDays(today(), rec.export_date) : null;
      rows.push({ spec: SOURCES[kind], rec, missing: rec ? missingRequired(SOURCES[kind], rec.mapping) : [], age, stale: age !== null && age > settings.file_max_age_days });
    }
    res.render("data.html", { rows, today: today(), sample_reset: config.enableSampleReset, endpoint: "data_sources" });
  }));

  router.post("/data/:kind/upload", need("manage"), upload.single("file"), asyncRoute(async (req, res) => {
    // CONNECTOR (Phase 5): manual CSV upload, the interface every source uses today. Keep it as the fallback for tools
    // without an API; a connector-backed source would show "Pull now" and its schedule instead.
    if (!checkCsrf(req)) return res.status(403).send("Invalid or missing CSRF token. Reload the page and try again.");
    const { kind } = req.params;
    if (!ownKey(SOURCES, kind)) return res.status(404).send("Not found");
    if (!req.file) { req.flash("error", "Choose a CSV file to upload."); return res.redirect(res.locals.url("data_sources")); }
    let rec;
    try {
      rec = await storeUpload(db, config.uploadDir, kind, req.file.originalname, req.file.buffer, parseDate(one(req.body.export_date)) || today(), { uploadedBy: req.coraUser() });
    } catch (err) {
      if (!(err instanceof SourceError) && !String(err.code || "").startsWith("CSV_")) throw err;
      req.flash("error", `${SOURCES[kind].label}: ${err.message}`);
      return res.redirect(res.locals.url("data_sources"));
    }
    if (missingRequired(SOURCES[kind], rec.mapping).length) req.flash("info", "Some required columns could not be matched automatically. Map them below.");
    else req.flash("success", `${SOURCES[kind].label}: ${rec.row_count} rows loaded; all columns mapped automatically.`);
    return res.redirect(res.locals.url("mapping", { kind }));
  }));

  router.all("/data/:kind/mapping", need("manage"), asyncRoute(async (req, res) => {
    // CONNECTOR (Phase 5): column mapping exists because every bank's CSV export differs. A connector maps API fields to
    // the source's field keys in code, so this screen applies only to uploaded files.
    const { kind } = req.params;
    if (!ownKey(SOURCES, kind)) return res.status(404).send("Not found");
    const rec = await activeFile(db, kind);
    if (!rec) { req.flash("error", "No file loaded for this source yet."); return res.redirect(res.locals.url("data_sources")); }
    const spec = SOURCES[kind];
    if (req.method === "POST") {
      const mapping = Object.fromEntries(spec.fields.map((f) => [f.key, one(req.body[`map_${f.key}`])]).filter(([, h]) => typeof h === "string" && rec.headers.includes(h)));
      await db.collection("source_files").updateOne({ id: rec.id }, { $set: { mapping, mapped_by: req.coraUser(), mapped_at: new Date() } });
      rec.mapping = mapping;
      const missing = missingRequired(spec, mapping);
      if (missing.length) req.flash("error", `Still unmapped: ${missing.map((f) => f.label).join(", ")}`);
      else { req.flash("success", "Column mapping saved."); return res.redirect(res.locals.url("mapping", { kind })); }
    }
    res.render("mapping.html", { spec, rec, preview: loadRows(rec).slice(0, 15), missing: missingRequired(spec, rec.mapping), endpoint: "mapping" });
  }));

  router.post("/data/reset-samples", need("manage"), asyncRoute(async (req, res) => {
    // Demo only: reloads the synthetic CSVs for every source. Off unless enableSampleReset (the demo server) is set.
    if (!config.enableSampleReset) return res.status(404).send("Not found");
    await loadSamples(db, config, { all: true });
    req.flash("success", "Synthetic data set regenerated with today's dates and loaded for every source.");
    res.redirect(res.locals.url("data_sources"));
  }));

  // --- Assessment runs ------------------------------------------------------------------------------------
  router.get("/runs", asyncRoute(async (req, res) => res.render("runs/list.html", { runs: await listRuns(db), endpoint: "runs" })));

  router.get("/runs/:run_id", asyncRoute(async (req, res) => {
    const run = await loadRun(req, res);
    if (!run || guardComplete(run, req, res)) return;
    const findings = findingsOf(run);
    const rank = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    const scenarios = [...run.scenario_results].sort((a, b) => (rank[a.rating] - rank[b.rating]) || (b.score - a.score));
    res.render("runs/overview.html", {
      run, counts: countBy(run.results, (r) => r.status), severity_counts: countBy(findings, (f) => f.severity),
      by_check: Object.fromEntries(CHECK_ORDER.map((c) => [c, countBy(run.results.filter((r) => r.check_id === c), (r) => r.status)])),
      scenarios, scale: Math.max(run.settings.rating_thresholds.critical, ...run.scenario_results.map((s) => s.score)),
      top_assets: [...run.assets].sort((a, b) => b.score - a.score).slice(0, 6), previous: await previousRun(db, run),
      impact: businessImpact(run, findings), tab: "overview", endpoint: "run",
    });
  }));

  router.get("/runs/:run_id/step/:n", asyncRoute(async (req, res) => {
    const run = await loadRun(req, res);
    if (!run) return;
    const n = Number(req.params.n);
    if (!(n >= 1 && n <= STEPS.length)) return res.status(404).send("Not found");
    if ((run.mode || "full") === "step" && n > (run.progress || 1)) {
      req.flash("info", "Complete the earlier steps first.");
      return res.redirect(res.locals.url("run_step", { run_id: run.id, n: run.progress || 1 }));
    }
    const step = STEPS[n - 1];
    const findings = findingsOf(run);
    const impact = businessImpact(run, findings);
    const ctx = {
      run, step, steps: STEPS, tab: `step${n}`, impact, statements: impact.statements, final_step: FINAL_STEP, complete: isComplete(run), endpoint: "run",
      step_findings: findings.filter((f) => step.checks.includes(f.result.check_id) && f.severity !== "Data quality"),
      data_quality: findings.filter((f) => step.checks.includes(f.result.check_id) && f.severity === "Data quality"),
    };
    if (step.checks.length) {
      ctx.results = run.results.filter((r) => step.checks.includes(r.check_id));
      ctx.app_results = Object.fromEntries(run.results.filter((r) => r.application_id).map((r) => [`${r.application_id}|${r.check_id}`, r]));
      ctx.grid = Object.fromEntries(run.assets.map((a) => [a.id, Object.fromEntries(a.results.map((r) => [r.check_id, r]))]));
      ctx.assets = [...run.assets].sort((a, b) => (Number(!a.registered) - Number(!b.registered)) || String(a.asset_type || "").localeCompare(String(b.asset_type || "")) || (a.hostname < b.hostname ? -1 : 1));
      ctx.app_names = Object.fromEntries(run.applications.map((a) => [a.id, a.name]));
    }
    if (step.key === "assets") ctx.t3 = Object.fromEntries(run.assets.map((a) => [a.id, a.results.find((r) => r.check_id === "T3") || null]));
    if (step.key === "exceptions") {
      ctx.applied = run.results.filter((r) => r.exception);
      ctx.p1 = run.results.filter((r) => r.check_id === "P1" && r.status !== "n/a");
    }
    if (step.key === "risks") {
      ctx.unrecorded = run.results.filter((r) => r.check_id === "R4" && r.status === "fail");
      ctx.risks = run.risks || [];
      ctx.unmapped = run.unmapped_risks || [];
    }
    if (step.key === "dr") {
      ctx.dr = run.dr_results || [];
      ctx.dr_scale = Math.max(run.impact_tolerance_hours * 1.5, ...ctx.dr.map((d) => d.recovery.achieved).filter((v) => typeof v === "number"));
    }
    if (step.key === "impact") {
      const serious = Object.values(impact.statements).filter((st) => ["Critical", "High"].includes(st.finding.severity));
      ctx.impact_groups = STEPS.filter((s) => s.checks.length)
        .map((s) => [s.title, serious.filter((st) => s.checks.includes(st.finding.result.check_id)).sort((a, b) => b.finding.effective - a.finding.effective)])
        .filter(([, items]) => items.length);
    }
    return res.render("runs/step.html", ctx);
  }));

  router.post("/runs/:run_id/step/:n/next", need("assess"), asyncRoute(async (req, res) => {
    const run = await loadRun(req, res);
    if (!run) return;
    const n = Number(req.params.n);
    if (!Number.isInteger(n) || n < 1 || n > STEPS.length) return res.status(404).send("Not found");
    if ((run.mode || "full") === "step") {
      // Steps open in order: Next on a step the analyst has not reached yet does nothing.
      if (n > (run.progress || 1)) return res.redirect(res.locals.url("run_step", { run_id: run.id, n: run.progress || 1 }));
      await setProgress(db, run.id, n + 1);
    }
    if (n >= STEPS.length) {
      req.flash("success", "Assessment complete. All risks are listed below with their scores.");
      return res.redirect(res.locals.url("run_all_risks", { run_id: run.id }));
    }
    return res.redirect(res.locals.url("run_step", { run_id: run.id, n: n + 1 }));
  }));

  router.get("/runs/:run_id/all-risks", asyncRoute(async (req, res) => {
    const run = await loadRun(req, res);
    if (!run || guardComplete(run, req, res)) return;
    const findings = findingsOf(run);
    const impact = businessImpact(run, findings);
    res.render("runs/all_risks.html", { run, findings, statements: impact.statements, impact, step_of: STEP_OF, severity_counts: countBy(findings, (f) => f.severity), tab: "all", endpoint: "run" });
  }));

  router.get("/runs/:run_id/matrix", asyncRoute(async (req, res) => {
    const run = await loadRun(req, res);
    if (!run || guardComplete(run, req, res)) return;
    const grid = Object.fromEntries(run.assets.map((a) => [a.id, Object.fromEntries(a.results.map((r) => [r.check_id, r]))]));
    const assets = [...run.assets].sort((a, b) => (b.score - a.score) || (a.hostname < b.hostname ? -1 : 1));
    res.render("runs/matrix.html", { run, grid, assets, tab: "matrix", endpoint: "run" });
  }));

  // Earlier tab addresses open the matching step.
  for (const [route, n] of [["impact", 10], ["assets", 1], ["risks", 7], ["dr", 9], ["exceptions", 6]]) {
    router.get(`/runs/:run_id/${route}`, (req, res) => res.redirect(res.locals.url("run_step", { run_id: req.params.run_id, n })));
  }
  router.get("/runs/:run_id/findings", (req, res) => res.redirect(res.locals.url("run_all_risks", { run_id: req.params.run_id })));

  router.get("/runs/:run_id/result/:result_id", asyncRoute(async (req, res) => {
    const run = await loadRun(req, res);
    if (!run) return;
    const result = run.results.find((r) => r.id === Number(req.params.result_id));
    if (!result) return res.status(404).send("Not found");
    const app = run.applications.find((a) => a.id === result.application_id) || null;
    const step = STEPS.find((s) => s.checks.includes(result.check_id)) || STEPS[0];
    const template = req.get("HX-Request") ? "runs/_result.html" : "runs/result.html";
    res.render(template, { run, r: result, asset: result.asset, app, steps: STEPS, step, tab: `step${step.n}`, final_step: FINAL_STEP, complete: isComplete(run), endpoint: "run" });
  }));

  router.get("/runs/:run_id/findings.csv", asyncRoute(async (req, res) => {
    const run = await loadRun(req, res);
    if (!run || guardComplete(run, req, res)) return;
    const findings = findingsOf(run);
    const { statements } = businessImpact(run, findings);
    const rows = [["Run", "Service", "As of", "Severity", "Risk score", "Step", "Level", "Asset ID", "Asset or application", "Applications",
      "Owner", "Check", "Check name", "Status", "Detail", "Modifiers", "Exception", "Linked risks", "Business impact",
      "Impact on service and tolerance", "Scenarios affected", "Other services affected", "Recommended action", "Urgency"]];
    for (const f of findings) {
      const r = f.result;
      const a = f.asset;
      const st = statements[r.id];
      const s = STEP_OF[r.check_id];
      rows.push([run.id, run.service_name, run.as_of, f.severity, f.effective, s ? `${s.n}. ${s.title}` : "", a ? "Asset" : "Application", a ? a.asset_id : "",
        f.subject, f.applications.join("; "), f.owner, r.check_id, CHECKS[r.check_id].name, r.status, r.detail, f.modifiers.join("; "),
        r.exception?.values?.exception_id || "", (r.linked_risks || []).join("; "),
        ...(st ? [st.meaning, st.service_effect, st.scenarios.join("; "), st.other_services.join("; "), st.action, st.urgency] : ["", "", "", "", "", ""])]);
    }
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename=risks_run${run.id}.csv`);
    res.send(rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n");
  }));

  // --- Settings -------------------------------------------------------------------------------------------
  router.all("/settings", need("manage"), asyncRoute(async (req, res) => {
    if (req.method === "POST") {
      if (req.body.reset) {
        await resetSettings(db);
        req.flash("success", "Settings reset to defaults.");
        return res.redirect(res.locals.url("settings_page"));
      }
      const values = {};
      for (const [key, def] of Object.entries(DEFAULT_SETTINGS)) {
        if (def && typeof def === "object") {
          values[key] = {};
          for (const k of Object.keys(def)) values[key][k] = Number(one(req.body[`${key}.${k}`]));
        } else if (typeof def === "string") {
          values[key] = String(one(req.body[key]) ?? "").trim().slice(0, 500) || def;
        } else {
          values[key] = Number(one(req.body[key]));
        }
      }
      const numbers = Object.values(values).flatMap((v) => (typeof v === "object" ? Object.values(v) : [v])).filter((v) => typeof v === "number");
      if (numbers.some((v) => !Number.isFinite(v) || v < 0 || v > 100_000)) {
        req.flash("error", "Every numeric setting must be a number between 0 and 100,000.");
        return res.redirect(res.locals.url("settings_page"));
      }
      if (values.patch_sla_target_pct > 100 || values.thin_margin_pct > 100 || !RISK_LEVELS.includes(values.risk_appetite)) {
        req.flash("error", "Percentages must be 100 or less, and the risk appetite one of Low, Medium, High or Critical.");
        return res.redirect(res.locals.url("settings_page"));
      }
      await saveSettings(db, values, req.coraUser());
      req.flash("success", "Settings saved. They apply to new runs; existing runs keep the values they were run with.");
      return res.redirect(res.locals.url("settings_page"));
    }
    return res.render("settings.html", { settings: await getSettings(db), defaults: DEFAULT_SETTINGS, endpoint: "settings_page" });
  }));

  return router;
}

/** Cells starting with = + - @ (or a tab/return) are prefixed with ' so spreadsheets never run them as formulas. */
export function csvCell(value) {
  let s = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Load the synthetic data set, dated today, for every source (all: true) or only those with no file yet. */
export async function loadSamples(db, config, { all = false } = {}) {
  const missing = [];
  for (const kind of Object.keys(FILES)) if (all || !(await activeFile(db, kind))) missing.push(kind);
  if (!missing.length) return [];
  const asOf = today();
  const paths = generate(path.join(config.dataDir, "samples"), asOf);
  const fs = await import("node:fs");
  for (const kind of missing) await storeUpload(db, config.uploadDir, kind, FILES[kind], fs.readFileSync(paths[kind]), addDays(asOf, -1));
  return missing;
}
