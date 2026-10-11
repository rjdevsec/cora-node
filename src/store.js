// Persistence: assessment runs (dated snapshots) and the client's settings, in MongoDB.
import { DEFAULT_SETTINGS } from "./config.js";
import { APP_CHECKS, ASSET_CHECKS } from "./engine/checks.js";
import { nextId } from "./db.js";

const clone = (v) => structuredClone(v);

function merge(base, override) {
  const out = clone(base);
  for (const [k, v] of Object.entries(override || {})) {
    if (v && typeof v === "object" && !Array.isArray(v) && out[k] && typeof out[k] === "object") out[k] = merge(out[k], v);
    else if (k in out) out[k] = v;
  }
  return out;
}

// --- Settings --------------------------------------------------------------------------------------------

export async function getSettings(db) {
  const doc = await db.collection("settings").findOne({ _id: "rules" });
  return merge(DEFAULT_SETTINGS, doc?.value);
}

export async function saveSettings(db, values, user = null) {
  await db.collection("settings").updateOne({ _id: "rules" },
    { $set: { value: merge(DEFAULT_SETTINGS, values), updated_by: user, updated_at: new Date() } }, { upsert: true });
}

export async function resetSettings(db) {
  await db.collection("settings").deleteOne({ _id: "rules" });
}

// --- Runs ------------------------------------------------------------------------------------------------

/** Persist an assessment result as a dated snapshot; returns the run id. */
export async function saveRun(db, defn, res, settings, mode, user = null) {
  const id = await nextId(db, "runs");
  const firstAsset = await nextId(db, "run_assets", Math.max(res.assets.length, 1));
  const assets = res.assets.map((a, i) => ({
    id: firstAsset + i, asset_id: a.asset_id, hostname: a.hostname, ip: a.ip, asset_type: a.asset_type,
    applications: a.applications, environment: a.environment, criticality: a.criticality, owner: a.owner, os: a.os,
    internet_facing: a.internet_facing, registered: a.registered, discovery_status: a.discovery_status,
    discovery_match_key: a.discovery_match_key, other_services: a.other_services, subnet_applications: a.subnet_applications || [],
    modifiers: a.modifiers, score: a.score,
  }));
  const results = [];
  res.assets.forEach((a, i) => {
    for (const checkId of ASSET_CHECKS) {
      const r = a.results[checkId];
      results.push({
        run_id: id, run_asset_id: assets[i].id, application_id: null, check_id: checkId, status: r.status, raw_status: r.raw_status,
        detail: r.detail, evidence: r.evidence, exception: r.exception ?? null, weight: r.weight ?? 0, linked_risks: r.risk_ids || [],
        extra: r.unrecorded ? { unrecorded: r.unrecorded } : {},
      });
    }
  });
  for (const [appId, appResults] of Object.entries(res.app_level)) {
    for (const checkId of APP_CHECKS) {
      const r = appResults[checkId];
      const extra = {};
      for (const k of ["top_rank", "exceeds_tolerance", "factor"]) if (k in r) extra[k] = r[k];
      results.push({
        run_id: id, run_asset_id: null, application_id: appId, check_id: checkId, status: r.status, raw_status: r.raw_status,
        detail: r.detail, evidence: r.evidence, exception: null, weight: r.weight ?? 0, linked_risks: r.risk_ids || [], extra,
      });
    }
  }
  const firstResult = await nextId(db, "check_results", Math.max(results.length, 1));
  results.forEach((r, i) => { r.id = firstResult + i; });

  await db.collection("runs").insertOne({
    id, created_at: new Date(), created_by: user, as_of: defn.as_of, service_name: defn.name, service_tier: defn.tier,
    impact_tolerance_hours: defn.tolerance_hours, applications: defn.applications, sources: res.sources, settings,
    reconciliation: res.reconciliation, unmatched: res.unmatched, app_results: res.app_results, service_checks: res.service_checks,
    scenario_results: res.scenario_results, rating: res.rating, rating_reason: res.reason, score: res.score,
    risks: res.risks, unmapped_risks: res.unmapped_risks, dr_results: res.dr.map(({ results: _r, ...d }) => d),
    mode, progress: mode === "step" ? 1 : 99, assets,
  });
  if (results.length) await db.collection("check_results").insertMany(results);
  return id;
}

/** A run with its results attached: run.results (each with .asset), run.assets (each with .results). */
export async function getRun(db, id) {
  const run = await db.collection("runs").findOne({ id: Number(id) }, { projection: { _id: 0 } });
  if (!run) return null;
  const results = await db.collection("check_results").find({ run_id: run.id }, { projection: { _id: 0 } }).sort({ id: 1 }).toArray();
  const byId = new Map(run.assets.map((a) => [a.id, Object.assign(a, { results: [] })]));
  for (const r of results) {
    r.asset = r.run_asset_id ? byId.get(r.run_asset_id) : null;
    if (r.asset) r.asset.results.push(r);
  }
  run.assets.sort((a, b) => (a.hostname < b.hostname ? -1 : a.hostname > b.hostname ? 1 : 0));
  run.results = results;
  return run;
}

export async function listRuns(db, limit = 0) {
  const cursor = db.collection("runs").find({}, { projection: { _id: 0, id: 1, service_name: 1, as_of: 1, created_at: 1, applications: 1, rating: 1, score: 1, mode: 1, progress: 1, asset_count: { $size: "$assets" } } }).sort({ id: -1 });
  if (limit) cursor.limit(limit);
  return cursor.toArray();
}

export async function previousRun(db, run) {
  return db.collection("runs").findOne({ service_name: run.service_name, id: { $lt: run.id } }, { sort: { id: -1 }, projection: { _id: 0, id: 1, as_of: 1, rating: 1, score: 1 } });
}

export async function setProgress(db, id, progress) {
  await db.collection("runs").updateOne({ id: Number(id) }, { $max: { progress } });
}

export async function getResult(db, runId, resultId) {
  return db.collection("check_results").findOne({ run_id: Number(runId), id: Number(resultId) }, { projection: { _id: 0 } });
}
