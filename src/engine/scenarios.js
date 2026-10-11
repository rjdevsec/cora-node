/*
 * Step 11: generate the plausible scenarios to test from the issues and risks found, then rate each one.
 *
 * Scenarios are not supplied by the business. Each template below fires when the run's results show the conditions
 * that make it plausible; it names the affected applications and systems, carries the findings and register risks
 * behind it (its triggers), and says what to test. Rules are fixed, so the same results always produce the same
 * scenarios.
 */
import { combineRecovery } from "./riskRecovery.js";
import { g, join, maxBy, round } from "../util.js";

const PREVENTION = ["T4", "T5", "T6", "T7"];
const BACKUP = ["B1", "B2", "B3", "B4"];
const RECOVERY_BAD = new Set(["untested", "unproven", "exceeds"]);

const fails = (asset, checks) => checks.filter((c) => asset.results[c]?.status === "fail");
const appsOf = (asset) => (asset.applications.length ? asset.applications : asset.subnet_applications || []);

// Template: the checks it rests on (for linking register risks), and which recovery evidence applies.
const TEMPLATES = {
  ransomware: { checks: new Set([...PREVENTION, ...BACKUP]), recovery: "backup" },
  external: { checks: new Set(["T4", "T5", "T6"]), recovery: "dr" },
  privileged: { checks: new Set(["T8"]), recovery: "dr" },
  undetected: { checks: new Set(["T9", "T1", ...PREVENTION]), recovery: "dr" },
  data_loss: { checks: new Set([...BACKUP, "D3"]), recovery: "backup" },
  outage: { checks: new Set(["D1", "D2", "D4"]), recovery: "dr" },
};

export function generateScenarios(assets, appLevel, dr, risks, defn, settings, appNames) {
  const tol = `${g(defn.tolerance_hours)} hours`;
  const all = Object.values(assets); // includes unregistered hosts found by discovery
  const badRecoveryApps = new Set(Object.entries(dr).filter(([, d]) => RECOVERY_BAD.has(d.recovery.status)).map(([a]) => a));
  const found = new Map();
  const add = (key, assetTriggers, appTriggers) => {
    if (assetTriggers.length || appTriggers.length) found.set(key, { assets: assetTriggers, apps: appTriggers });
  };
  const appStatus = (app, c) => appLevel[app]?.[c]?.status;

  // Ransomware: a way in (unpatched, unsupported or unprotected) and weak backups or unproven recovery.
  add("ransomware", all.flatMap((a) => {
    const wayIn = fails(a, PREVENTION);
    const weak = fails(a, BACKUP);
    return wayIn.length && (weak.length || appsOf(a).some((x) => badRecoveryApps.has(x))) ? [[a, [...wayIn, ...weak]]] : [];
  }), []);
  // External attack: internet-facing system with an open way in.
  add("external", all.filter((a) => a.internet_facing && fails(a, ["T4", "T5", "T6"]).length).map((a) => [a, fails(a, ["T4", "T5", "T6"])]), []);
  // Misuse of privileged accounts outside PAM (worse when the system is not logging to the SIEM).
  add("privileged", all.filter((a) => fails(a, ["T8"]).length).map((a) => [a, fails(a, ["T8", "T9"])]), []);
  // Undetected intrusion: systems not logging to the SIEM, or unmanaged systems on the network; their open
  // weaknesses are how the intruder gets in, so they count as triggers too.
  add("undetected", all.filter((a) => fails(a, ["T9", "T1"]).length).map((a) => [a, [...fails(a, ["T9", "T1"]), ...fails(a, PREVENTION)]]), []);
  // Data corruption or loss: backups missing, stale, unprotected or untested, or DR data loss beyond RPO.
  add("data_loss", all.filter((a) => fails(a, BACKUP).length).map((a) => [a, fails(a, BACKUP)]),
    Object.keys(appLevel).filter((app) => appStatus(app, "D3") === "fail").map((app) => [app, ["D3"]]));
  // Prolonged outage: recovery not proven within the tolerance.
  add("outage", [], Object.keys(dr)
    .filter((app) => badRecoveryApps.has(app) || ["D2", "D4"].some((c) => appStatus(app, c) === "fail"))
    .map((app) => {
      const failed = ["D1", "D2", "D4"].filter((c) => appStatus(app, c) === "fail");
      return [app, failed.length ? failed : ["D1"]];
    }));

  // Register risks above appetite: attach to a fired scenario whose checks they name; otherwise their own scenario.
  const standalone = [];
  for (const r of risks.filter((x) => x.above)) {
    const homes = [...found.entries()].filter(([k, f]) => {
      const fApps = new Set([...f.assets.flatMap(([a]) => appsOf(a)), ...f.apps.map(([x]) => x)]);
      return r.controls.some((c) => TEMPLATES[k].checks.has(c)) && r.apps.some((x) => fApps.has(x));
    }).map(([k]) => k);
    if (!homes.length) standalone.push(r);
    for (const k of homes) { // the R1 result for the risk's applications then belongs to these scenarios
      const f = found.get(k);
      const have = new Set(f.apps.map(([x]) => x));
      for (const app of r.apps) if (!have.has(app) && appStatus(app, "R1") === "fail") f.apps.push([app, ["R1"]]);
    }
  }

  const scenarios = [];
  for (const [key, f] of found) {
    const appIds = [...new Set([...f.assets.flatMap(([a]) => appsOf(a)), ...f.apps.map(([x]) => x)])].sort();
    const hosts = f.assets.map(([a]) => a.hostname);
    const names = join(appIds.map((x) => appNames[x] ?? x));
    const hostList = join(hosts.slice(0, 4)) + (hosts.length > 4 ? ` and ${hosts.length - 4} more` : "");
    const triggers = [
      ...f.assets.flatMap(([a, cs]) => cs.map((c) => ({ kind: "asset", subject: a.hostname, check: c }))),
      ...f.apps.flatMap(([app, cs]) => cs.map((c) => ({ kind: "app", subject: app, check: c }))),
    ];
    // Two applications or fewer are named; more read as the service, with the applications in the description.
    const title = appIds.length <= 2 ? names : `${appIds.length} applications of ${defn.name}`;
    const text = describe(key, names, hostList, f, tol);
    text.name = text.name.replace("{title}", title);
    scenarios.push({ key, applications: appIds, hosts, triggers, ...text });
  }

  for (const r of standalone) {
    const names = join(r.apps.map((x) => appNames[x] ?? x));
    const label = r.category === "Application" ? "Application security" : "Asset";
    scenarios.push({
      key: `risk:${r.id}`, applications: r.apps, hosts: r.hosts,
      triggers: r.apps.map((app) => ({ kind: "app", subject: app, check: "R1" })),
      name: `${r.title} (${r.id})`,
      description: `${label} risk ${r.id}, rated ${r.rating}, materialises against ${names}.`,
      test: [`Validate the treatment for ${r.id}: ${r.treatment || "no treatment recorded"}.`,
        `Tabletop exercise: ${r.title.toLowerCase()} disrupting ${names}.`],
    });
  }

  // Rate each scenario with the plan's table: material exposure set against demonstrated recovery.
  const weights = settings.check_weights;
  const minW = settings.material_gap_min_weight;
  const thresholds = settings.rating_thresholds;
  for (const sc of scenarios) {
    const scApps = new Set(sc.applications);
    const trig = all.filter((a) => sc.hosts.includes(a.hostname));
    const material = trig.flatMap((a) => Object.entries(a.results)
      .filter(([c, r]) => r.status === "fail" && Number(weights[c] ?? 1) >= minW && !r.risk_in_date).map(([c]) => [a.hostname, c]));
    const linkedRisks = risks.filter((r) => r.apps.some((x) => scApps.has(x)) && (r.above || sc.key === `risk:${r.id}`));
    const aboveRisks = linkedRisks.filter((r) => r.above);
    const late = risks.filter((r) => (r.overdue || r.no_owner) && r.apps.some((x) => scApps.has(x)));
    const appScores = sc.triggers.filter((t) => t.kind === "app" && appLevel[t.subject]).map((t) => appLevel[t.subject][t.check]?.score ?? 0);
    const score = Math.max(0, ...trig.map((a) => a.score), ...appScores);
    let recovery = combineRecovery(sc.applications.filter((a) => dr[a]).map((a) => dr[a]), defn.tolerance_hours, appNames);
    if (TEMPLATES[sc.key]?.recovery === "backup") {
      const weak = trig.filter((a) => fails(a, BACKUP).length).map((a) => a.hostname);
      if (weak.length && !RECOVERY_BAD.has(recovery.status)) {
        recovery = {
          ...recovery, status: "unproven",
          label: `backups for ${join(weak.slice(0, 3))}${weak.length > 3 ? " and others" : ""} are missing, stale, unprotected or untested, so restoring within ${tol} is unproven`,
        };
      }
    }
    const isMaterial = Boolean(material.length || aboveRisks.length || score >= thresholds.high);
    const bad = RECOVERY_BAD.has(recovery.status);
    const rating = isMaterial && bad ? "Critical"
      : isMaterial || late.length || bad ? "High"
        : sc.triggers.length || recovery.status === "thin" ? "Medium" : "Low";
    const reasons = [];
    const s = (n) => (n !== 1 ? "s" : "");
    if (material.length) reasons.push(`${material.length} material gap${s(material.length)} without a valid exception or in-date risk treatment`);
    if (aboveRisks.length) reasons.push(`${aboveRisks.length} open risk${s(aboveRisks.length)} above the ${settings.risk_appetite} appetite (${aboveRisks.map((r) => r.id).join(", ")})`);
    if (score >= thresholds.high && !material.length) reasons.push(`a risk score of ${g(score)}`);
    if (late.length) reasons.push(`${late.length} risk${s(late.length)} with overdue treatment or no owner`);
    reasons.push(recovery.label);
    Object.assign(sc, {
      rating, score: round(score, 2), recovery, reasons,
      risk_ids: linkedRisks.map((r) => r.id), material_count: material.length, asset_count: trig.length,
      weakest_asset: trig.length ? maxBy(trig, (a) => a.score).hostname : null,
      weakest_gaps: [...new Set(sc.triggers.map((t) => t.check))].sort(),
    });
  }
  const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  scenarios.sort((a, b) => (order[a.rating] - order[b.rating]) || (b.score - a.score));
  return scenarios;
}

function describe(key, names, hosts, f, tol) {
  const checks = new Set([...f.assets.flatMap(([, cs]) => cs), ...f.apps.flatMap(([, cs]) => cs)]);
  const has = (...cs) => cs.some((c) => checks.has(c));
  if (key === "ransomware") {
    const why = [];
    if (has("T4", "T5")) why.push("unpatched or unsupported systems");
    if (has("T6", "T7")) why.push("missing or outdated malware protection");
    const backup = [];
    if (has("B1", "B2")) backup.push("missing or stale");
    if (has("B3")) backup.push("unprotected");
    if (has("B4")) backup.push("untested");
    const rec = backup.length ? `, and recovery depends on backups that are ${backup.join(" and ")}` : ", and recovery within the tolerance has not been proven";
    return {
      name: "Ransomware on {title}",
      description: `Ransomware gets in through ${why.join(" and ")} on ${hosts} and encrypts ${names}${rec}.`,
      test: [`Restore ${names} from protected backups and confirm it completes within ${tol}.`,
        `Detection and containment of ransomware activity on ${hosts}.`,
        "Isolation of the affected network segment without stopping the rest of the service."],
    };
  }
  if (key === "external") {
    return {
      name: "External attack on internet-facing {title}",
      description: `An attacker on the internet exploits unfixed weaknesses on ${hosts} to take control of ${names}.`,
      test: [`Penetration test of the internet route to ${hosts}.`, "Emergency patching or virtual patching (WAF/IPS) within the critical-severity SLA."],
    };
  }
  if (key === "privileged") {
    const unseen = has("T9") ? " and is not logging to the SIEM, so misuse would go unnoticed" : "";
    return {
      name: "Misuse of unmanaged privileged accounts on {title}",
      description: `An administrator or service account outside the PAM vault on ${hosts} is stolen or misused${unseen}.`,
      test: [`Tabletop: stolen administrator credentials used on ${hosts}.`, "Check that privileged sessions are recorded and alerted on."],
    };
  }
  if (key === "undetected") {
    return {
      name: "Undetected intrusion into {title}",
      description: `An attacker operates on ${hosts} without raising an alert, because the systems are not sending logs to the SIEM or are not managed.`,
      test: [`Purple-team exercise: confirm attack activity on ${hosts} raises SIEM alerts.`, "Onboard missing log sources and re-test detection."],
    };
  }
  if (key === "data_loss") {
    return {
      name: "Data corruption or loss on {title}",
      description: `Data on ${names} is corrupted or deleted and cannot be restored to the recovery point, because backups on ${hosts} are missing, stale, unprotected or untested.`,
      test: [`Restore test of ${hosts} to the recovery point objective.`, "Verify backup immutability or offsite copies."],
    };
  }
  return {
    name: "Prolonged outage of {title}",
    description: `${names} stays unavailable for longer than the ${tol} the service can tolerate, because recovery has not been proven within it.`,
    test: [`Full-scope DR test of ${names} measured against the ${tol} tolerance.`, "Close open issues from the last DR test before re-testing."],
  };
}
