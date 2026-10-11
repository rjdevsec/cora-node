/*
 * Business impact: translate findings into what they mean for the service and its tolerance.
 *
 * Rule-based and deterministic: every sentence is built from fixed wording per check plus the run's own data
 * (applications, scenarios, tolerance, modifiers), so the same run always reads the same and each statement traces
 * to a check result. The Phase 3 AI analysis can later write a richer narrative on top of this.
 */
import { g, join } from "../util.js";

const fill = (template, vars) => template.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? vars[k] : m));

// What the gap means, in plain terms. {host} = system, {apps} = the business applications it supports.
const GAP_MEANING = {
  T1: "An unmanaged system is running on the same network as {apps}. Nobody is accountable for patching or monitoring it, which makes it an easy way in for an attacker to reach {apps}.",
  T2: "{host} is recorded as supporting {apps} but has not been seen on the network recently. Either the inventory is wrong or the system is not being monitored, so the real exposure of the service is unknown.",
  T3: "{host} is classified below the importance of the service, so it may get slower patching, weaker monitoring and a lower place in the recovery queue than {apps} needs.",
  T4: "Security weaknesses on {host} have been left unfixed beyond the agreed deadline. An attacker could use them to take control of {apps}.",
  T5: "{host} runs software the vendor no longer supports. New weaknesses will not be fixed, so the risk to {apps} grows every month.",
  T6: "{host} has no working protection against malicious software, so ransomware reaching it would not be blocked.",
  T7: "Malware protection on {host} is out of date and would not recognise recent threats such as new ransomware strains.",
  T8: "Powerful administrator accounts on {host} are outside the privileged access vault. If they are misused or stolen, they give full control of {apps} with no oversight.",
  T9: "{host} does not send security logs to the monitoring centre, so an attack on {apps} would probably go unnoticed.",
  P1: "An exception meant to accept a risk on {host} is expired, unapproved or has no compensating control, so the risk is being carried without valid sign-off.",
  P2: "Patching on {host} is falling behind the bank's target, which shows the patching process is not keeping pace.",
  H1: "No current owner is accountable for {host}, so fixes and decisions during an incident affecting {apps} may stall.",
  R4: "Security gaps on {host} are not recorded in the risk register, so the bank is carrying risks to {apps} that nobody has assessed or accepted.",
  B1: "{host} has no active backup, so data on {apps} held there could not be restored after corruption or ransomware.",
  B2: "Backups of {host} are not completing on schedule, so a restore would bring back old data and lose recent {apps} transactions.",
  B3: "{host} has no immutable or offsite backup copy, so ransomware that reaches the backup system could destroy every copy of {apps} data.",
  B4: "Restoring {host} has not been proven recently or takes longer than the service can tolerate, so recovery of {apps} is uncertain.",
};

// Application-level checks. {app} = application, {tol} = service tolerance, other keys from the run's data.
const APP_MEANING = {
  R1: "{app} carries open risks rated above the bank's appetite: {risks}.",
  R2: "Agreed fixes for risks on {app} are overdue or have no owner ({risks}), so known exposures stay open longer than planned.",
  R3: "Risks on {app} have been accepted without the right approval or past their review date ({risks}), so the bank may be carrying them without a current decision.",
  D1: "{app}'s ability to recover has not been proven: {why}.",
  D2: "In its last DR test, {app} took {achieved} to recover, against the {tol} the service can tolerate{rto}.",
  D3: "In its last DR test, {app} lost {loss} of data against a {rpo} objective, so transactions could be lost in a real outage.",
  D4: "Problems found in {app}'s last DR test are still open past their due date, so the next recovery could fail the same way.",
};
const APP_IMPACT = { R1: "Known risk", R2: "Unmanaged risk", R3: "Unmanaged risk", D1: "Recovery", D2: "Recovery", D3: "Recovery", D4: "Recovery" };
const APP_ACTION = {
  R1: "Agree a dated treatment plan to bring {risks} within appetite, or escalate for formal acceptance.",
  R2: "Update the overdue treatment for {risks} and confirm an owner for each.",
  R3: "Have {risks} re-approved at the right level, or close them.",
  D1: "Run a full-scope DR test of {app} covering all its servers and databases.",
  D2: "Reduce {app}'s recovery time below the {tol} tolerance and prove it in a DR test.",
  D3: "Increase backup or replication frequency for {app} and re-test data loss.",
  D4: "Close the open issues from {app}'s last DR test.",
};

// What kind of harm to the service the gap leads to.
const IMPACT_TYPE = {
  T1: "Compromise", T4: "Compromise", T5: "Compromise", T6: "Compromise", T7: "Compromise", T8: "Compromise",
  T9: "Late detection", T2: "Unknown exposure", T3: "Unknown exposure",
  P1: "Unmanaged risk", P2: "Unmanaged risk", H1: "Unmanaged risk", R4: "Unmanaged risk",
  B1: "Recovery", B2: "Recovery", B3: "Recovery", B4: "Recovery",
};

// How the gap stretches recovery against the impact tolerance.
const TOLERANCE_EFFECT = {
  Compromise: "A successful attack would take {apps} out of service until the systems are cleaned and restored.",
  "Late detection": "An attack found late is usually found after the damage is done, so containment and recovery start late.",
  "Unknown exposure": "Systems missing from the inventory or wrongly classified may be left out of recovery plans, slowing restoration.",
  "Unmanaged risk": "Without clear ownership and sign-off, fixes and recovery decisions take longer.",
  "Known risk": "A known, unmitigated risk to {apps} could materialise as an outage or compromise of the service.",
  Recovery: "If {apps} fails, the service may stay down longer than the {tol} it can tolerate.",
};

const ACTION = {
  T1: "Register {host}, assign an owner and bring it under patching and monitoring, or remove it from the network.",
  T2: "Confirm whether {host} still exists and correct the asset register or the discovery scope.",
  T3: "Reclassify {host} to match the service tier so it gets the right patching, monitoring and recovery priority.",
  T4: "Apply the overdue fixes on {host}, starting with those that have known attack tools.",
  T5: "Upgrade or replace the unsupported software on {host}, or approve a time-bound exception with compensating controls.",
  T6: "Install or repair malware protection on {host}.",
  T7: "Bring malware protection on {host} up to date and fix the update process.",
  T8: "Move the privileged accounts on {host} into the vault with password rotation.",
  T9: "Connect {host} to the SIEM and confirm events arrive.",
  P1: "Renew, approve or close the exception on {host}, with a documented compensating control.",
  P2: "Agree a catch-up plan for patching on {host}.",
  H1: "Assign a current owner for {host}.",
  R4: "Record the gaps on {host} in the risk register, or raise exceptions with compensating controls.",
  B1: "Put {host} under a scheduled backup job.",
  B2: "Fix the failing or stale backup job for {host} and confirm a successful run.",
  B3: "Add an immutable or offsite copy to the backups of {host}.",
  B4: "Run a restore test of {host} and bring the restore time within the tolerance.",
};

const SEVERITY_URGENCY = { Critical: "Immediate", High: "High priority", Medium: "Planned", Low: "Monitor" };
const RECOVERY_OUTLOOK = { exceeds: "Recovery exceeds tolerance", untested: "Recovery untested", unproven: "Recovery unproven", thin: "Thin recovery margin", proven: "Recovery within tolerance" };
const SEV_ORDER = ["Critical", "High", "Medium", "Low"];

function toleranceOutlook(rating) {
  if (rating === "Critical") return ["Breach likely", "crit"];
  if (rating === "High") return ["Breach possible", "bad"];
  if (rating === "Medium") return ["Within tolerance, gaps to fix", "warn"];
  return ["Within tolerance", "good"];
}

const isNum = (v) => typeof v === "number" && Number.isFinite(v);
const plural = (n, word, many = `${word}s`) => (n === 1 ? word : many);

function appStatement(f, drByApp, risksById, tol) {
  const r = f.result;
  const { app } = f;
  const linked = r.linked_risks || [];
  const riskText = linked.map((id) => (risksById[id] ? `${id} “${risksById[id].title}” (${risksById[id].rating})` : id)).join("; ") || "see the risk register";
  const riskIds = linked.join(", ") || "the linked risks";
  const d = drByApp[app.id] || {};
  const test = d.test || {};
  const achieved = d.recovery?.achieved;
  const rto = Number(test.rto_hours);
  let why = "";
  if (r.check_id === "D1") {
    const i = r.detail.indexOf(": ");
    why = (i >= 0 ? r.detail.slice(i + 2) : r.detail).replace(/\.+$/, "");
  }
  const loss = Number(test.achieved_rpo_hours);
  const rpo = Number(test.rpo_hours);
  const meaning = fill(APP_MEANING[r.check_id], {
    app: app.name, tol, risks: riskText, why: why || "no DR test is recorded",
    achieved: isNum(achieved) ? `${g(achieved)} hours` : "an unknown time",
    rto: test.rto_hours !== "" && isNum(rto) ? ` and its own ${g(rto)}-hour recovery objective` : "",
    loss: test.achieved_rpo_hours !== "" && isNum(loss) ? `${g(loss)} hours` : "more",
    rpo: test.rpo_hours !== "" && isNum(rpo) ? `${g(rpo)}-hour` : "its",
  });
  const impact = APP_IMPACT[r.check_id];
  return {
    impact_type: impact, meaning,
    service_effect: fill(TOLERANCE_EFFECT[impact], { apps: app.name, tol }),
    action: fill(APP_ACTION[r.check_id], { app: app.name, tol, risks: riskIds }),
  };
}

/** Returns { summary, scenarios, statements, other, actions, critical, high, at_risk } for a hydrated run. */
export function businessImpact(run, findings) {
  const appNames = Object.fromEntries(run.applications.map((a) => [a.id, a.name]));
  const tolerance = run.impact_tolerance_hours;
  const tol = `${g(tolerance)} ${plural(tolerance, "hour")}`;
  const tolAdj = `${g(tolerance)}-hour`;
  const serious = findings.filter((f) => f.severity === "Critical" || f.severity === "High");
  const described = findings.filter((f) => f.severity !== "Data quality");
  const drByApp = Object.fromEntries((run.dr_results || []).map((d) => [d.id, d]));
  const risks = run.risks || [];
  const risksById = Object.fromEntries(risks.map((r) => [r.id, r]));
  const scenarios = run.scenario_results || [];

  const scenariosFor = (subject, check) => scenarios.filter((s) => (s.triggers || []).some((t) => t.subject === subject && t.check === check));

  const statements = {};
  for (const f of described) {
    const r = f.result;
    const a = f.asset;
    if (!a) {
      const st = appStatement(f, drByApp, risksById, tol);
      statements[r.id] = {
        ...st, finding: f, scenarios: scenariosFor(f.app.id, r.check_id).map((s) => s.name), other_services: [],
        urgency: SEVERITY_URGENCY[f.severity] || "Planned", owner: f.owner || "Unassigned",
      };
      continue;
    }
    const appIds = a.applications.length ? a.applications : a.subnet_applications || [];
    const apps = join(appIds.map((x) => appNames[x] ?? x));
    const host = a.asset_type && a.asset_type !== "Unknown" ? `${a.hostname} (${a.asset_type.toLowerCase()})` : a.hostname;
    const impact = IMPACT_TYPE[r.check_id];
    let parts;
    let serviceEffect;
    if (a.registered || r.check_id === "T1") {
      parts = [fill(GAP_MEANING[r.check_id], { host, apps })];
      serviceEffect = fill(TOLERANCE_EFFECT[impact], { apps, tol });
    } else {
      // Unregistered hosts are not part of the applications, only on their network: say so, don't overclaim.
      parts = [fill(GAP_MEANING[r.check_id], { host, apps: "this unregistered system" }),
        `It sits on the same network as ${apps}, so an attacker who controls it is one step away from them.`];
      serviceEffect = `An attacker controlling this system could move on to ${apps} and take them out of service until they are cleaned and restored.`;
    }
    if (a.modifiers.includes("exposure") && impact === "Compromise") parts.push("It is reachable from the internet, so an attacker needs no inside access.");
    if (a.modifiers.includes("exploitability") && r.check_id === "T4") parts.push("Ready-made attack tools exist for at least one of these weaknesses.");
    if (a.modifiers.includes("compounding")) parts.push("Combined with its other gaps, an attacker could get in, take control and stay unnoticed on this system.");
    if (r.linked_risks?.length) parts.push(`This is recorded in the risk register as ${r.linked_risks.join(", ")}.`);
    else if (r.check_id !== "R4" && r.status === "fail") parts.push("It is not recorded in the risk register.");
    if (r.status === "excepted") parts.push("This is covered by an approved exception, but the exposure remains.");
    statements[r.id] = {
      finding: f, impact_type: impact, meaning: parts.join(" "), service_effect: serviceEffect,
      scenarios: scenariosFor(a.hostname, r.check_id).map((s) => s.name), other_services: a.other_services,
      action: fill(ACTION[r.check_id], { host: a.hostname }), urgency: SEVERITY_URGENCY[f.severity] || "Planned", owner: a.owner || "Unassigned",
    };
  }

  // Per scenario: what could happen, why, and the position against tolerance.
  const rank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const scenarioViews = [...scenarios].sort((x, y) => (rank[y.rating] - rank[x.rating]) || (y.score - x.score)).map((s) => {
    const linked = Object.values(statements).filter((st) => st.scenarios.includes(s.name))
      .sort((x, y) => (SEV_ORDER.indexOf(x.finding.severity) - SEV_ORDER.indexOf(y.finding.severity)) || (y.finding.effective - x.finding.effective));
    const bySubject = {};
    for (const st of linked) (bySubject[st.finding.subject] ??= []).push(st);
    const [outlook, outlookClass] = toleranceOutlook(s.rating);
    const apps = join(s.applications.map((x) => appNames[x] ?? x));
    const impacts = [...new Set(linked.map((st) => st.impact_type))].sort();
    const other = [...new Set(linked.flatMap((st) => st.other_services))].sort();
    const { recovery } = s;
    let toleranceText;
    if (recovery) {
      let rec = recovery.label[0].toUpperCase() + recovery.label.slice(1);
      if (recovery.status === "untested" || recovery.status === "unproven") rec += ", so recovery is treated as exceeding tolerance";
      toleranceText = `${run.service_name} can tolerate at most ${tol} of disruption. ${rec}.`;
      if (linked.length) toleranceText += ` The findings below could trigger this scenario (${impacts.map((i) => i.toLowerCase()).join(", ")}).`;
    } else {
      toleranceText = `No Critical or High gap feeds this scenario. Recovery of ${apps} within ${tol} has not been demonstrated.`;
    }
    return {
      name: s.name, description: s.description, rating: s.rating, score: s.score, applications: apps,
      outlook, outlook_class: outlookClass, tolerance_text: toleranceText, recovery,
      recovery_label: RECOVERY_OUTLOOK[recovery?.status] || "", reasons: s.reasons || [], by_asset: bySubject, other_services: other,
      test: s.test || [], risk_ids: s.risk_ids || [], generated: true,
      critical: linked.filter((st) => st.finding.severity === "Critical").length,
      high: linked.filter((st) => st.finding.severity === "High").length,
    };
  });

  const other = Object.values(statements).filter((st) => !st.scenarios.length && ["Critical", "High"].includes(st.finding.severity));

  // Executive summary.
  const atRisk = scenarioViews.filter((s) => s.rating === "Critical" || s.rating === "High");
  const crit = serious.filter((f) => f.severity === "Critical").length;
  const high = serious.length - crit;
  const lines = [`${run.service_name} is rated ${run.rating}. ${atRisk.length} of ${scenarioViews.length} plausible ${plural(scenarioViews.length, "scenario")} could breach `
    + `the ${tolAdj} impact tolerance, driven by ${crit} critical and ${high} high ${plural(high, "finding")}.`];
  if (atRisk.length) {
    const worst = atRisk[0];
    lines.push(`The most exposed scenario is “${worst.name}”: ${worst.description.replace(/\.+$/, "")}.`);
    const top = Object.values(worst.by_asset).flat()[0];
    if (top) lines.push(`The main cause: ${top.meaning}`);
  }
  if ((run.dr_results || []).length) {
    const counts = { exceeds: [], untested: [], unproven: [], thin: [], proven: [] };
    for (const d of run.dr_results) counts[d.recovery.status].push(appNames[d.id] ?? d.id);
    const parts = [];
    if (counts.exceeds.length) parts.push(`${join(counts.exceeds)} took longer than the tolerance to recover`);
    if (counts.untested.length || counts.unproven.length) parts.push(`recovery of ${join([...counts.untested, ...counts.unproven])} is not proven by a current, complete test`);
    if (counts.thin.length) parts.push(`${join(counts.thin)} recovered within tolerance but on a thin margin`);
    const n = run.dr_results.length;
    lines.push(`DR tests: ${counts.proven.length} of ${n} ${plural(n, "application")} recovered within tolerance with margin${parts.length ? `; ${parts.join("; ")}.` : "."}`);
    const above = risks.filter((r) => r.above);
    const unrecorded = run.results.filter((x) => x.check_id === "R4" && x.status === "fail").length;
    let riskLine = `${above.length} open ${plural(above.length, "risk")} above appetite ${above.length === 1 ? "is" : "are"} recorded against these applications`;
    if (unrecorded) riskLine += `, and ${unrecorded} ${unrecorded === 1 ? "system has" : "systems have"} gaps that are not in the risk register at all`;
    lines.push(`${riskLine}.`);
  }
  const shared = [...new Set(Object.values(statements).flatMap((st) => st.other_services))].sort();
  if (shared.length) lines.push(`Some affected systems also support ${join(shared)}, so the same incident would disrupt those services too.`);

  const actions = [];
  const seen = new Set();
  for (const st of Object.values(statements).filter((x) => ["Critical", "High"].includes(x.finding.severity))
    .sort((x, y) => (Number(x.finding.severity !== "Critical") - Number(y.finding.severity !== "Critical")) || (y.finding.effective - x.finding.effective))) {
    const key = `${st.finding.subject}|${st.finding.result.check_id}`;
    if (!seen.has(key)) { seen.add(key); actions.push(st); }
  }

  return { summary: lines, scenarios: scenarioViews, statements, other, actions: actions.slice(0, 6), critical: crit, high, at_risk: atRisk.length };
}
