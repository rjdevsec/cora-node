/*
 * Backups (step 8): checks B1–B4 per asset, from the backup management tool's export.
 *
 * Source rows come from `loadAll().backups`: today a CSV export, in Phase 5 a connector to the backup platform's
 * API. Each row is one backup job for a host (`hostname`), with its latest restore test.
 */
import { result } from "./checks.js";
import { PASSED } from "./riskRecovery.js";
import { ageDays, endOfDayMs, fmtDateTime, g, maxBy } from "../util.js";

const SCHEDULE_HOURS = { continuous: 1, "real-time": 1, realtime: 1, hourly: 1, daily: 24, nightly: 24, weekly: 168, monthly: 744 };
const INACTIVE = new Set(["disabled", "inactive", "suspended", "retired", "paused", "deleted"]);
const ALL = ["B1", "B2", "B3", "B4"];

export function backupChecks(jobs, evidence, asOf, tolerance, settings, loaded, registered) {
  if (!registered) return Object.fromEntries(ALL.map((c) => [c, result(c, "n/a", "Not in the register; covered by T1.")]));
  if (!loaded) return Object.fromEntries(ALL.map((c) => [c, result(c, "no_data", "Backup management export not loaded.")]));
  const active = jobs.filter((j) => !INACTIVE.has((j.job_status || "active").trim().toLowerCase()));
  const ev = jobs.map((j) => evidence("backups", j));
  const out = {};
  if (!active.length) {
    const states = [...new Set(jobs.map((j) => (j.job_status || "").toLowerCase()))].sort().join(", ");
    out.B1 = result("B1", "fail", jobs.length ? `Backup job(s) exist but are ${states}.` : "No active backup job covers this asset.", ev);
    for (const c of ["B2", "B3", "B4"]) out[c] = result(c, "n/a", "No active backup; covered by B1.");
    return out;
  }
  out.B1 = result("B1", "pass", `${active.length} active job(s): `
    + active.map((j) => `${j.job_name || "job"} (${j.schedule || "schedule not stated"})`).join("; ") + ".", ev);

  // B2: the most recent success must fall within the tightest schedule plus the grace period.
  const interval = Math.min(...active.map((j) => SCHEDULE_HOURS[(j.schedule || "daily").trim().toLowerCase()] ?? 24));
  const allowed = interval + settings.backup_grace_days * 24;
  const successes = active.map((j) => j.last_success).filter(Boolean);
  const failedRuns = active.filter((j) => !["", ...PASSED].includes((j.last_result || "").trim().toLowerCase()));
  if (!successes.length) {
    out.B2 = result("B2", "fail", "No successful backup recorded.", ev);
  } else {
    const latest = maxBy(successes, (d) => d.getTime());
    const ageH = (endOfDayMs(asOf) - latest.getTime()) / 3_600_000;
    const note = failedRuns.length ? ` Last run result: ${failedRuns[0].last_result}.` : "";
    out.B2 = ageH > allowed
      ? result("B2", "fail", `Last successful backup ${fmtDateTime(latest)}, ${(ageH / 24).toFixed(1)} days ago; the schedule allows ${g(allowed / 24)} days.${note}`, ev)
      : result("B2", "pass", `Last successful backup ${fmtDateTime(latest)}, within schedule.${note}`, ev);
  }

  // B3: at least one immutable or offsite copy.
  const flags = active.map((j) => [j.immutable, j.offsite]);
  if (flags.some(([i, o]) => i || o)) {
    const kinds = [...new Set(flags.flatMap(([i, o]) => [i ? "immutable" : null, o ? "offsite" : null]).filter(Boolean))].sort();
    out.B3 = result("B3", "pass", `Protected copy: ${kinds.join(" and ")}.`, ev);
  } else if (flags.every(([i, o]) => i === null && o === null)) {
    out.B3 = result("B3", "no_data", "Immutability and offsite copy not recorded.", ev);
  } else {
    out.B3 = result("B3", "fail", "No immutable or offsite copy; ransomware that reaches the backup server could destroy every copy.", ev);
  }

  // B4: latest restore test passed, within policy, and fast enough for the tolerance.
  const tested = active.filter((j) => j.restore_test_date);
  if (!tested.length) {
    out.B4 = result("B4", "fail", "No restore test recorded.", ev);
  } else {
    const t = maxBy(tested, (j) => j.restore_test_date);
    const age = ageDays(asOf, t.restore_test_date);
    const problems = [];
    if (age > settings.restore_test_max_age_days) problems.push(`last test ${age} days ago (policy ${g(settings.restore_test_max_age_days)} days)`);
    if (!PASSED.has((t.restore_result || "").trim().toLowerCase())) problems.push(`result '${t.restore_result || "blank"}'`);
    if (t.restore_hours !== null && t.restore_hours > tolerance) problems.push(`restore took ${g(t.restore_hours)}h, beyond the ${g(tolerance)}h tolerance`);
    const took = t.restore_hours !== null ? `, restored in ${g(t.restore_hours)}h` : "";
    out.B4 = problems.length
      ? result("B4", "fail", `Restore test ${t.restore_test_date}: ${problems.join("; ")}.`, [evidence("backups", t)])
      : result("B4", "pass", `Restore test ${t.restore_test_date} passed${took}.`, [evidence("backups", t)]);
  }
  return out;
}
