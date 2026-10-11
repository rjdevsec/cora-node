// Engine rules on the synthetic data set: every planted gap is found, scenarios are generated and rated.
import assert from "node:assert/strict";
import { test } from "node:test";

import { catalogue } from "../src/engine/pipeline.js";
import { assessService, byHost, sampleData } from "./helpers.js";

const data = sampleData();
const cash = assessService("Cash Withdrawal (ATM)", { data });
const hosts = byHost(cash);
const status = (h, c) => hosts[h].results[c].status;

test("catalogue lists services and applications", () => {
  const services = catalogue(data.dependencies[1]);
  assert.deepEqual(Object.keys(services).sort(), ["Branch Teller Services", "Cash Withdrawal (ATM)", "Online Payments"]);
  const svc = services["Cash Withdrawal (ATM)"];
  assert.equal(svc.tier, 1);
  assert.equal(svc.tolerance_hours, 4);
  assert.deepEqual(svc.applications.map((a) => a.id), ["APP-ATM", "APP-CAUTH", "APP-CBS", "APP-FRD", "APP-HSM", "APP-NOTIF"]);
});

test("asset resolution and reconciliation", () => {
  const rec = cash.reconciliation;
  assert.equal(rec.registered_in_scope, 15);
  assert.equal(rec.unregistered, 1);
  assert.equal(hosts["tmp-atm-test01"].registered, false);
  assert.equal(status("tmp-atm-test01", "T1"), "fail");
  assert.equal(status("hsm-mgmt01", "T2"), "fail"); // never seen by discovery
  assert.equal(status("cbs-app02", "T2"), "fail"); // seen 45 days ago
  assert.equal(status("cbs-db02", "T2"), "pass"); // FQDN in register, short name elsewhere
  assert.ok(!("printer-3f" in hosts)); // unregistered but out of scope
  assert.deepEqual(hosts["cbs-app01"].other_services, ["Branch Teller Services", "Online Payments"]);
});

test("hygiene checks find the planted gaps", () => {
  assert.equal(status("atmsw-db01", "T3"), "fail");
  assert.equal(status("frd-db01", "T3"), "fail");
  assert.equal(status("cauth-app02", "T4"), "fail");
  assert.equal(status("cauth-app01", "T4"), "pass");
  assert.equal(status("notif-app01", "T4"), "fail"); // matched by IP under an old hostname
  assert.equal(status("cauth-db01", "T5"), "fail"); // expired exception does not apply
  assert.equal(status("atmsw-db01", "T5"), "excepted"); // valid exception
  assert.equal(status("notif-gw01", "T6"), "fail");
  assert.equal(status("notif-gw01", "T7"), "n/a");
  assert.equal(status("frd-app01", "T6"), "excepted");
  assert.equal(status("atmsw-app02", "T7"), "fail");
  assert.equal(status("cauth-app01", "T8"), "fail");
  assert.equal(status("hsm-mgmt01", "T8"), "no_data");
  assert.equal(status("cauth-app02", "T9"), "fail");
  assert.equal(status("cbs-db01", "T9"), "fail");
  assert.equal(status("cauth-app01", "P1"), "fail");
  assert.equal(status("frd-db01", "P2"), "fail");
  assert.equal(status("hsm-mgmt01", "H1"), "fail");
  assert.equal(status("frd-db01", "H1"), "fail"); // owner has left
  assert.ok(Object.values(hosts["atmsw-app01"].results).every((r) => ["pass", "n/a"].includes(r.status)));
});

test("backup checks find the planted gaps", () => {
  assert.equal(status("hsm-mgmt01", "B1"), "fail");
  assert.equal(status("hsm-mgmt01", "B2"), "n/a");
  assert.equal(status("cbs-db01", "B2"), "fail");
  assert.match(hosts["cauth-db01"].results.B2.detail, /Failed/);
  assert.equal(status("notif-gw01", "B3"), "fail");
  assert.match(hosts["frd-db01"].results.B4.detail, /300 days/);
  assert.match(hosts["cbs-db02"].results.B4.detail, /beyond the 4h tolerance/);
  assert.equal(status("atmsw-app02", "B4"), "fail");
  assert.ok(["B1", "B2", "B3", "B4"].every((c) => status("atmsw-db01", c) === "pass"));
  assert.equal(status("tmp-atm-test01", "B1"), "n/a");
});

test("risk register linking and checks", () => {
  const risks = Object.fromEntries(cash.risks.map((r) => [r.id, r]));
  assert.ok(!("RSK-107" in risks)); // closed
  assert.ok(!("RSK-201" in risks)); // another service's application
  assert.deepEqual(cash.unmapped_risks.map((r) => r.id), ["RSK-106"]);
  assert.deepEqual(risks["RSK-101"].apps, ["APP-CAUTH"]); // referenced by application name
  assert.ok(risks["RSK-101"].above && risks["RSK-101"].overdue);
  assert.match(risks["RSK-104"].acceptance_problems[0], /not a senior approver/);
  assert.equal(risks["RSK-110"].category, "Application");
  const app = cash.app_level;
  assert.equal(app["APP-CAUTH"].R1.status, "fail");
  assert.equal(app["APP-ATM"].R3.status, "pass");
  assert.equal(app["APP-CBS"].R3.status, "fail");
  assert.equal(app["APP-FRD"].R2.status, "fail");
  assert.deepEqual(hosts["cauth-db01"].results.T5.risk_ids, ["RSK-101"]);
  assert.deepEqual(hosts["atmsw-db01"].results.R4.unrecorded, ["T3"]);
});

test("DR checks and recovery position", () => {
  const dr = Object.fromEntries(cash.dr.map((d) => [d.id, d]));
  assert.deepEqual(Object.fromEntries(Object.entries(dr).map(([k, d]) => [k, d.recovery.status])),
    { "APP-ATM": "proven", "APP-CAUTH": "thin", "APP-CBS": "exceeds", "APP-FRD": "unproven", "APP-HSM": "proven", "APP-NOTIF": "proven" });
  assert.equal(dr["APP-CBS"].test_count, 2);
  assert.equal(dr["APP-CBS"].test.age_days, 150); // latest of two tests used
  assert.equal(dr["APP-NOTIF"].results.D3.status, "fail");
  assert.equal(dr["APP-CAUTH"].results.D4.status, "fail");
});

test("scenarios are generated from the risks and rated", () => {
  const byKey = Object.fromEntries(cash.scenario_results.map((s) => [s.key, s]));
  for (const k of ["ransomware", "external", "privileged", "undetected", "data_loss", "outage", "risk:RSK-110"]) assert.ok(k in byKey, k);
  assert.deepEqual(byKey.external.hosts, ["notif-gw01"]);
  assert.equal(byKey.external.rating, "High"); // material exposure, recovery proven
  assert.equal(byKey.ransomware.rating, "Critical");
  assert.equal(byKey.outage.rating, "Critical");
  assert.ok(cash.scenario_results.every((s) => s.test.length && s.triggers.length));
  assert.equal(cash.rating, "Critical");
  assert.match(cash.reason, /^Worst scenario/);
});

test("the same evidence gives the same result", () => {
  const again = assessService("Cash Withdrawal (ATM)", { data });
  assert.deepEqual(again.scenario_results.map((s) => [s.name, s.rating, s.score]), cash.scenario_results.map((s) => [s.name, s.rating, s.score]));
  assert.equal(again.rating, cash.rating);
});

test("no scenario reaches Critical when nothing plausible", () => {
  const r = assessService("Online Payments", { data, applications: [{ id: "APP-IB", name: "Internet Banking", owner: "Grace Wu" }] });
  assert.ok(["Low", "Medium"].includes(r.rating));
});
