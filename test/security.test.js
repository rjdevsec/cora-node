// Security regression tests: one per finding of the secure code review (see SECURITY.md).
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { after, before, test } from "node:test";

import request from "supertest";

import { createCora } from "../src/app.js";
import { loadSamples } from "../src/routes.js";
import { today } from "../src/util.js";
import { csrfFrom, startMongo, tmpDir } from "./helpers.js";

const SECRET = "security-test-secret-key-0123456789abcdef";
const CASH = { service: "Cash Withdrawal (ATM)", tier: "1", tolerance: "4", apps: ["APP-ATM", "APP-CBS"] };
let mongo;
let app;

before(async () => {
  mongo = await startMongo();
  app = await createCora({ db: mongo.client.db("cora_sec"), dataDir: tmpDir("cora-sec-"), secretKey: SECRET });
  await loadSamples(app.locals.db, app.locals.config);
});
after(async () => mongo.stop());

async function signedIn(target = app) {
  const agent = request.agent(target);
  const page = await agent.get("/");
  return [agent, csrfFrom(page.text)];
}

test("SEC-01 a multipart POST without a token is refused on every route", async () => {
  const files = () => app.locals.db.collection("source_files").countDocuments();
  const before = await files();
  for (const path of ["/data/reset-samples", "/settings", "/run", "/runs/1/step/1/next", "/data/antivirus/mapping"]) {
    assert.equal((await request(app).post(path).field("reset", "1")).status, 403, path);
  }
  assert.equal((await request(app).post("/data/antivirus/upload").attach("file", Buffer.from("a,b\n1,2\n"), "x.csv")).status, 403);
  assert.equal(await files(), before, "no data changed");
});

test("SEC-01 PUT, PATCH and DELETE need the token too", async () => {
  for (const method of ["put", "patch", "delete"]) assert.equal((await request(app)[method]("/settings")).status, 403, method);
});

test("SEC-02 the synthetic-data reset is off unless enabled", async () => {
  const [agent, token] = await signedIn();
  assert.doesNotMatch((await agent.get("/data")).text, /Reload synthetic data/);
  assert.equal((await agent.post("/data/reset-samples").type("form").send({ _csrf: token })).status, 404);
});

test("SEC-03 the host's authorize hook controls each action", async () => {
  const roles = { viewer: ["view"], analyst: ["view", "assess"], admin: ["view", "assess", "manage"] };
  const cora = await createCora({
    db: mongo.client.db("cora_sec"), dataDir: tmpDir("cora-auth-"), secretKey: SECRET,
    authorize: (req, action) => (roles[req.headers["x-role"]] || []).includes(action),
    currentUser: (req) => req.headers["x-user"],
  });
  const as = (role) => {
    const agent = request.agent(cora);
    const wrap = (r) => r.set("x-role", role).set("x-user", `${role}@bank`);
    return { get: (p) => wrap(agent.get(p)), post: (p) => wrap(agent.post(p)) };
  };
  assert.equal((await request(cora).get("/")).status, 403); // no role: nothing
  const viewer = as("viewer");
  const page = await viewer.get("/");
  assert.equal(page.status, 200);
  assert.doesNotMatch(page.text, /Rules &amp; thresholds/); // menu hidden
  const token = csrfFrom(page.text);
  assert.equal((await viewer.post("/run").type("form").send({ _csrf: token, ...CASH })).status, 403);
  assert.equal((await viewer.get("/settings")).status, 403);
  assert.equal((await viewer.get("/data")).status, 403);

  const analyst = as("analyst");
  const t2 = csrfFrom((await analyst.get("/")).text);
  const run = await analyst.post("/run").type("form").send({ _csrf: t2, as_of: today(), mode: "full", ...CASH });
  assert.equal(run.status, 302);
  assert.equal((await analyst.get("/settings")).status, 403);
  const id = Number(run.headers.location.match(/\/runs\/(\d+)/)[1]);
  assert.equal((await app.locals.db.collection("runs").findOne({ id })).created_by, "analyst@bank"); // audit trail

  const admin = as("admin");
  const t3 = csrfFrom((await admin.get("/")).text);
  const up = await admin.post("/data/antivirus/upload").field("_csrf", t3)
    .attach("file", Buffer.from("Hostname,Agent Status,Signature Date,Last Check-in\nx,Running,2026-10-01,2026-10-01\n"), "av.csv");
  assert.equal(up.status, 302);
  const rec = await app.locals.db.collection("source_files").findOne({ kind: "antivirus", active: true });
  assert.equal(rec.uploaded_by, "admin@bank");
  if (process.platform !== "win32") assert.equal(fs.statSync(rec.stored_path).mode & 0o777, 0o600); // owner-only evidence file
  await loadSamples(app.locals.db, app.locals.config, { all: true });
});

test("SEC-04 Next cannot skip steps in a step-by-step run", async () => {
  const [agent, token] = await signedIn();
  const res = await agent.post("/run").type("form").send({ _csrf: token, as_of: today(), mode: "step", ...CASH });
  const id = Number(res.headers.location.match(/\/runs\/(\d+)/)[1]);
  await agent.post(`/runs/${id}/step/11/next`).type("form").send({ _csrf: token });
  await agent.post(`/runs/${id}/step/abc/next`).type("form").send({ _csrf: token });
  assert.equal((await app.locals.db.collection("runs").findOne({ id })).progress, 1);
  assert.match((await agent.get(`/runs/${id}/all-risks`)).headers.location, /\/step\/1$/);
});

test("SEC-05 prototype names and odd input give a clean 4xx or a message, never a 500", async () => {
  const [agent, token] = await signedIn();
  for (const p of ["/?service=__proto__", "/service-panel?service=constructor", "/data/__proto__/mapping", "/data/constructor/mapping",
    "/?service=a&service=b", "/runs/abc", "/runs/1/result/xyz", "/runs/1/step/0"]) {
    assert.ok((await agent.get(p)).status < 500, p);
  }
  for (const body of [{ service: "__proto__", apps: "x" }, { ...CASH, apps: ["__proto__", "constructor"] }, { ...CASH, tier: "9" },
    { ...CASH, tolerance: "-1" }, { ...CASH, tolerance: "1e400" }]) {
    const res = await agent.post("/run").type("form").send({ _csrf: token, ...body });
    assert.equal(res.status, 302, JSON.stringify(body));
    assert.doesNotMatch(res.headers.location, /\/runs\//, JSON.stringify(body)); // refused with a message, no run created
  }
  const up = await agent.post("/data/__proto__/upload").field("_csrf", token).attach("file", Buffer.from("a\n1\n"), "x.csv");
  assert.equal(up.status, 404);
});

test("SEC-06 settings are range-checked", async () => {
  const [agent, token] = await signedIn();
  for (const bad of [{ "check_weights.T1": "-5" }, { patch_sla_target_pct: "500" }, { risk_appetite: "<script>" }]) {
    await agent.post("/settings").type("form").send({ _csrf: token, ...bad });
    const page = (await agent.get("/settings")).text;
    assert.match(page, /must be/, JSON.stringify(bad));
  }
  const doc = await app.locals.db.collection("settings").findOne({ _id: "rules" });
  assert.equal(doc, null, "nothing saved");
});

test("SEC-07 security headers and no caching of results", async () => {
  const res = await request(app).get("/");
  const csp = res.headers["content-security-policy"];
  for (const d of ["script-src 'self'", "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'self'"]) assert.ok(csp.includes(d), d);
  assert.equal(res.headers["x-frame-options"], "SAMEORIGIN");
  assert.equal(res.headers["x-content-type-options"], "nosniff");
  assert.equal(res.headers["cache-control"], "no-store");
  assert.equal(res.headers["x-powered-by"], undefined);
  const cookie = res.headers["set-cookie"].join(";");
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
});

test("SEC-08 an expired or forged session cookie is not accepted", async () => {
  const sign = (v) => crypto.createHmac("sha256", SECRET).update(v).digest("base64url");
  const old = Buffer.from(JSON.stringify({ csrf: "t".repeat(32), iat: Date.now() - 9 * 3600 * 1000 })).toString("base64url");
  const res = await request(app).post("/settings").set("Cookie", `cora_session=${old}.${sign(old)}`).type("form").send({ _csrf: "t".repeat(32), reset: "1" });
  assert.equal(res.status, 403); // correctly signed, but older than 8 hours
  const forged = Buffer.from(JSON.stringify({ csrf: "t".repeat(32), iat: Date.now() })).toString("base64url");
  const res2 = await request(app).post("/settings").set("Cookie", `cora_session=${forged}.${sign("other")}`).type("form").send({ _csrf: "t".repeat(32), reset: "1" });
  assert.equal(res2.status, 403);
});

test("SEC-09 weak secret keys and oversized uploads are refused", async () => {
  await assert.rejects(createCora({ db: mongo.client.db("cora_sec"), dataDir: tmpDir("cora-weak-"), secretKey: "short" }), /at least 32/);
  const small = await createCora({ db: mongo.client.db("cora_sec"), dataDir: tmpDir("cora-big-"), secretKey: SECRET, maxUploadBytes: 1024 });
  const [agent, token] = await signedIn(small);
  const res = await agent.post("/data/antivirus/upload").field("_csrf", token).attach("file", Buffer.alloc(4096, "a"), "big.csv");
  assert.equal(res.status, 413);
});

test("SEC-10 risk export neutralises spreadsheet formulas", async () => {
  const { csvCell } = await import("../src/routes.js");
  for (const v of ["=1+1", "+1", "-1", "@SUM(A1)", "\t=1", "\r=1"]) assert.match(csvCell(v), /^"?'/, JSON.stringify(v));
});
