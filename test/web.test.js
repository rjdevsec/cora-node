// Every screen, the step-by-step flow, uploads and mapping, settings, CSRF, the CSV export, and mounting in a host app.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import cookieSession from "cookie-session";
import express from "express";
import expressSession from "express-session";
import request from "supertest";

import { createCora } from "../src/app.js";
import { DEFAULT_SETTINGS } from "../src/config.js";
import { loadSamples } from "../src/routes.js";
import { today } from "../src/util.js";
import { csrfFrom, startMongo, tmpDir } from "./helpers.js";

let mongo;
let app;
const CASH = { service: "Cash Withdrawal (ATM)", tier: "1", tolerance: "4", apps: ["APP-ATM", "APP-CAUTH", "APP-CBS", "APP-FRD", "APP-HSM", "APP-NOTIF"] };

before(async () => {
  mongo = await startMongo();
  app = await createCora({ db: mongo.client.db("cora_test"), dataDir: tmpDir("cora-web-"), secretKey: "test-secret-key-at-least-32-characters-long", enableSampleReset: true });
  await loadSamples(app.locals.db, app.locals.config);
});
after(async () => mongo.stop());

async function agentWithToken(target = app, base = "") {
  const agent = request.agent(target);
  const page = await agent.get(`${base}/`);
  return [agent, csrfFrom(page.text)];
}

async function startRun(agent, token, mode, base = "") {
  const res = await agent.post(`${base}/run`).type("form").send({ _csrf: token, as_of: today(), mode, ...CASH });
  assert.equal(res.status, 302);
  return [res.headers.location, Number(res.headers.location.match(/\/runs\/(\d+)/)[1])];
}

test("start screen, service panel and extraction preview", async () => {
  const [agent, token] = await agentWithToken();
  const panel = await agent.get("/service-panel?service=Cash+Withdrawal+%28ATM%29");
  assert.match(panel.text, /Run step by step/);
  assert.match(panel.text, /Card Authorisation/);
  const preview = await agent.post("/preview").type("form").send({ _csrf: token, apps: ["APP-ATM"] });
  assert.match(preview.text, /<span class="label">Registered assets<\/span><span class="value">3<\/span>/);
  assert.match(preview.text, /Backup management export/);
});

test("a full run opens every step and view", async () => {
  const [agent, token] = await agentWithToken();
  const [loc, id] = await startRun(agent, token, "full");
  assert.match(loc, new RegExp(`/runs/${id}$`));
  assert.match((await agent.get(`/runs/${id}`)).text, /Critical/);
  for (let n = 1; n <= 11; n += 1) assert.equal((await agent.get(`/runs/${id}/step/${n}`)).status, 200, `step ${n}`);
  assert.match((await agent.get(`/runs/${id}/step/1`)).text, /Ownership \(H1\)/);
  const pam = (await agent.get(`/runs/${id}/step/4`)).text;
  assert.match(pam, /Application servers/);
  assert.match(pam, /Database servers/);
  assert.match((await agent.get(`/runs/${id}/step/6`)).text, /EX-101/);
  const risks = (await agent.get(`/runs/${id}/step/7`)).text;
  assert.match(risks, /RSK-101/);
  assert.match(risks, /RSK-106/);
  assert.match((await agent.get(`/runs/${id}/step/8`)).text, /hsm-mgmt01/);
  const dr = (await agent.get(`/runs/${id}/step/9`)).text;
  assert.match(dr, /Exceeds tolerance/);
  assert.match(dr, /Thin margin/);
  const impact = (await agent.get(`/runs/${id}/step/10`)).text;
  assert.match(impact, /reachable from the internet/);
  assert.match(impact, /one step away from/);
  assert.match(impact, /took 6 hours to recover/);
  const scenarios = (await agent.get(`/runs/${id}/step/11`)).text;
  assert.match(scenarios, /Ransomware on/);
  assert.match(scenarios, /What to test/);
  assert.match(scenarios, /Breach likely/);
  const all = (await agent.get(`/runs/${id}/all-risks`)).text;
  assert.match(all, /Risk register for this assessment/);
  assert.ok(all.indexOf(">Critical<") < all.indexOf(">High<"));
  const matrix = (await agent.get(`/runs/${id}/matrix`)).text;
  assert.match(matrix, />B3</);
  const resultUrl = matrix.match(/href="(\/runs\/\d+\/result\/\d+)"/)[1];
  assert.equal((await agent.get(resultUrl).set("HX-Request", "true")).status, 200);
  assert.equal((await agent.get(resultUrl)).status, 200);
  for (const [old, n] of [["impact", 10], ["assets", 1], ["risks", 7], ["dr", 9], ["exceptions", 6]]) {
    assert.match((await agent.get(`/runs/${id}/${old}`)).headers.location, new RegExp(`/step/${n}$`));
  }
  assert.equal((await agent.get("/runs")).status, 200);
  assert.equal((await agent.get("/data")).status, 200);
});

test("the risk export is a CSV with formulas neutralised", async () => {
  const [agent, token] = await agentWithToken();
  const [, id] = await startRun(agent, token, "full");
  const csv = await agent.get(`/runs/${id}/findings.csv`);
  assert.match(csv.headers["content-type"], /text\/csv/);
  assert.match(csv.text, /Risk score/);
  assert.match(csv.text, /8\. Backups and restores/);
  const { csvCell } = await import("../src/routes.js");
  assert.equal(csvCell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
  assert.equal(csvCell("-1"), "'-1");
});

test("step by step reveals one step at a time", async () => {
  const [agent, token] = await agentWithToken();
  const [loc, id] = await startRun(agent, token, "step");
  assert.match(loc, new RegExp(`/runs/${id}/step/1$`));
  assert.match((await agent.get(`/runs/${id}/step/3`)).headers.location, /\/step\/1$/); // later steps locked
  assert.match((await agent.get(`/runs/${id}`)).headers.location, /\/step\/1$/); // summary locked
  const page = (await agent.get(`/runs/${id}/step/1`)).text;
  assert.match(page, /In progress · step 1 of 11/);
  for (let n = 1; n <= 10; n += 1) {
    const next = await agent.post(`/runs/${id}/step/${n}/next`).type("form").send({ _csrf: token });
    assert.match(next.headers.location, new RegExp(`/step/${n + 1}$`));
  }
  const last = await agent.post(`/runs/${id}/step/11/next`).type("form").send({ _csrf: token });
  assert.match(last.headers.location, /\/all-risks$/);
  assert.equal((await agent.get(`/runs/${id}/all-risks`)).status, 200);
  assert.equal((await agent.get(`/runs/${id}`)).status, 200);
});

test("upload with automatic and manual column mapping", async () => {
  const [agent, token] = await agentWithToken();
  const res = await agent.post("/data/antivirus/upload").field("_csrf", token).field("export_date", "2026-10-03")
    .attach("file", Buffer.from("Server Name,Agent,Sig Date,Contact\nfoo,Running,2026-10-01,2026-10-02\n"), "av.csv");
  assert.equal(res.status, 302);
  assert.match(res.headers.location, /\/mapping$/);
  assert.match((await agent.get("/data/antivirus/mapping")).text, /Required fields not mapped/);
  const saved = await agent.post("/data/antivirus/mapping").type("form")
    .send({ _csrf: token, map_hostname: "Server Name", map_agent_status: "Agent", map_signature_date: "Sig Date", map_last_checkin: "Contact" });
  assert.equal(saved.status, 302);
  const page = (await agent.get("/data/antivirus/mapping")).text;
  assert.match(page, /All required fields are mapped/);
  assert.match(page, /2026-10-01/);
  await loadSamples(app.locals.db, app.locals.config, { all: true }); // restore the synthetic data for later tests
});

test("settings save text and numbers", async () => {
  const [agent, token] = await agentWithToken();
  const form = { _csrf: token };
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    if (v && typeof v === "object") for (const [kk, vv] of Object.entries(v)) form[`${k}.${kk}`] = String(vv);
    else form[k] = String(v);
  }
  form.risk_appetite = "High";
  const res = await agent.post("/settings").type("form").send(form);
  assert.equal(res.status, 302);
  assert.match((await agent.get("/settings")).text, /<option selected>High<\/option>/);
  await agent.post("/settings").type("form").send({ _csrf: token, reset: "1" });
});

test("requests without a CSRF token are refused", async () => {
  const res = await request(app).post("/run").type("form").send({ service: "Cash Withdrawal (ATM)" });
  assert.equal(res.status, 403);
  const forged = Buffer.from(JSON.stringify({ csrf: "x".repeat(32) })).toString("base64url");
  const withForgedCookie = await request(app).post("/run").set("Cookie", `cora_session=${forged}.${"A".repeat(43)}`)
    .type("form").send({ _csrf: "x".repeat(32), service: "Cash Withdrawal (ATM)" });
  assert.equal(withForgedCookie.status, 403); // an unsigned session cookie is ignored
});

test("mounted under /cora inside a host Express app", async () => {
  const host = express();
  host.use(cookieSession({ name: "session", keys: ["host-key"] }));
  host.get("/login", (req, res) => { req.session.user = "alice"; res.send("ok"); });
  host.get("/whoami", (req, res) => res.send(req.session.user || "nobody"));
  host.use("/cora", app);
  const agent = request.agent(host);
  await agent.get("/login");
  const start = await agent.get("/cora/");
  assert.equal(start.status, 200);
  const links = [...start.text.matchAll(/(?:href|src|action)="(\/[^"]*)"/g)].map((m) => m[1]);
  assert.ok(links.length > 5 && links.every((l) => l.startsWith("/cora/")), "every link carries the mount path");
  assert.equal((await agent.get("/cora/static/fonts/PlusJakartaSans-latin.woff2")).status, 200);
  const token = csrfFrom(start.text);
  const [loc] = await startRun(agent, token, "step", "/cora");
  assert.match(loc, /^\/cora\/runs\/\d+\/step\/1$/);
  assert.equal((await agent.get(loc)).status, 200);
  assert.equal((await agent.get("/whoami")).text, "alice"); // the host's session is untouched
});

test("mounted in a typical MERN backend: express-session, login guard, body parsers, React catch-all", async () => {
  const host = express();
  host.use(express.json());
  host.use(express.urlencoded({ extended: true }));
  host.use(expressSession({ secret: "host-secret", resave: false, saveUninitialized: false }));
  host.post("/api/login", (req, res) => { req.session.user = req.body.user; res.json({ ok: true }); });
  host.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));
  const requireLogin = (req, res, next) => (req.session.user ? next() : res.sendStatus(401));
  host.use("/cora", requireLogin, app);
  host.get("/{*splat}", (req, res) => res.send("<div id=root></div>")); // the React app's index.html
  const agent = request.agent(host);
  assert.equal((await agent.get("/cora/")).status, 401);
  await agent.post("/api/login").send({ user: "alice" });
  const start = await agent.get("/cora/");
  assert.equal(start.status, 200);
  assert.match(start.headers["x-frame-options"], /SAMEORIGIN/); // can be shown in an iframe on the host's own site
  const [loc] = await startRun(agent, csrfFrom(start.text), "full", "/cora");
  assert.equal((await agent.get(loc)).status, 200);
  assert.equal((await agent.get(`${loc}/all-risks`)).status, 200);
  assert.deepEqual((await agent.get("/api/me")).body, { user: "alice" }); // the host's session is untouched
  assert.match((await agent.get("/dashboard")).text, /id=root/); // the host's own routes still work
});
