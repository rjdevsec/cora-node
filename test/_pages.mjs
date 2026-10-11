// Dev check: render every page once and print the first error per page.
import request from "supertest";
import { createCora } from "../src/app.js";
import { loadSamples } from "../src/routes.js";
import { csrfFrom, startMongo, tmpDir } from "./helpers.js";
import { today } from "../src/util.js";
const mongo = await startMongo();
const errors = [];
const orig = console.error; console.error = (e) => errors.push(String(e?.message || e).split("\n").slice(0, 3).join(" | "));
const app = await createCora({ db: mongo.client.db("pages"), dataDir: tmpDir("cora-pages-"), secretKey: "x" });
await loadSamples(app.locals.db, app.locals.config);
const agent = request.agent(app);
const check = async (url, opts = {}) => {
  errors.length = 0;
  const r = opts.post ? await agent.post(url).type("form").send(opts.post) : await agent.get(url).set(opts.headers || {});
  console.log(String(r.status).padEnd(4), url, errors[0] ? "\n      " + errors[0] : "");
  return r;
};
let home = await check("/");
let token; try { token = csrfFrom(home.text); } catch { token = "x"; }
await check("/service-panel?service=Cash+Withdrawal+%28ATM%29");
await check("/preview", { post: { _csrf: token, apps: ["APP-ATM"] } });
await check("/data"); await check("/data/antivirus/mapping"); await check("/settings");
const run = await check("/run", { post: { _csrf: token, service: "Cash Withdrawal (ATM)", tier: "1", tolerance: "4", as_of: today(), mode: "full", apps: ["APP-ATM", "APP-CAUTH", "APP-CBS", "APP-FRD", "APP-HSM", "APP-NOTIF"] } });
const id = (run.headers.location || "").match(/runs\/(\d+)/)?.[1];
if (id) {
  for (const u of ["", "/all-risks", "/matrix", "/findings.csv", ...Array.from({ length: 11 }, (_, i) => `/step/${i + 1}`)]) await check(`/runs/${id}${u}`);
  await check(`/runs/${id}/result/1`); await check(`/runs/${id}/result/1`, { headers: { "HX-Request": "true" } });
  const lastApp = await mongo.client.db("pages").collection("check_results").findOne({ application_id: { $ne: null } });
  await check(`/runs/${id}/result/${lastApp.id}`);
}
await check("/runs");
console.error = orig; await mongo.stop(); process.exit(0);
