import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient } from "mongodb";

import { DEFAULT_SETTINGS } from "../src/config.js";
import { assess, catalogue } from "../src/engine/pipeline.js";
import { generate } from "../src/sampleData.js";
import { SOURCES, autoMap, convert, readCsv } from "../src/sources.js";
import { today } from "../src/util.js";

export const tmpDir = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

/** Rows per source from the synthetic CSVs, exactly as loadAll() would return them (no database needed). */
export function sampleData(asOf = today()) {
  const paths = generate(tmpDir("cora-data-"), asOf);
  const data = {};
  for (const [kind, file] of Object.entries(paths)) {
    const { headers, rows } = readCsv(fs.readFileSync(file));
    const mapping = autoMap(SOURCES[kind], headers);
    data[kind] = [{ id: 1, filename: path.basename(file), export_date: asOf },
      rows.map((raw, i) => Object.fromEntries([["_row", i + 2], ...SOURCES[kind].fields.map((f) => [f.key, convert(f, mapping[f.key] ? raw[mapping[f.key]] : "")])]))];
  }
  return data;
}

export function assessService(name = "Cash Withdrawal (ATM)", { data = sampleData(), settings = DEFAULT_SETTINGS, applications } = {}) {
  const svc = catalogue(data.dependencies[1])[name];
  return assess({ name, tier: svc.tier, tolerance_hours: svc.tolerance_hours, applications: applications || svc.applications, as_of: today() }, data, settings);
}

export const byHost = (result) => Object.fromEntries(result.assets.map((a) => [a.hostname.split(".")[0].toLowerCase(), a]));

export async function startMongo() {
  const server = await MongoMemoryServer.create();
  const client = new MongoClient(server.getUri());
  await client.connect();
  return { server, client, stop: async () => { await client.close(); await server.stop(); } };
}

export function csrfFrom(html) {
  const m = html.match(/name="_csrf" value="([^"]+)"/) || html.match(/"X-CSRF-Token": "([^"]+)"/);
  if (!m) throw new Error("No CSRF token in page");
  return m[1];
}
