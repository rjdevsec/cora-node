/*
 * Run CORA on its own:
 *
 *   CORA_MONGODB_URI=mongodb://host:27017 CORA_DATA_DIR=/var/lib/cora node src/server.js
 *
 *   node src/server.js --demo      local demo: loads the synthetic data set for any source with no file yet. With
 *                                   no CORA_MONGODB_URI it also starts a private MongoDB (from the dev dependency
 *                                   mongodb-memory-server) that keeps its data in CORA_DATA_DIR/mongo.
 */
import fs from "node:fs";
import path from "node:path";

import { createCora } from "./app.js";
import { loadConfig } from "./config.js";
import { loadSamples } from "./routes.js";

const demo = process.argv.includes("--demo");
const port = Number(process.env.PORT || 8100);
const host = process.env.HOST || "127.0.0.1";

async function main() {
  const config = loadConfig();
  let mongod = null;
  if (demo && !process.env.CORA_MONGODB_URI) {
    const { MongoMemoryServer } = await import("mongodb-memory-server");
    const dbPath = path.join(config.dataDir, "mongo");
    fs.mkdirSync(dbPath, { recursive: true });
    mongod = await MongoMemoryServer.create({ instance: { dbPath, storageEngine: "wiredTiger" } });
    process.env.CORA_MONGODB_URI = mongod.getUri();
    console.log(`Demo database: local MongoDB with data in ${dbPath}`);
  }
  const app = await createCora({ mongoUri: process.env.CORA_MONGODB_URI || config.mongoUri, ...(demo ? { enableSampleReset: true } : {}) });
  if (demo) {
    const loaded = await loadSamples(app.locals.db, app.locals.config);
    if (loaded.length) console.log(`Loaded the synthetic data set for: ${loaded.join(", ")}`);
  }
  const server = app.listen(port, host, () => console.log(`CORA on http://${host}:${port}`));
  const stop = async () => {
    server.close();
    await app.locals.close();
    if (mongod) await mongod.stop({ doCleanup: false });
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
