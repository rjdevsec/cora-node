/*
 * CORA as a library for a host application.
 *
 *   import { createCora } from "cora";
 *   const cora = await createCora({ db: mongoClient.db("cora"), dataDir: "/var/lib/cora" });
 *   app.use("/cora", requireLogin, cora);           // protect the path with the host's authentication
 *
 * The engine can also be used on its own: assess() takes a service definition, rows per source and settings.
 */
export { createCora } from "./app.js";
export { loadConfig, DEFAULT_SETTINGS } from "./config.js";
export { assess, catalogue } from "./engine/pipeline.js";
export { businessImpact } from "./engine/narrative.js";
export { SOURCES, loadAll, loadRows, storeUpload } from "./sources.js";
export { loadSamples } from "./routes.js";
