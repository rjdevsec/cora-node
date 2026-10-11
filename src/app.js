/*
 * The CORA web application as an Express app.
 *
 *   Stand-alone:  node src/server.js                       (see server.js)
 *   In a host:    const cora = await createCora({ db });   app.use("/cora", cora);
 *
 * Every link CORA renders is built from the mount path (req.baseUrl), so it works at any prefix. CORA has no sign-on
 * of its own yet: protect the mount path with the host application's authentication.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";
import nunjucks from "nunjucks";
import onHeaders from "on-headers";

import { loadConfig } from "./config.js";
import { connect } from "./db.js";
import { APP_CHECKS, ASSET_CHECKS, CHECKS, STATUS_LABELS } from "./engine/checks.js";
import { buildRoutes, ROUTES } from "./routes.js";
import { g } from "./util.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function secretKey(config) {
  if (config.secretKey) {
    if (String(config.secretKey).length < 32) throw new Error("CORA secret key must be at least 32 characters (CORA_SECRET_KEY).");
    return config.secretKey;
  }
  const file = path.join(config.dataDir, "secret.key");
  if (!fs.existsSync(file)) {
    fs.mkdirSync(config.dataDir, { recursive: true });
    fs.writeFileSync(file, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
  }
  return fs.readFileSync(file, "utf8").trim();
}

/** Build a URL for a named route under the mount path; unused params become the query string. */
export function makeUrl(base, name, params = {}) {
  if (name === "static") return `${base}/static/${params.filename}`;
  const pattern = ROUTES[name];
  if (!pattern) throw new Error(`Unknown route: ${name}`);
  const rest = { ...params };
  const url = pattern.replace(/\{(\w+)\}/g, (_, k) => {
    const v = rest[k];
    delete rest[k];
    return encodeURIComponent(v);
  });
  const query = new URLSearchParams(Object.entries(rest).filter(([, v]) => v !== undefined && v !== null)).toString();
  return `${base}${url}${query ? `?${query}` : ""}`;
}

function templateEnv(viewsDir) {
  const env = new nunjucks.Environment(new nunjucks.FileSystemLoader(viewsDir, { noCache: process.env.NODE_ENV === "development" }),
    { autoescape: true, trimBlocks: false, lstripBlocks: false });
  const get = (obj, key) => String(key).split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
  env.addFilter("g", g);
  env.addFilter("where", (arr, attr, value) => (arr || []).filter((x) => get(x, attr) === value));
  env.addFilter("where_not", (arr, attr, value) => (arr || []).filter((x) => get(x, attr) !== value));
  env.addFilter("where_in", (arr, attr, values) => (arr || []).filter((x) => values.includes(get(x, attr))));
  env.addFilter("where_not_in", (arr, attr, values) => (arr || []).filter((x) => !values.includes(get(x, attr))));
  env.addFilter("truthy", (arr, attr) => (arr || []).filter((x) => Boolean(get(x, attr))));
  env.addFilter("pluck", (arr, attr) => (arr || []).map((x) => get(x, attr)));
  env.addFilter("numbers", (arr) => (arr || []).filter((x) => typeof x === "number" && Number.isFinite(x)));
  env.addFilter("max", (arr) => Math.max(...(arr || [])));
  env.addFilter("capfirst", (s) => (s ? String(s)[0].toUpperCase() + String(s).slice(1) : ""));
  env.addFilter("count", (arr) => (arr || []).length);
  // Python truthiness: empty lists, empty objects, "", 0, null and undefined are false (in JavaScript [] and {} are true).
  const has = (v) => (Array.isArray(v) ? v.length > 0 : v && typeof v === "object" && !(v instanceof Date) ? Object.keys(v).length > 0 : Boolean(v));
  env.addFilter("has", has);
  env.addFilter("flatten_count", (arr) => (arr || []).reduce((n, x) => n + (Array.isArray(x) ? x.length : 0), 0));
  env.addFilter("keys", (obj) => Object.keys(obj || {}));
  env.addFilter("values", (obj) => Object.values(obj || {}));
  env.addFilter("dt", (d) => (d instanceof Date ? d.toISOString().replace("T", " ").slice(0, 16) : d));
  env.addFilter("cell", (v) => (v === null || v === undefined || v === "" ? "" : v === true ? "Yes" : v === false ? "No" : Array.isArray(v) ? v.join("; ") : v instanceof Date ? v.toISOString().replace("T", " ").slice(0, 16) : v));
  env.addGlobal("CHECKS", CHECKS);
  env.addGlobal("ASSET_CHECKS", ASSET_CHECKS);
  env.addGlobal("APP_CHECKS", APP_CHECKS);
  env.addGlobal("STATUS_LABELS", STATUS_LABELS);
  env.addGlobal("STATUS_CLASS", { pass: "good", fail: "bad", excepted: "warn", no_data: "neutral", "n/a": "na" });
  env.addGlobal("RATING_CLASS", { Critical: "crit", High: "bad", Medium: "warn", Low: "good" });
  return env;
}

/**
 * Create the CORA Express app.
 * options: { db } an existing MongoDB Db (for example from the host application), or { mongoUri, dbName };
 *          plus any config overrides (dataDir, secretKey, sessionCookie, cookieSecure, ...).
 */
export async function createCora(options = {}) {
  const config = loadConfig(options);
  let { db } = options;
  let client = null;
  if (!db) ({ client, db } = await connect(config.mongoUri, config.dbName));
  fs.mkdirSync(config.uploadDir, { recursive: true, mode: 0o700 }); // uploaded evidence: readable by the service account only
  if (config.cookieSecure === false && process.env.NODE_ENV === "production") {
    console.warn("CORA: session cookie is not marked Secure. Set CORA_COOKIE_SECURE=1 when served over HTTPS.");
  }

  const app = express();
  app.disable("x-powered-by");
  const env = templateEnv(path.join(ROOT, "views"));
  env.express(app);
  app.set("view engine", "html");

  app.use((req, res, next) => {
    res.setHeader("X-Frame-Options", "SAMEORIGIN"); // the host may show CORA in an iframe on the same site
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; "
      + "base-uri 'self'; form-action 'self'; frame-ancestors 'self'");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    next();
  });
  app.use("/static", express.static(path.join(ROOT, "public"), { maxAge: "1h" }));
  // CORA's state lives on req.coraSession in its own signed cookie, scoped to the mount path. It never reads or replaces
  // req.session, so the host's session middleware (express-session, cookie-session, or none) keeps working when mounted.
  app.use(coraSession({ name: config.sessionCookie, secret: secretKey(config), secure: config.cookieSecure, maxAgeSeconds: 8 * 3600 }));
  // Flat form fields only (no nested objects from the query-string parser), at most 1 MB and 2,000 fields.
  app.use(express.urlencoded({ extended: false, limit: "1mb", parameterLimit: 2000 }));
  app.use((req, res, next) => {
    req.body ??= {}; // Express 5 leaves req.body undefined when no parser ran
    // Pages carry assessment results and evidence: never cache them in the browser or a shared proxy.
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  // Authorisation and audit, supplied by the host (see README). Defaults: every signed-in user may do everything.
  const authorize = typeof config.authorize === "function" ? config.authorize : () => true;
  const currentUser = typeof config.currentUser === "function" ? config.currentUser : () => null;

  // CSRF: a random token per session, required on every request that changes data. The only exempt request is the
  // multipart upload, whose route checks the token after the file is parsed; every other multipart request is refused.
  app.use((req, res, next) => {
    req.coraSession.csrf ??= crypto.randomBytes(24).toString("base64url");
    res.locals.csrf_token = () => req.coraSession.csrf;
    res.locals.csrf_field = () => new nunjucks.runtime.SafeString(`<input type="hidden" name="_csrf" value="${req.coraSession.csrf}">`);
    res.locals.url = (name, params) => makeUrl(req.baseUrl, name, params);
    res.locals.flashes = () => { const f = req.coraSession.flash || []; req.coraSession.flash = []; return f; };
    req.flash = (category, message) => { req.coraSession.flash = [...(req.coraSession.flash || []), [category, message]]; };
    res.locals.can = (action) => Boolean(authorize(req, action));
    req.coraUser = () => {
      const u = currentUser(req);
      return u == null ? null : String(u).slice(0, 200);
    };
    if (!SAFE_METHODS.has(req.method)) {
      const multipart = String(req.headers["content-type"] || "").toLowerCase().startsWith("multipart/form-data");
      const uploadRoute = req.method === "POST" && /^\/data\/[a-z_]+\/upload$/.test(req.path);
      if (!(multipart && uploadRoute) && !checkCsrf(req)) {
        return res.status(403).send("Invalid or missing CSRF token. Reload the page and try again.");
      }
    }
    next();
  });

  app.use(buildRoutes({ db, config, authorize }));
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err?.code === "LIMIT_FILE_SIZE") return res.status(413).send("The file is larger than the upload limit.");
    if (err?.name === "MulterError" || err?.type === "entity.too.large" || err?.type === "entity.parse.failed" || err?.status === 413) {
      return res.status(400).send("The request could not be read.");
    }
    console.error("CORA error:", err?.stack || err);
    res.status(500).send("Something went wrong. The error has been logged.");
  });

  app.locals.db = db;
  app.locals.config = config;
  app.locals.close = async () => { if (client) await client.close(); };
  return app;
}

/** A small signed-cookie session (JSON, HMAC-SHA256). The cookie is rewritten only when the data changed. */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function coraSession({ name, secret, secure = false, maxAgeSeconds }) {
  const sign = (value) => crypto.createHmac("sha256", secret).update(value).digest("base64url");
  return (req, res, next) => {
    let data = {};
    const raw = readCookie(req.headers.cookie, name);
    const [value, sig] = raw ? raw.split(".") : [];
    if (value && sig && sig.length === 43 && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(value)))) {
      try {
        const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
        // The cookie's Max-Age is advisory; the signed issue time is what ends the session.
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && Number(parsed.iat) + maxAgeSeconds * 1000 > Date.now()) data = parsed;
      } catch { /* tampered or old format: start a new session */ }
    }
    data.iat ??= Date.now();
    const before = raw ? JSON.stringify(data) : "";
    req.coraSession = data;
    onHeaders(res, () => {
      const now = JSON.stringify(req.coraSession);
      if (now === before) return;
      const encoded = Buffer.from(now).toString("base64url");
      res.append("Set-Cookie", `${name}=${encoded}.${sign(encoded)}; Path=${req.baseUrl || "/"}; Max-Age=${maxAgeSeconds}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`);
    });
    next();
  };
}

function readCookie(header, name) {
  for (const part of String(header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

export function checkCsrf(req) {
  const sent = req.body?._csrf || req.headers["x-csrf-token"];
  const expected = req.coraSession?.csrf;
  if (!sent || !expected || sent.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected));
}
