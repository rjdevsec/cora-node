# CORA (Node.js)

Cyber and Operational Resilience Assessment of a critical business service. This is the Node.js port of the Python/Flask version in `service_assessment/`. The engine gives identical results on the same CSVs.

**Stack:** Node.js 22 or later, Express 5, Nunjucks (server-rendered screens with HTMX), and the MongoDB driver. Uploaded CSVs are kept on disk; everything else is stored in MongoDB.

## Run it

```bash
npm install
npm run dev        # demo: in-memory MongoDB plus synthetic data on http://127.0.0.1:8100
npm test           # 29 tests, including test/security.test.js: engine, every screen, uploads, CSRF, mounting
npm start          # against a real MongoDB (CORA_MONGODB_URI)
```

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `CORA_MONGODB_URI` | `mongodb://127.0.0.1:27017` | MongoDB connection |
| `CORA_DB_NAME` | `cora` | Database name |
| `CORA_DATA_DIR` | `cora_data` | Where uploaded CSVs are stored |
| `CORA_SECRET_KEY` | generated once into `CORA_DATA_DIR/secret.key` | Signs the session cookie, at least 32 characters. **Set it in production**, for example `openssl rand -hex 32`. |
| `CORA_SESSION_COOKIE` | `cora_session` | Cookie name, separate from the host's cookie |
| `CORA_COOKIE_SECURE` | on when `NODE_ENV=production` | HTTPS-only cookie; `1` or `0` overrides |
| `CORA_ENABLE_SAMPLE_RESET` | off (on with `npm run dev`) | Shows "Reload synthetic data". Never enable with real data. |
| `PORT`, `HOST` | `8100`, `127.0.0.1` | Stand-alone server only |

## Embedding in a React + MongoDB application

The screens stay as they are; there is no React rewrite. CORA is an Express sub-app, and the host's Node backend mounts it under a path:

```js
import { createCora } from "cora";

const cora = await createCora({
  db: mongoClient.db("cora"),
  dataDir: "/var/lib/cora",
  secretKey: process.env.CORA_SECRET_KEY,
  // Who may do what. Actions: "view" (results), "assess" (start runs), "manage" (data sources and settings).
  authorize: (req, action) => action === "manage" ? req.user?.roles?.includes("cora-admin") : Boolean(req.user),
  // Recorded on runs, uploads, mappings and settings changes (audit trail).
  currentUser: (req) => req.user?.email,
});
app.use("/cora", requireLogin, cora);       // authentication stays with the host
// ...then the React catch-all, e.g. app.get("/{*splat}", sendIndexHtml)
```

- **Roles:** without `authorize`, every signed-in user can upload evidence and change scoring settings. Pass it in production.
- **Order:** mount CORA *before* the React catch-all route, or that route will serve `index.html` for `/cora/*`.
- **React side:** add a menu link to `/cora/` (a normal link, not a React Router `<Link>`), or show it in an `<iframe src="/cora/">`. Framing is allowed from the same site only.
- **Development:** if the React dev server (Vite or CRA) proxies `/api` to the backend, add `/cora` to the proxy.
- **Database:** pass a `Db` from the host's `MongoClient`. With Mongoose, use `mongoose.connection.getClient().db("cora")`. If the bundled driver version differs, pass `mongoUri` instead. CORA uses its own collections: `source_files`, `settings`, `runs`, `check_results`, `counters`.
- **Sessions:** CORA keeps its state in its own signed cookie (`cora_session`, scoped to the mount path) on `req.coraSession`. It never touches `req.session`, so `express-session`, `cookie-session`, or JWT logins in the host are unaffected.
- **Body parsing:** host body parsers in front of CORA are fine.
- **Uploads:** CSV uploads are limited to 25 MB, so a reverse proxy in front needs at least that much (`client_max_body_size` in nginx).
- **Other frameworks:** Express and NestJS (Express adapter) mount it directly. Fastify needs `@fastify/express`.
- **Test:** `test/web.test.js` covers both a `cookie-session` host and a typical MERN backend (express-session, login guard, body parsers, React catch-all).

## Connectors (Phase 5)

All data is read through `loadRows()` and `loadAll()` in `src/sources.js`. Comments marked `CONNECTOR (Phase 5)` show where a direct API integration replaces each CSV upload. Examples are the CMDB, the vulnerability scanner, EDR, PAM, the SIEM, the GRC registers, backup and DR.

## Security

See [SECURITY.md](SECURITY.md) for the secure code review (10 findings, all fixed) and the items the host application must provide: authentication, HTTPS, rate limiting and encryption at rest. `test/security.test.js` has a regression test for each finding.
