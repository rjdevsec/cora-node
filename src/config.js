// Configuration from environment variables, and the default rules and thresholds.
import path from "node:path";

export function loadConfig(overrides = {}) {
  const dataDir = path.resolve(overrides.dataDir || process.env.CORA_DATA_DIR || "cora_data");
  return {
    // MongoDB, as used by the host application. One database per CORA installation.
    mongoUri: process.env.CORA_MONGODB_URI || "mongodb://127.0.0.1:27017",
    dbName: process.env.CORA_DB_NAME || "cora",
    // Uploaded evidence files and the generated session key live here (back it up with the database).
    dataDir,
    uploadDir: path.join(dataDir, "uploads"),
    secretKey: process.env.CORA_SECRET_KEY || null, // generated into dataDir when unset
    // CORA's own session cookie, so it never collides with a host application's cookie when embedded.
    sessionCookie: process.env.CORA_SESSION_COOKIE || "cora_session",
    // Secure (HTTPS-only) cookie: on by default when NODE_ENV=production; CORA_COOKIE_SECURE=1 or 0 overrides.
    cookieSecure: process.env.CORA_COOKIE_SECURE ? process.env.CORA_COOKIE_SECURE === "1" : process.env.NODE_ENV === "production",
    maxUploadBytes: 25 * 1024 * 1024, // 25 MB per upload
    // "Reload synthetic data" replaces every source with demo data. Off unless the demo server turns it on.
    enableSampleReset: process.env.CORA_ENABLE_SAMPLE_RESET === "1",
    // Host hooks (pass to createCora): authorize(req, action) -> boolean for "view" | "assess" | "manage";
    // currentUser(req) -> a name or id recorded on runs, uploads and settings changes for the audit trail.
    authorize: null,
    currentUser: null,
    ...overrides,
  };
}

// Rule thresholds and scoring weights. Every value is editable per client on the Rules & thresholds screen;
// these are the starting values to be calibrated with the first client.
export const DEFAULT_SETTINGS = {
  patch_sla_days: { critical: 14, high: 30, medium: 90, low: 180 }, // T4, P2
  patch_sla_target_pct: 95, // P2: share of vulnerabilities fixed (or still open) within SLA
  discovery_max_age_days: 30, // T2: registered asset not seen in discovery for longer than this
  av_signature_max_age_days: 3, // T7
  av_checkin_max_age_days: 7, // T6: agent installed but not reporting
  siem_max_silence_hours: 24, // T9: no events within this period
  file_max_age_days: 30, // upload freshness flag
  check_weights: {
    T1: 3, T2: 2, T3: 2, T4: 5, T5: 4, T6: 4, T7: 2, T8: 4, T9: 3,
    P1: 2, P2: 2, H1: 1, R4: 1,
    B1: 5, B2: 4, B3: 4, B4: 3,
    R1: 4, R2: 3, R3: 2, D1: 5, D2: 5, D3: 4, D4: 2,
  },
  modifiers: { exposure: 1.5, exploitability: 1.5, concentration: 1.25, compounding: 1.5 },
  excepted_weight_factor: 0.3, // a gap under a valid exception still counts, at reduced weight
  material_gap_min_weight: 3, // a failed check at or above this weight is a "material" gap
  rating_thresholds: { critical: 25, high: 12, medium: 1 }, // scenario hygiene score; "high" and above is material
  risk_appetite: "Medium", // R1: open risks rated above this fail (Low / Medium / High / Critical)
  senior_approvers: "CISO, CRO, Chief Risk Officer, Head of IT Risk", // R3: who may accept High and Critical risks
  dr_test_max_age_days: 365, // D1: a passed, full-scope test is needed within this period
  thin_margin_pct: 25, // recovery within tolerance but by less than this share of it is a thin margin
  backup_grace_days: 1, // B2: allowed slack beyond the schedule interval
  restore_test_max_age_days: 180, // B4: a passed restore test is needed within this period
};
