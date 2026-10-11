// Shared helpers: date handling, normalisation and small collection utilities.
//
// Dates are carried as "YYYY-MM-DD" strings (they compare correctly as text) and date-times as JS Date objects
// in UTC, so day arithmetic never shifts with the server's time zone.

const DAY_MS = 86_400_000;
const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };

const pad = (n, w = 2) => String(n).padStart(w, "0");

export function isoDate(y, m, d) {
  return `${pad(y, 4)}-${pad(m)}-${pad(d)}`;
}

function validDate(y, m, d) {
  if (!(y >= 1 && m >= 1 && m <= 12 && d >= 1)) return false;
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

// The same formats, in the same order, as the Python version: day-first before month-first.
const DATE_PATTERNS = [
  [/^(\d{4})-(\d{1,2})-(\d{1,2})$/, (m) => [m[1], m[2], m[3]]],          // %Y-%m-%d
  [/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/, (m) => [m[3], m[2], m[1]]],        // %d/%m/%Y
  [/^(\d{1,2})-(\d{1,2})-(\d{4})$/, (m) => [m[3], m[2], m[1]]],          // %d-%m-%Y
  [/^(\d{4})\/(\d{1,2})\/(\d{1,2})$/, (m) => [m[1], m[2], m[3]]],        // %Y/%m/%d
  [/^(\d{1,2}) ([A-Za-z]{3}) (\d{4})$/, (m) => [m[3], MONTHS[m[2].toLowerCase()], m[1]]], // %d %b %Y
  [/^(\d{1,2})-([A-Za-z]{3})-(\d{4})$/, (m) => [m[3], MONTHS[m[2].toLowerCase()], m[1]]], // %d-%b-%Y
  [/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/, (m) => [m[3], m[1], m[2]]],        // %m/%d/%Y
];
const DATETIME_PATTERNS = [
  /^(\d{4})-(\d{1,2})-(\d{1,2})[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?$/,
];
const DMY_TIME = /^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{1,2}):(\d{2})$/;

/** Parse a date in any supported format; returns "YYYY-MM-DD" or null. */
export function parseDate(value) {
  const v = String(value ?? "").trim();
  if (!v) return null;
  for (const [re, pick] of DATE_PATTERNS) {
    const m = v.match(re);
    if (!m) continue;
    const [y, mo, d] = pick(m).map(Number);
    if (validDate(y, mo, d)) return isoDate(y, mo, d);
  }
  if (v.length > 10) {
    const dt = parseDatetime(v);
    return dt ? dateOf(dt) : null;
  }
  return null;
}

/** Parse a date-time (or a date, as midnight); returns a UTC Date or null. */
export function parseDatetime(value) {
  let v = String(value ?? "").trim();
  if (!v) return null;
  v = v.replace("Z", "").split("+")[0];
  for (const re of DATETIME_PATTERNS) {
    const m = v.match(re);
    if (m) {
      const [y, mo, d, h, mi, s] = [m[1], m[2], m[3], m[4], m[5], m[6] || 0].map(Number);
      if (validDate(y, mo, d) && h < 24 && mi < 60 && s < 60) return new Date(Date.UTC(y, mo - 1, d, h, mi, s));
    }
  }
  const m = v.match(DMY_TIME);
  if (m) {
    const [d, mo, y, h, mi] = m.slice(1).map(Number);
    if (validDate(y, mo, d) && h < 24 && mi < 60) return new Date(Date.UTC(y, mo - 1, d, h, mi));
  }
  if (v.length <= 10) {
    const d = parseDate(v);
    if (d) return new Date(`${d}T00:00:00Z`);
  }
  return null;
}

export function parseBool(value) {
  const v = String(value ?? "").trim().toLowerCase();
  if (["y", "yes", "true", "1", "t", "onboarded", "managed"].includes(v)) return true;
  if (["n", "no", "false", "0", "f"].includes(v)) return false;
  return null;
}

export function parseList(value) {
  return String(value ?? "").split(/[;|,]/).map((p) => p.trim()).filter(Boolean);
}

export function parseNumber(value) {
  const v = String(value ?? "").trim();
  if (v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** Hostnames are compared case-insensitively and without their domain suffix. */
export function normHost(value) {
  const v = String(value ?? "").trim().toLowerCase();
  if (!v || /^[\d.]+$/.test(v)) return v;
  return v.split(".")[0];
}

export function normMac(value) {
  return String(value ?? "").toLowerCase().replace(/[^0-9a-f]/g, "");
}

export function dateOf(dt) {
  return isoDate(dt.getUTCFullYear(), dt.getUTCMonth() + 1, dt.getUTCDate());
}

const dayNumber = (iso) => Date.parse(`${iso}T00:00:00Z`) / DAY_MS;

/** Whole days from a to b (both "YYYY-MM-DD"). */
export function daysBetween(a, b) {
  return Math.round(dayNumber(b) - dayNumber(a));
}

/** Days from `when` (a date string or a Date) to `asOf`; null when `when` is missing. */
export function ageDays(asOf, when) {
  if (when == null || when === "") return null;
  return daysBetween(when instanceof Date ? dateOf(when) : when, asOf);
}

/** The last instant of a date, as milliseconds (Python: datetime.combine(as_of, time.max)). */
export function endOfDayMs(asOf) {
  return Date.parse(`${asOf}T23:59:59.999Z`);
}

export function addDays(iso, days) {
  return dateOf(new Date(Date.parse(`${iso}T00:00:00Z`) + days * DAY_MS));
}

/** Today's date on this machine's calendar. */
export function today() {
  const d = new Date();
  return isoDate(d.getFullYear(), d.getMonth() + 1, d.getDate());
}

export function fmtDateTime(dt, seconds = false) {
  const base = `${dateOf(dt)} ${pad(dt.getUTCHours())}:${pad(dt.getUTCMinutes())}`;
  return seconds ? `${base}:${pad(dt.getUTCSeconds())}` : base;
}

/** Python's "%g": up to six significant digits, no trailing zeros. */
export function g(n) {
  if (n == null || n === "") return "";
  const num = Number(n);
  if (!Number.isFinite(num)) return String(n);
  return String(Number(num.toPrecision(6)));
}

export const round = (n, places = 0) => {
  const f = 10 ** places;
  return Math.round((n + Number.EPSILON) * f) / f;
};

/** First element with the largest key (Python's max(..., key=...)). */
export function maxBy(items, key) {
  let best;
  let bestKey;
  for (const item of items) {
    const k = key(item);
    if (best === undefined || k > bestKey) {
      best = item;
      bestKey = k;
    }
  }
  return best;
}

export const sum = (items, fn = (x) => x) => items.reduce((acc, x) => acc + Number(fn(x) || 0), 0);

export function join(names) {
  const list = [...new Set(names.filter(Boolean))];
  if (!list.length) return "the service";
  return list.length === 1 ? list[0] : `${list.slice(0, -1).join(", ")} and ${list[list.length - 1]}`;
}

/** The /24 network an IPv4 address sits in, or null. */
export function subnet(ip) {
  const parts = String(ip ?? "").trim().split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null;
  return `${parts.slice(0, 3).join(".")}.0/24`;
}
