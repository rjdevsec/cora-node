// Evidence rows attached to check results: a source row as plain, display-ready values.
import { SOURCES } from "../sources.js";
import { fmtDateTime } from "../util.js";

export function jsonable(value) {
  if (value instanceof Date) return fmtDateTime(value, true);
  if (Array.isArray(value)) return value.join("; ");
  if (value === null || value === undefined) return "";
  if (value === true) return "Yes";
  if (value === false) return "No";
  return value;
}

export function evidence(kind, row) {
  const values = {};
  for (const [k, v] of Object.entries(row)) if (k !== "_row") values[k] = jsonable(v);
  return { source: kind, source_label: SOURCES[kind].label, row: row._row, values };
}
