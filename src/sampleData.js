/*
 * Synthetic data set for the Cash Withdrawal (ATM) service, with dates relative to the day it is generated.
 *
 * Gaps are planted on purpose so that every check has something to find: miscategorised and end-of-life databases,
 * overdue exploitable vulnerabilities, missing or stale antivirus, service accounts outside PAM, hosts missing from
 * the SIEM, an unregistered host in an in-scope subnet, an asset missing from discovery, an owner who has left, and
 * valid, expired and unapproved exceptions. Backups: a host with no job, stale and failing jobs, an unprotected copy,
 * out-of-date, missing and too-slow restore tests. Risks above appetite, overdue and unowned treatment, invalid
 * acceptance, a risk that maps to nothing, and DR tests that are missing scope, out of date, too slow for the
 * tolerance or lose too much data.
 *
 *     node src/sampleData.js [folder]          # writes the CSVs (default: ./sample_data)
 *
 * The files use realistic export headers (not CORA's field names) so they exercise column mapping. They also serve
 * as reference output for Phase 5 connectors: a connector for a source should yield the same records, mapped to the
 * same field keys, that this generator's CSV yields after mapping.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { addDays, fmtDateTime, today } from "./util.js";

export const FILES = {
  dependencies: "application_dependencies.csv",
  asset_register: "asset_register.csv",
  discovery: "discovery_scan.csv",
  vulnerabilities: "vulnerability_report.csv",
  antivirus: "edr_export.csv",
  pam: "pam_export.csv",
  privileged_accounts: "privileged_accounts.csv",
  siem: "siem_log_sources.csv",
  exceptions: "exception_register.csv",
  hr_leavers: "hr_leavers.csv",
  risk_register: "risk_register.csv",
  backups: "backup_jobs.csv",
  dr_tests: "dr_test_results.csv",
};

const APPS = {
  "APP-ATM": ["ATM Switch", "Priya Shah"],
  "APP-CAUTH": ["Card Authorisation", "Marcus Lee"],
  "APP-CBS": ["Core Banking", "Elena Novak"],
  "APP-FRD": ["Fraud Detection", "Tom Becker"],
  "APP-HSM": ["HSM Key Management", "Priya Shah"],
  "APP-NOTIF": ["Customer Notifications", "Daniel Price"], // owner has left
  "APP-IB": ["Internet Banking", "Grace Wu"],
  "APP-PAYHUB": ["Payments Hub", "Grace Wu"],
  "APP-TELLER": ["Teller Platform", "Omar Haddad"],
};

const SERVICES = [
  ["Cash Withdrawal (ATM)", 1, 4, ["APP-ATM", "APP-CAUTH", "APP-CBS", "APP-FRD", "APP-HSM", "APP-NOTIF"]],
  ["Online Payments", 1, 2, ["APP-IB", "APP-PAYHUB", "APP-CBS", "APP-FRD"]],
  ["Branch Teller Services", 2, 24, ["APP-TELLER", "APP-CBS"]],
];

// hostname, asset id, ip, mac, type, applications, criticality, owner, os, end of support, internet facing
const ASSETS = [
  ["atmsw-app01", "A-1001", "10.20.1.11", "00:1a:2b:01:00:11", "Server", "APP-ATM", "Tier 1", "Priya Shah", "RHEL 8.8", "2029-05-31", "N"],
  ["atmsw-app02", "A-1002", "10.20.1.12", "00:1a:2b:01:00:12", "Server", "APP-ATM", "Tier 1", "Priya Shah", "RHEL 8.8", "2029-05-31", "N"],
  ["atmsw-db01", "A-1003", "10.20.1.21", "00:1a:2b:01:00:21", "Database", "APP-ATM", "Tier 2", "Priya Shah", "Oracle 19c on RHEL 7.9", "2024-06-30", "N"],
  ["cauth-app01", "A-1101", "10.20.1.31", "00:1a:2b:01:00:31", "Server", "APP-CAUTH", "Tier 1", "Marcus Lee", "Windows Server 2019", "2029-01-09", "N"],
  ["cauth-app02", "A-1102", "10.20.1.32", "00:1a:2b:01:00:32", "Server", "APP-CAUTH", "Tier 1", "Marcus Lee", "Windows Server 2019", "2029-01-09", "N"],
  ["cauth-db01", "A-1103", "10.20.1.41", "00:1a:2b:01:00:41", "Database", "APP-CAUTH", "Tier 1", "Marcus Lee", "SQL Server 2016", "2026-07-14", "N"],
  ["hsm-mgmt01", "A-1201", "10.20.1.51", "00:1a:2b:01:00:51", "Server", "APP-HSM", "Tier 1", "", "RHEL 9.2", "2032-05-31", "N"],
  ["cbs-app01", "A-1301", "10.20.2.11", "00:1a:2b:02:00:11", "Server", "APP-CBS;APP-TELLER", "Tier 1", "Elena Novak", "AIX 7.2", "2027-04-30", "N"],
  ["cbs-app02", "A-1302", "10.20.2.12", "00:1a:2b:02:00:12", "Server", "APP-CBS", "Tier 1", "Elena Novak", "AIX 7.2", "2027-04-30", "N"],
  ["cbs-db01", "A-1303", "10.20.2.21", "00:1a:2b:02:00:21", "Database", "APP-CBS", "Tier 1", "Elena Novak", "Oracle 19c", "2027-04-30", "N"],
  ["CBS-DB02.corp.bank.local", "A-1304", "10.20.2.22", "00:1a:2b:02:00:22", "Database", "APP-CBS", "Tier 1", "Elena Novak", "Oracle 19c", "2027-04-30", "N"],
  ["frd-app01", "A-1401", "10.20.3.11", "00:1a:2b:03:00:11", "Server", "APP-FRD", "Tier 1", "Tom Becker", "Ubuntu 22.04", "2027-04-30", "N"],
  ["frd-db01", "A-1402", "10.20.3.21", "00:1a:2b:03:00:21", "Database", "APP-FRD", "Tier 2", "Daniel Price", "PostgreSQL 14", "2026-11-12", "N"],
  ["notif-gw01", "A-1501", "10.20.3.31", "00:1a:2b:03:00:31", "Server", "APP-NOTIF", "Tier 1", "Sara Okafor", "Ubuntu 20.04", "2025-05-31", "Y"],
  ["notif-app01", "A-1502", "10.20.3.32", "00:1a:2b:03:00:32", "Server", "APP-NOTIF", "Tier 2", "Sara Okafor", "Ubuntu 22.04", "2027-04-30", "N"],
  // Assets of other services
  ["ib-web01", "A-2001", "10.30.1.11", "00:1a:2b:04:00:11", "Server", "APP-IB", "Tier 1", "Grace Wu", "RHEL 9.2", "2032-05-31", "Y"],
  ["payhub-app01", "A-2101", "10.30.1.21", "00:1a:2b:04:00:21", "Server", "APP-PAYHUB", "Tier 1", "Grace Wu", "RHEL 9.2", "2032-05-31", "N"],
  ["teller-app01", "A-3001", "10.40.1.11", "00:1a:2b:05:00:11", "Server", "APP-TELLER", "Tier 2", "Omar Haddad", "Windows Server 2022", "2031-10-14", "N"],
];
const IN_SCOPE_SERVERS = ASSETS.slice(0, 15).map((a) => a[0]);

const csvCell = (v) => {
  const s = v === null || v === undefined ? "" : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
function write(file, header, rows) {
  fs.writeFileSync(file, [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n");
}

/** Write the synthetic CSVs into `target`, dated relative to `asOf`; returns kind -> file path. */
export function generate(target, asOf = today()) {
  fs.mkdirSync(target, { recursive: true });
  const paths = Object.fromEntries(Object.entries(FILES).map(([k, f]) => [k, path.join(target, f)]));
  const d = (daysAgo) => addDays(asOf, -daysAgo);
  const now = new Date(Date.parse(`${asOf}T09:00:00Z`));
  const hoursAgo = (h) => fmtDateTime(new Date(now.getTime() - h * 3_600_000));

  write(paths.dependencies, ["Service", "Service Tier", "Impact Tolerance Hours", "Application ID", "Application Name", "Application Owner"],
    SERVICES.flatMap(([svc, tier, tol, apps]) => apps.map((app) => [svc, tier, tol, app, APPS[app][0], APPS[app][1]])));

  // The register holds one row per asset and application, as many CMDB exports do.
  const register = ASSETS.flatMap(([host, aid, ip, , typ, apps, crit, owner, os, eol, inet]) =>
    apps.split(";").map((app) => [aid, host, ip, typ, app, "Production", crit, owner, os, eol, inet]));
  register.push(["A-9001", "hr-app01", "10.50.1.11", "Server", "APP-HR", "Production", "Tier 3", "Ken Adams", "RHEL 8.8", "2029-05-31", "N"]);
  write(paths.asset_register, ["Asset ID", "Hostname", "IP Address", "Type", "Application", "Environment", "Criticality",
    "Owner", "Operating System", "End of Support", "Internet Facing"], register);

  const discovery = ASSETS.filter(([host]) => host !== "hsm-mgmt01") // hsm-mgmt01: registered but never seen by discovery
    .map(([host, , ip, mac, , , , , os]) => {
      const short = host.split(".")[0].toLowerCase();
      return [`${short}.corp.bank.local`, ip, mac, os, d(short === "cbs-app02" ? 45 : 1)];
    });
  discovery.push(["tmp-atm-test01.corp.bank.local", "10.20.1.99", "00:1a:2b:01:00:99", "Windows Server 2012 R2", d(2)]); // unregistered, in scope subnet
  discovery.push(["printer-3f", "10.99.0.5", "00:1a:2b:99:00:05", "Embedded", d(1)]); // unregistered, out of scope
  write(paths.discovery, ["DNS Name", "IP Address", "MAC Address", "Operating System", "Last Seen"], discovery);

  const vulns = [ // host, ip, id, title, severity, detected days ago, exploit, status, fixed days ago
    ["atmsw-app01", "10.20.1.11", "CVE-2026-1001", "OpenSSL buffer overflow", "High", 10, "N", "Open", null],
    ["atmsw-app01", "10.20.1.11", "CVE-2026-0900", "glibc privilege escalation", "Medium", 60, "N", "Fixed", 40],
    ["atmsw-app02", "10.20.1.12", "CVE-2026-1001", "OpenSSL buffer overflow", "High", 12, "N", "Open", null],
    ["atmsw-app02", "10.20.1.12", "CVE-2026-0900", "glibc privilege escalation", "Medium", 60, "N", "Fixed", 41],
    ["atmsw-db01", "10.20.1.21", "CVE-2026-2002", "Oracle Database RCE", "Medium", 40, "N", "Open", null],
    ["atmsw-db01", "10.20.1.21", "CVE-2026-1800", "Oracle TNS listener flaw", "High", 100, "N", "Fixed", 80],
    ["cauth-app01", "10.20.1.31", "CVE-2026-3003", "Windows SMB remote code execution", "Critical", 8, "Y", "Open", null],
    ["cauth-app01", "10.20.1.31", "CVE-2026-2900", "Windows kernel EoP", "High", 70, "N", "Fixed", 50],
    ["cauth-app02", "10.20.1.32", "CVE-2026-3100", "Windows RDP remote code execution", "Critical", 45, "Y", "Open", null],
    ["cauth-app02", "10.20.1.32", "CVE-2026-3101", ".NET Framework RCE", "High", 50, "N", "Open", null],
    ["cauth-db01", "10.20.1.41", "CVE-2026-3200", "SQL Server elevation of privilege", "High", 20, "N", "Open", null],
    ["cauth-db01", "10.20.1.41", "CVE-2026-2950", "SQL Server info disclosure", "Medium", 120, "N", "Fixed", 70],
    ["cbs-app01", "10.20.2.11", "CVE-2026-4001", "AIX OpenSSH vulnerability", "High", 65, "N", "Open", null],
    ["cbs-app01", "10.20.2.11", "CVE-2026-3500", "AIX kernel flaw", "High", 120, "N", "Fixed", 110],
    ["cbs-app02", "10.20.2.12", "CVE-2026-3500", "AIX kernel flaw", "High", 120, "N", "Fixed", 105],
    ["cbs-db01", "10.20.2.21", "CVE-2026-3700", "Oracle Database RCE", "Critical", 30, "N", "Fixed", 22],
    ["CBS-DB02", "10.20.2.22", "CVE-2026-3800", "Oracle weak cipher", "Low", 30, "N", "Open", null],
    ["CBS-DB02", "10.20.2.22", "CVE-2026-3700", "Oracle Database RCE", "Critical", 30, "N", "Fixed", 21],
    ["frd-app01", "10.20.3.11", "CVE-2026-5001", "Ubuntu libc flaw", "Medium", 30, "N", "Open", null],
    ["frd-app01", "10.20.3.11", "CVE-2026-4800", "Ubuntu kernel EoP", "High", 80, "N", "Fixed", 60],
    ["frd-db01", "10.20.3.21", "CVE-2026-5100", "PostgreSQL SQL injection", "High", 90, "N", "Fixed", 50],
    ["frd-db01", "10.20.3.21", "CVE-2026-5101", "PostgreSQL DoS", "Medium", 10, "N", "Open", null],
    ["notif-gw01", "10.20.3.31", "CVE-2026-6001", "nginx HTTP/2 remote code execution", "Critical", 35, "Y", "Open", null],
    ["notif-gw01", "10.20.3.31", "CVE-2026-6002", "OpenSSH remote code execution", "High", 70, "Y", "Open", null],
    ["notif-gw01", "10.20.3.31", "CVE-2026-5900", "Ubuntu sudo flaw", "Medium", 200, "N", "Fixed", 50],
    // Scanned under an old hostname; matched to the register by IP.
    ["notifapp01-old", "10.20.3.32", "CVE-2026-6100", "Java runtime flaw", "Medium", 120, "N", "Open", null],
    ["notifapp01-old", "10.20.3.32", "CVE-2026-6000", "Apache Tomcat RCE", "High", 100, "N", "Fixed", 30],
    ["notifapp01-old", "10.20.3.32", "CVE-2026-5950", "Log4j variant", "Medium", 200, "N", "Fixed", 20],
    ["tmp-atm-test01", "10.20.1.99", "CVE-2025-9999", "Windows Server 2012 R2 end of life", "Critical", 200, "Y", "Open", null],
    ["ib-web01", "10.30.1.11", "CVE-2026-7001", "Apache httpd RCE", "Critical", 5, "Y", "Open", null],
    ["legacy-ftp02", "10.88.1.5", "CVE-2024-1234", "vsftpd backdoor", "Critical", 400, "Y", "Open", null],
  ];
  write(paths.vulnerabilities, ["Host", "IP Address", "CVE", "Name", "Severity", "First Detected", "Exploit Available", "Status", "Fixed Date"],
    vulns.map(([h, ip, v, t, s, det, e, st, fx]) => [h, ip, v, t, s, d(det), e, st, fx === null ? "" : d(fx)]));

  const av = [];
  for (const host of [...IN_SCOPE_SERVERS, "ib-web01", "payhub-app01", "teller-app01"]) {
    const short = host.split(".")[0];
    if (short === "notif-gw01") continue; // no agent
    let sig = 1;
    let checkin = 0;
    if (short === "atmsw-app02") sig = 9;
    if (short === "frd-app01") { checkin = 15; sig = 15; }
    av.push([short.toUpperCase(), "Running", d(sig), d(checkin)]);
  }
  write(paths.antivirus, ["Computer Name", "Agent Status", "Definition Date", "Last Seen"], av);

  const priv = [];
  const pam = [];
  for (const host of IN_SCOPE_SERVERS) {
    const short = host.split(".")[0].toLowerCase();
    if (short === "hsm-mgmt01") continue; // no privileged account list for this host
    const accounts = [short.startsWith("cauth-app") ? "Administrator" : "root", `svc_${short.split("-")[0]}`];
    if (short === "cauth-app02") accounts.push("svc_batch");
    if (short === "notif-gw01") accounts.push("deploy");
    for (const acc of accounts) {
      priv.push([short, acc, ["root", "Administrator", "deploy"].includes(acc) ? "Local admin" : "Service"]);
      if ((short === "cauth-app02" && acc === "svc_batch") || (short === "notif-gw01" && acc === "deploy")) continue; // not in the vault at all
      const onboarded = short === "cauth-app01" && acc === "svc_cauth" ? "No" : "Yes";
      pam.push([short, acc, onboarded, onboarded === "Yes" ? d(20) : ""]);
    }
  }
  write(paths.privileged_accounts, ["Server", "Account Name", "Privilege"], priv);
  write(paths.pam, ["Address", "Username", "Managed", "Last Password Change"], pam);

  const siem = [];
  for (const host of [...IN_SCOPE_SERVERS, "ib-web01", "payhub-app01"]) {
    const short = host.split(".")[0].toLowerCase();
    if (short === "cauth-app02") continue; // never onboarded to the SIEM
    siem.push([short, short.includes("db") ? "Database audit" : "OS syslog", hoursAgo(short === "cbs-db01" ? 6 * 24 : 2)]);
  }
  write(paths.siem, ["Log Source", "Log Source Type", "Last Event"], siem);

  write(paths.exceptions, ["Exception ID", "Asset", "Control", "Reason", "Compensating Control", "Approver", "Expiry Date"], [
    ["EX-101", "atmsw-db01", "T5", "Oracle and RHEL upgrade scheduled for next quarter", "Network isolation; database firewall", "CISO", d(-90)],
    ["EX-102", "cauth-db01", "T5", "Vendor certification for SQL Server 2022 pending", "Virtual patching on IPS", "Head of IT Risk", d(20)],
    ["EX-103", "cauth-app01", "T8", "Legacy service account cannot rotate", "", "", d(-60)],
    ["EX-104", "frd-app01", "T6", "EDR migration in progress", "Host IPS enabled; daily integrity scan", "CISO", d(-30)],
    ["EX-105", "ib-web01", "T4", "Awaiting vendor patch", "WAF virtual patch", "CISO", d(-14)],
  ]);

  write(paths.hr_leavers, ["Employee Name", "Last Day"], [["Daniel Price", d(60)], ["Ken Adams", d(200)]]);

  // Risk register: applications by ID or by name, as real registers mix both.
  const risks = [
    ["RSK-101", "Unsupported SQL Server on card authorisation database", "Card Authorisation", "cauth-db01", "T5", "High", "High",
      "Open", "Upgrade to SQL Server 2022", "Marcus Lee", d(20), "", ""], // above appetite, overdue
    ["RSK-102", "ATM switch database on end-of-life platform", "APP-ATM", "atmsw-db01", "T5", "High", "Medium",
      "Accepted", "Upgrade scheduled next quarter", "Priya Shah", "", "CISO", d(-60)], // valid acceptance
    ["RSK-103", "Internet-facing notification gateway with exploitable flaws", "APP-NOTIF", "notif-gw01", "T4;T5;T6", "Critical",
      "Critical", "Open", "Rebuild on supported OS behind WAF", "Sara Okafor", d(-30), "", ""], // above appetite, in date
    ["RSK-104", "Core banking batch accounts outside PAM", "Core Banking", "", "T8", "High", "High",
      "Accepted", "Accepted pending PAM upgrade", "Elena Novak", "", "IT Manager", d(10)], // wrong approver, review overdue
    ["RSK-105", "Fraud model drift reduces detection rate", "APP-FRD", "", "", "Medium", "Low",
      "Open", "Retrain model quarterly", "", d(-90), "", ""], // no owner
    ["RSK-106", "Legacy file transfer server unpatched", "File Transfer Gateway", "legacy-ftp02", "T4", "High", "High",
      "Open", "Decommission", "Ken Adams", d(-10), "", ""], // maps to nothing known
    ["RSK-107", "HSM firmware outdated", "APP-HSM", "hsm-mgmt01", "", "Medium", "Low",
      "Closed", "Firmware upgraded", "Priya Shah", d(100), "", ""], // closed, ignored
    ["RSK-108", "Card authorisation servers missing SIEM coverage", "APP-CAUTH", "cauth-app02", "T9", "High", "Medium",
      "Open", "Onboard log sources", "Marcus Lee", d(-45), "", ""], // within appetite, in date
    ["RSK-109", "Core banking recovery exceeds tolerance", "APP-CBS", "", "D2", "High", "High",
      "Open", "Active-active database replication", "Elena Novak", d(-120), "", ""],
    ["RSK-110", "Card authorisation API open to credential stuffing", "APP-CAUTH", "", "", "High", "High",
      "Open", "Rate limiting and bot detection on the API gateway", "Marcus Lee", d(-40), "", ""], // application security
    ["RSK-201", "Internet banking DDoS exposure", "Internet Banking", "ib-web01", "", "High", "Medium",
      "Open", "Scrubbing service", "Grace Wu", d(-60), "", ""],
  ];
  // The risk register labels each risk as an application (security) risk or an asset risk.
  const appRisks = new Set(["RSK-104", "RSK-105", "RSK-109", "RSK-110", "RSK-201"]);
  write(paths.risk_register, ["Risk ID", "Risk Title", "Category", "Affected Applications", "Affected Assets", "Related Checks",
    "Inherent Risk", "Residual Risk", "Status", "Treatment Plan", "Risk Owner", "Target Date", "Accepted By", "Next Review"],
  risks.map((r) => [r[0], r[1], appRisks.has(r[0]) ? "Application" : "Asset", ...r.slice(2)]));

  // Backup management export: one row per backup job, with the latest restore test.
  const backups = [];
  for (const [host] of ASSETS) {
    const short = host.split(".")[0].toLowerCase();
    if (short === "hsm-mgmt01") continue; // no backup job at all
    const isDb = short.includes("db");
    let last = hoursAgo(8);
    let lastResult = "Success";
    let status = "Active";
    let [immutable, offsite] = isDb ? ["Yes", "Yes"] : ["No", "Yes"];
    let [restoreDate, restoreResult, restoreHours] = [d(60), "Pass", isDb ? 1.5 : 0.5];
    if (short === "cbs-db01") last = hoursAgo(3 * 24); // daily job, last success 3 days ago
    if (short === "cauth-db01") { last = hoursAgo(4 * 24); lastResult = "Failed"; } // failing for 4 days
    if (short === "notif-gw01") [immutable, offsite] = ["No", "No"]; // no protected copy
    if (short === "frd-db01") restoreDate = d(300); // restore test out of date
    if (short === "cbs-db02") restoreHours = 7; // restore slower than the 4h tolerance
    if (short === "atmsw-app02") [restoreDate, restoreResult, restoreHours] = ["", "", ""]; // never restore-tested
    if (short === "teller-app01") status = "Disabled";
    backups.push([short, `${isDb ? "DB" : "FS"}-${short.toUpperCase()}`, "Daily", status, last, lastResult,
      isDb ? 35 : 14, immutable, offsite, restoreDate, restoreResult, restoreHours]);
  }
  write(paths.backups, ["Client Name", "Backup Policy", "Schedule", "Job State", "Last Successful Backup", "Last Run Result",
    "Retention Days", "Immutable Copy", "Offsite Copy", "Last Restore Test", "Restore Result", "Restore Time Hours"], backups);

  write(paths.dr_tests, ["Application", "Test Date", "Test Type", "Assets Tested", "RTO", "Actual Recovery Time", "RPO",
    "Actual Data Loss", "Result", "Open Issues", "Issue Due Date"], [
    ["APP-ATM", d(100), "Full failover", "atmsw-app01;atmsw-app02;atmsw-db01", 2, 1.5, 0.25, 0.1, "Pass", "", ""],
    ["APP-CAUTH", d(200), "Full failover", "cauth-app01;cauth-app02;cauth-db01", 2, 3.5, 0.25, 0.2, "Pass",
      "Manual DNS change slowed failover", d(30)], // thin margin, RTO missed, issue overdue
    ["APP-CBS", d(150), "Database failover", "cbs-app01;cbs-app02;cbs-db01", 4, 6, 0.5, 0.25, "Partial",
      "Replication lag on CBS-DB02 not tested", d(-20)], // exceeds tolerance, partial scope
    ["APP-CBS", d(520), "Full failover", "cbs-app01;cbs-app02;cbs-db01;cbs-db02", 4, 3, 0.5, 0.25, "Pass", "", ""],
    ["Fraud Detection", d(400), "Full failover", "frd-app01;frd-db01", 4, 2, 1, 0.5, "Pass", "", ""], // outside policy period
    ["APP-HSM", d(60), "Key restore", "hsm-mgmt01", 1, 0.75, 0, 0, "Pass", "", ""],
    ["APP-NOTIF", d(90), "Full failover", "notif-gw01;notif-app01", 2, 1, 1, 2, "Pass", "", ""], // data loss beyond RPO
    ["APP-IB", d(80), "Full failover", "ib-web01", 1, 0.5, 0.25, 0.1, "Pass", "", ""],
    ["APP-PAYHUB", d(70), "Full failover", "payhub-app01", 1, 1.5, 0.25, 0.1, "Pass", "", ""],
    ["APP-TELLER", d(120), "Full failover", "teller-app01", 8, 5, 1, 0.5, "Pass", "", ""],
  ]);
  return paths;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const target = path.resolve(process.argv[2] || "sample_data");
  for (const [kind, file] of Object.entries(generate(target))) console.log(kind.padEnd(22), file);
}
