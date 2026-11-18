// Builds VaultGuard_Project_Report.docx  (run: node report/build_report.js)
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, AlignmentType,
  HeadingLevel, WidthType, BorderStyle, ShadingType, PageBreak, Footer, PageNumber,
  NumberFormat, TableOfContents, LevelFormat, VerticalAlign,
} = require("docx");

const DIR = __dirname;
const FONT = "Times New Roman";
const TEXT_W = 9026; // A4 width 11906 - 2 x 1440 margins

// ---------------------------------------------------------------- helpers
function runs(text, base = {}) {
  return String(text).split(/(\*\*[^*]+\*\*)/).filter(Boolean).map((t) =>
    t.startsWith("**") ? new TextRun({ text: t.slice(2, -2), bold: true, ...base }) : new TextRun({ text: t, ...base }));
}
const P = (text, o = {}) => new Paragraph({ children: runs(text), alignment: AlignmentType.JUSTIFIED, spacing: { before: 80, after: 120 }, ...o });
const C = (text, o = {}) => new Paragraph({ children: runs(text, o.run || {}), alignment: AlignmentType.CENTER, spacing: { after: o.after ?? 120 } });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)], pageBreakBefore: true });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(t)] });
const B = (text) => new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: runs(text), alignment: AlignmentType.JUSTIFIED, spacing: { after: 60 } });
let numRef = 0;
const NL = (items) => { const ref = "num" + (numRef++ % 20); return items.map((t) => new Paragraph({ numbering: { reference: ref, level: 0 }, children: runs(t), alignment: AlignmentType.JUSTIFIED, spacing: { after: 60 } })); };
const BR = () => new Paragraph({ children: [new PageBreak()] });
const SP = () => new Paragraph({ children: [] });

const tableNo = {}, figNo = {};
let curCh = 0;
function caption(kind, text) {
  const store = kind === "Table" ? tableNo : figNo;
  store[curCh] = (store[curCh] || 0) + 1;
  return new Paragraph({ alignment: AlignmentType.CENTER, keepNext: kind === "Table", spacing: { before: 120, after: 120 },
    children: [new TextRun({ text: `${kind} ${curCh}.${store[curCh]}: ${text}`, bold: true, size: 22 })] });
}

const border = { style: BorderStyle.SINGLE, size: 4, color: "808080" };
const borders = { top: border, bottom: border, left: border, right: border };
const NOB = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const RATING_FILL = { High: "F4B6B6", Medium: "FFE699", Low: "C6E0B4", Pass: "C6E0B4" };

function cell(text, width, o = {}) {
  const lines = String(text).split("\n");
  return new TableCell({
    borders, width: { size: width, type: WidthType.DXA }, verticalAlign: VerticalAlign.CENTER,
    shading: o.fill ? { fill: o.fill, type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: lines.map((l) => new Paragraph({ alignment: o.center ? AlignmentType.CENTER : AlignmentType.LEFT,
      keepNext: !!o.keepNext, spacing: { after: 0, line: 252 }, children: runs(l, { size: 20, bold: !!o.bold }) })),
  });
}
function table(headers, rows, pct, o = {}) {
  const widths = pct.map((p) => Math.round((TEXT_W * p) / 100));
  widths[widths.length - 1] += TEXT_W - widths.reduce((a, b) => a + b, 0);
  const centerCols = o.center || [];
  return new Table({
    width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: widths,
    rows: [
      new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, widths[i], { bold: true, fill: "D9E2F3", center: true })) }),
      ...rows.map((r) => new TableRow({ cantSplit: true, children: r.map((v, i) => cell(v, widths[i], {
        center: centerCols.includes(i), fill: RATING_FILL[v] })) })),
    ],
  });
}
function image(file, widthPx, cap) {
  const buf = fs.readFileSync(path.join(DIR, file));
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 120, after: 0 },
      children: [new ImageRun({ type: "png", data: buf, transformation: { width: widthPx, height: Math.round((widthPx * h) / w) } })] }),
    caption("Figure", cap),
  ];
}
const shot = (f, cap, w = 560) => image(`screenshots/${f}.png`, w, cap);
const code = (lines) => lines.split("\n").map((l) => new Paragraph({ spacing: { after: 0, line: 240 },
  shading: { fill: "F2F2F2", type: ShadingType.CLEAR, color: "auto" },
  children: [new TextRun({ text: l || " ", font: "Consolas", size: 17 })] }));

// ---------------------------------------------------------------- data
const ASSETS = [
  ["A1", "User accounts and password hashes", "Prevent account takeover and disclosure of credential material.", "High"],
  ["A2", "Roles and permission assignments", "Prevent unauthorised change of access rights.", "High"],
  ["A3", "Session records and session cookies", "Ensure only valid, current sessions are honoured.", "High"],
  ["A4", "Stored user files (business documents)", "Preserve confidentiality and integrity of file content.", "High"],
  ["A5", "Encryption keys (master key and per-file keys)", "Protect keys from disclosure; loss of a key means loss of data.", "High"],
  ["A6", "Share-link tokens", "Restrict anonymous access to the intended file, time window and download count.", "Medium–High"],
  ["A7", "Audit log", "Preserve completeness, integrity and attribution of security events.", "High"],
  ["A8", "Security alerts and monitoring data", "Ensure suspicious activity is surfaced to administrators.", "Medium"],
  ["A9", "Vault service availability", "Authorised users can reach their files when needed.", "Medium"],
];

const THREATS = [
  ["T1", "Password guessing and credential stuffing", "External attacker, bots", "Spoofing", "T1110 Brute Force", "A1"],
  ["T2", "Theft or reuse of a session cookie", "Attacker on shared PC, XSS, malware", "Spoofing", "T1539 Steal Web Session Cookie", "A3"],
  ["T3", "Privilege escalation to administrative functions", "Malicious or curious user", "Elevation of privilege", "T1078 Valid Accounts", "A2"],
  ["T4", "Access to another user's file by changing its ID (IDOR) or by an insider administrator", "Authenticated user, insider", "Information disclosure", "T1530 Data from Cloud Storage", "A4"],
  ["T5", "Theft of the storage disk, backup or database file", "Insider, attacker with host access", "Information disclosure / Tampering", "T1005 Data from Local System", "A4, A5"],
  ["T6", "Upload of malicious or disguised files", "Authenticated user", "Tampering", "T1105 Ingress Tool Transfer", "A4, A9"],
  ["T7", "Compromise of the master encryption key", "Attacker with server access", "Information disclosure", "T1552 Unsecured Credentials", "A5"],
  ["T8", "Leaked, guessed or replayed share links", "Unintended recipient, attacker", "Information disclosure", "—", "A6"],
  ["T9", "Cross-site request forgery and clickjacking", "Malicious website", "Tampering", "T1189 Drive-by Compromise", "A2, A4"],
  ["T10", "Modification or deletion of audit records to hide activity", "Insider, attacker with DB access", "Repudiation", "T1070 Indicator Removal", "A7"],
  ["T11", "Bulk download (exfiltration) by a legitimate account", "Departing employee, hijacked account", "Information disclosure", "T1567 Exfiltration Over Web Service", "A4, A8"],
  ["T12", "Data loss or service disruption (disk failure, lockout abuse)", "Hardware fault, attacker", "Denial of service", "T1485 Data Destruction", "A9, A4"],
];

const RISKS = [
  ["R1", "Attacker guesses or stuffs passwords and takes over an account.", "A1", 3, 3],
  ["R2", "Stolen or old session cookie is replayed to act as the victim.", "A3", 2, 3],
  ["R3", "Normal user reaches admin functions or keeps privileges after a role change.", "A2", 2, 3],
  ["R4", "User or administrator reads files that belong to someone else.", "A4", 3, 3],
  ["R5", "Stolen disk or backup exposes file contents, or stored files are silently altered.", "A4, A5", 2, 3],
  ["R6", "Malicious or disguised file is stored and later served to users.", "A4, A9", 3, 2],
  ["R7", "Master key is disclosed, allowing decryption of every stored file.", "A5", 2, 3],
  ["R8", "Share link reaches an unintended person or is reused indefinitely.", "A6, A4", 3, 2],
  ["R9", "Victim's browser is tricked into performing actions (CSRF, clickjacking).", "A2, A4", 2, 2],
  ["R10", "Audit records are altered or deleted so misuse cannot be proven.", "A7", 2, 3],
  ["R11", "Legitimate account bulk-downloads data without being noticed.", "A4, A8", 2, 3],
  ["R12", "Files or database are lost or unavailable (no backup, lockout abuse).", "A9, A4", 2, 3],
];
const RESID = { R1: [1, 3], R2: [1, 3], R3: [1, 3], R4: [1, 3], R5: [1, 3], R6: [1, 2], R7: [2, 3], R8: [2, 2], R9: [1, 2], R10: [2, 2], R11: [2, 2], R12: [2, 3] };
const rating = (s) => (s >= 6 ? "High" : s >= 3 ? "Medium" : "Low");
const count = (fn, r) => RISKS.filter((x) => rating(fn(x)) === r).length;
const inh = (x) => x[3] * x[4], res = (x) => RESID[x[0]][0] * RESID[x[0]][1];
const INH_HIGH = count(inh, "High"), RES_HIGH = count(res, "High");
const WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve"];

const TESTS = [
  ["TC-01", "R1", "Register with six weak passwords (short, no digit, common, contains username).", "All rejected with HTTP 400; no account created."],
  ["TC-02", "R1", "Inspect the stored password field.", "Value is a salted scrypt hash, never plaintext."],
  ["TC-03", "R1", "Log in with an unknown username and with a wrong password.", "Identical 401 response and message (no user enumeration)."],
  ["TC-04", "R1", "Five wrong passwords, then the correct password.", "Account locked 15 min; correct password refused; high alert raised."],
  ["TC-05", "R1", "22 login attempts from one IP address.", "Attempts 21–22 return HTTP 429; rate-limit alert raised."],
  ["TC-06", "R2", "Copy session cookie, log out, replay the cookie from a second client.", "Replayed cookie is rejected (server-side revocation)."],
  ["TC-07", "R2", "Set session last activity to 16 minutes ago.", "Request redirected to login (idle timeout)."],
  ["TC-08", "R2", "Admin uses 'Revoke sessions' on a logged-in user.", "User's next request is rejected."],
  ["TC-09", "R2", "Change password on device 1 while device 2 is logged in.", "Device 1 stays signed in; device 2 is signed out."],
  ["TC-10", "R3", "Admin disables an account that has an active session.", "Session ends immediately; later login fails."],
  ["TC-11", "R3", "Normal user requests /admin/users, /audit and posts a role change.", "HTTP 403 each time; role unchanged; three privilege-probe alerts."],
  ["TC-12", "R3", "Auditor reads/verifies the audit log, then tries user management and alert resolution.", "Read/verify allowed; management actions return 403."],
  ["TC-13", "R4", "Administrator opens /files and a user's download URL.", "HTTP 403 (separation of duties)."],
  ["TC-14", "R4", "Bob requests download/delete of Alice's file ID.", "HTTP 404; file untouched; Alice can still download."],
  ["TC-15", "R3", "Admin changes a logged-in user's role.", "User's sessions revoked; re-login required."],
  ["TC-16", "R5", "Upload a PDF containing a marker string; read the stored blob.", "Marker absent from disk; random file name; download returns original."],
  ["TC-17", "R6", "Upload .exe, an executable renamed .pdf, a binary .txt, and a >5 MB file.", "All four rejected and logged; nothing stored."],
  ["TC-18", "R6", "Upload a file named ../../../evil.txt.", "Name sanitised to evil.txt; stored under random name inside the vault."],
  ["TC-19", "R5", "Flip one bit of a stored ciphertext, then download.", "Download refused (HTTP 500); integrity-failure alert raised."],
  ["TC-20", "R5", "Share a file, then delete it.", "Blob removed, wrapped key erased (crypto-shredding), share revoked."],
  ["TC-21", "R8", "Use share links past their download limit, after expiry, after revocation, and with a guessed token.", "Allowed downloads succeed; all other cases return 404."],
  ["TC-22", "R8", "Compare issued share token with database value.", "Only SHA-256 digest stored; token has 256 bits of entropy."],
  ["TC-23", "R9", "Post a delete request with a forged CSRF token.", "HTTP 400; file not deleted."],
  ["TC-24", "R9", "Inspect response headers and cookie flags.", "CSP frame-ancestors 'none', X-Frame-Options DENY, nosniff, HttpOnly, SameSite=Lax."],
  ["TC-25", "R10", "Upload a file and read its audit entry.", "Entry records actor, action, target, outcome, IP and UTC time."],
  ["TC-26", "R10", "Run UPDATE and DELETE on audit_log directly in SQLite.", "Both refused by database triggers ('append-only')."],
  ["TC-27", "R10", "Drop the trigger, change a failed login to 'success', run verification.", "Chain reported broken at the altered record; high alert raised."],
  ["TC-28", "R11", "Download the same file 10 times within 60 seconds.", "Download-burst (possible exfiltration) alert raised."],
];

function heatmap(items) {
  const lab = ["", "Impact 1 – Low", "Impact 2 – Medium", "Impact 3 – High"];
  const w = [2026, 2333, 2333, 2334];
  const rows = [new TableRow({ children: lab.map((t, i) => cell(t, w[i], { bold: true, fill: "D9E2F3", center: true, keepNext: true })) })];
  for (const L of [3, 2, 1]) {
    rows.push(new TableRow({ height: { value: 700, rule: "atLeast" }, children: [cell(`Likelihood ${L} – ${["", "Low", "Medium", "High"][L]}`, w[0], { bold: true, fill: "D9E2F3", center: true, keepNext: L > 1 }),
      ...[1, 2, 3].map((I) => cell(items.filter((x) => x[1] === L && x[2] === I).map((x) => x[0]).join(", ") || "–", w[I],
        { center: true, bold: true, keepNext: L > 1, fill: RATING_FILL[rating(L * I)] }))] }));
  }
  return new Table({ width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: w, rows });
}

// ---------------------------------------------------------------- front matter
const TEAM = [["AARAV", "[RA2411030010281]"], ["PARTH SINGH", "[RA2411030010256]"], ["ADITYA MAURYA", "[RA2411030010287]"]];
const GUIDE = "DR. V. HEMAMALINI", GUIDE_DESIG = "Associate Professor";

const front = [];
front.push(
  SP(), C("VAULTGUARD: SECURE FILE VAULT WITH", { run: { bold: true, size: 32 }, after: 0 }),
  C("RISK-DRIVEN SECURITY CONTROLS", { run: { bold: true, size: 32 }, after: 360 }),
  C("21CSC308T – Security Risk Management Principles", { run: { size: 26 }, after: 360 }),
  C("A PROJECT REPORT", { run: { bold: true, size: 26 }, after: 240 }),
  C("Submitted by", { run: { italics: true }, after: 120 }),
  ...TEAM.map(([n, r]) => C(`${n} ${r}`, { run: { bold: true }, after: 40 })),
  SP(), C("Under the Guidance of", { run: { italics: true }, after: 120 }),
  C(GUIDE, { run: { bold: true }, after: 40 }),
  C(`(${GUIDE_DESIG}, Department of Networking and Communications)`, { after: 300 }),
  C("in partial fulfillment of the requirements for the degree of", { after: 40 }),
  C("BACHELOR OF TECHNOLOGY", { run: { bold: true }, after: 40 }),
  C("in", { after: 40 }),
  C("COMPUTER SCIENCE ENGINEERING", { run: { bold: true }, after: 40 }),
  C("with specialization in CYBER SECURITY", { run: { bold: true }, after: 360 }),
  C("DEPARTMENT OF NETWORKING AND COMMUNICATIONS", { run: { bold: true }, after: 40 }),
  C("SCHOOL OF COMPUTING", { after: 40 }),
  C("COLLEGE OF ENGINEERING AND TECHNOLOGY", { after: 40 }),
  C("SRM INSTITUTE OF SCIENCE AND TECHNOLOGY", { run: { bold: true }, after: 40 }),
  C("KATTANKULATHUR – 603203", { after: 240 }),
  C("NOVEMBER 2026", { run: { bold: true } }),
);
front.push(BR(), SP(),
  C("SRM INSTITUTE OF SCIENCE AND TECHNOLOGY", { run: { bold: true, size: 28 }, after: 40 }),
  C("KATTANKULATHUR – 603203", { after: 480 }),
  C("BONAFIDE CERTIFICATE", { run: { bold: true, size: 28, underline: {} }, after: 480 }),
  new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { line: 480 }, children: runs(
    `Certified that this project report titled “**VAULTGUARD: SECURE FILE VAULT WITH RISK-DRIVEN SECURITY CONTROLS**” is the bonafide work of “**${TEAM.map(([n, r]) => `${n} ${r}`).join(", ")}**” who carried out the 21CSC308T – Security Risk Management Principles project work under my supervision.`) }),
  SP(), SP(), SP(), SP(), SP(),
  new Table({ width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: [4513, 4513],
    borders: { top: NOB, bottom: NOB, left: NOB, right: NOB, insideHorizontal: NOB, insideVertical: NOB },
    rows: [new TableRow({ children: [
      [GUIDE, GUIDE_DESIG.toUpperCase(), "Networking and Communications"], ["HEAD OF DEPARTMENT", "PROFESSOR AND HEAD", "Networking and Communications"],
    ].map((lines, i) => new TableCell({ width: { size: 4513, type: WidthType.DXA }, borders: { top: NOB, bottom: NOB, left: NOB, right: NOB },
      children: lines.map((l, j) => new Paragraph({ alignment: i ? AlignmentType.RIGHT : AlignmentType.LEFT, spacing: { after: 0 }, children: [new TextRun({ text: l, bold: j === 0 })] })) })) })] }),
);
front.push(BR(), C("ABSTRACT", { run: { bold: true, size: 28 }, after: 240 }),
  P("Organisations increasingly store sensitive documents such as financial reports, salary sheets and contracts in shared file repositories. A breach of such a repository can expose confidential information, allow silent modification of records, and leave no reliable trail for investigation. This project applies the principles of security risk management to the design, implementation and evaluation of **VaultGuard**, a secure file vault developed with Python Flask and SQLite."),
  P(`Unlike an evaluation that only reviews documentation, this project follows the complete risk management cycle. Nine information assets were identified and twelve threats were catalogued using the STRIDE model and mapped to MITRE ATT&CK techniques. Each threat was paired with a vulnerability to form twelve risk scenarios, which were scored on a three-level likelihood and impact scale to produce an inherent risk register. ${WORDS[INH_HIGH][0].toUpperCase() + WORDS[INH_HIGH].slice(1)} of the twelve risks were rated High before controls were applied.`),
  P("Controls were then selected in proportion to each risk and implemented in VaultGuard. They include scrypt password hashing with a password policy, account lockout and IP rate limiting, server-side sessions with idle and absolute timeouts, role-based access control with separation of duties, object-level ownership checks, envelope encryption with a separate key for every file, file-type and content validation, expiring and limited share links, CSRF protection and security headers, an append-only audit log protected by a SHA-256 hash chain, and automated security alerts."),
  P(`The effectiveness of the controls was verified with 28 automated test cases that reproduce realistic attacks, including brute force, session replay, privilege escalation, insecure direct object reference, disguised uploads, ciphertext tampering and audit-log tampering. All 28 tests passed. A residual risk assessment shows that the number of High risks fell from ${WORDS[INH_HIGH]} to ${WORDS[RES_HIGH]}: master-key storage on the application host and the absence of backups. Treatments for these and for the remaining Medium risks, such as multi-factor authentication and external anchoring of the audit chain, are recommended together with an implementation roadmap and monitoring measures.`),
);
front.push(BR(), C("TABLE OF CONTENTS", { run: { bold: true, size: 28 }, after: 240 }),
  new TableOfContents("Table of Contents", { hyperlink: true, headingStyleRange: "1-2" }));
front.push(BR(), C("LIST OF ABBREVIATIONS", { run: { bold: true, size: 28 }, after: 240 }),
  table(["Abbreviation", "Expansion"], [
    ["AES", "Advanced Encryption Standard"], ["ATT&CK", "Adversarial Tactics, Techniques and Common Knowledge (MITRE)"],
    ["CIA", "Confidentiality, Integrity and Availability"], ["CSP", "Content Security Policy"], ["CSRF", "Cross-Site Request Forgery"],
    ["DEK", "Data Encryption Key"], ["HMAC", "Hash-based Message Authentication Code"], ["IDOR", "Insecure Direct Object Reference"],
    ["KEK", "Key Encryption Key (master key)"], ["KMS", "Key Management Service"], ["MFA", "Multi-Factor Authentication"],
    ["NIST", "National Institute of Standards and Technology"], ["RBAC", "Role-Based Access Control"],
    ["SHA-256", "Secure Hash Algorithm, 256-bit"], ["SoD", "Separation of Duties"],
    ["STRIDE", "Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege"],
  ], [25, 75]));

const body = [];
const ch = (n, title) => { curCh = n; body.push(H1(`CHAPTER ${n}: ${title}`)); };

// ================================================================ CHAPTER 1
ch(1, "INTRODUCTION AND VAULTGUARD OVERVIEW");
body.push(H2("1.1 Introduction"),
  P("Information security risk management is the coordinated process of identifying what an organisation needs to protect, understanding what could harm it, estimating how likely and how serious that harm would be, and choosing controls that reduce the risk to an acceptable level. The process does not end when controls are chosen: controls must be verified, the remaining (residual) risk must be accepted or treated further, and the whole assessment must be repeated as the system and its threats change."),
  P("File storage systems are a natural subject for this process. They concentrate valuable information in one place, they are used by many people with different responsibilities, and they are often reachable over a network. A weakness in authentication, authorisation, encryption or logging can lead directly to disclosure of confidential documents, unauthorised modification of records, or loss of the evidence needed to investigate an incident."),
  P("This project designs, builds and evaluates **VaultGuard**, a secure file vault in which users can upload, download and share documents. Every security feature of VaultGuard was introduced as a response to a specific risk identified during the assessment, and every feature was tested to confirm that it actually reduces that risk. The report therefore documents both the risk assessment and the risk-driven engineering that followed it."),
  H2("1.2 Problem Statement"),
  P("Small organisations, college departments and project teams commonly share sensitive files through general-purpose tools such as shared drives, messaging applications or email attachments. These tools frequently store files in readable form, grant broad access to anyone with a link, provide little control over how long a shared file remains available, and keep limited or easily altered records of who accessed what."),
  P("Several specific concerns arise in such an environment:"),
  B("weak or reused passwords allow an attacker to take over accounts through repeated guessing;"),
  B("a user may be able to open another user's document simply by changing a number in a URL;"),
  B("administrators who manage accounts may also be able to read every document, creating an insider risk;"),
  B("a stolen disk or backup may expose every file because files are stored without encryption;"),
  B("a shared link may remain usable indefinitely and may be forwarded to unintended recipients;"),
  B("activity records may be edited or deleted, so that misuse cannot be proven afterwards."),
  P("The problem addressed by this project is to systematically identify and evaluate these risks for a file vault, to implement proportionate controls, and to demonstrate through practical testing which risks have been reduced and which residual risks still require treatment."),
  H2("1.3 Objectives"),
  P("The objectives of the project are:"),
  ...NL([
    "To identify the information assets of a secure file vault and their protection requirements.",
    "To build a threat catalogue using the STRIDE model and map threats to MITRE ATT&CK techniques.",
    "To pair threats with vulnerabilities and assess the resulting risks using a likelihood and impact model.",
    "To select and implement preventive, detective and corrective controls in proportion to each risk.",
    "To verify the effectiveness of each control through repeatable automated attack-based tests.",
    "To reassess residual risk and recommend further treatments, policies and monitoring measures.",
  ]),
  P("Throughout the project the three security objectives of confidentiality, integrity and availability (CIA) are used to describe the consequences of each risk."),
  H2("1.4 VaultGuard System Overview"),
  P("VaultGuard is a web application built with the Python Flask framework. Data about users, sessions, files, share links, audit events and alerts is stored in an SQLite relational database, and the uploaded files themselves are stored as encrypted blobs in a separate storage directory. The application is started with a single command, which makes it easy to demonstrate and to test."),
  P("The system supports three roles. A **user** can upload, download, delete and share their own files. An **administrator** manages accounts, roles, lockouts and sessions, and handles security alerts, but deliberately has no permission to read user files. An **auditor** has read-only access to the audit log and alerts and can verify the integrity of the audit log. Anonymous recipients can download a file only through a valid share link."),
  ...image("diagrams/architecture.png", 590, "VaultGuard architecture and request-processing layers"),
  P("Every request passes through a sequence of layered checks, shown in Figure 1.1. Security headers are added to every response; state-changing requests must carry a valid CSRF token; the session is validated against the server-side session table; the user's role must grant the permission required by the route; and for file operations the user must own the requested file. Only then does the request reach the business logic, which in turn records an audit event."),
  H2("1.5 Database Design"),
  P("VaultGuard uses six database tables. Table 1.1 summarises their purpose and the security-relevant design choices made in each."),
  caption("Table", "VaultGuard database tables"),
  table(["Table", "Purpose", "Security-relevant design"], [
    ["users", "Accounts, roles and status", "scrypt password hashes; failed-attempt counter and lock expiry; role restricted by CHECK constraint"],
    ["sessions", "Server-side login sessions", "Only a SHA-256 digest of the session id is stored; revocation flag; creation and last-activity times"],
    ["files", "Metadata of uploaded files", "Random storage name; per-file key stored only in wrapped (encrypted) form; SHA-256 of plaintext for integrity checking"],
    ["shares", "Share links", "Only a digest of the token is stored; expiry time, download limit, download count and revocation flag"],
    ["audit_log", "Record of security events", "Actor, action, target, outcome, IP, time; hash chain fields; triggers block UPDATE and DELETE"],
    ["alerts", "Security alerts", "Severity, type, detail and resolution status with the resolving administrator"],
  ], [16, 26, 58]),
  H2("1.6 Main Functionalities and Security Features"),
  P("Table 1.2 lists the main features of VaultGuard and links each to the security purpose it serves. The detailed design of each control is presented in Chapter 4."),
  caption("Table", "Main VaultGuard features and their security relevance"),
  table(["Feature", "Description", "Security relevance"], [
    ["Registration and login", "Password policy, scrypt hashing, generic error messages", "Resists password guessing and username enumeration"],
    ["Lockout and rate limiting", "Lock after 5 failures for 15 minutes; 20 attempts per IP per 10 minutes", "Slows brute-force and credential-stuffing attacks"],
    ["Session management", "Server-side sessions, 15-minute idle and 8-hour absolute timeout, revocation", "Limits the value of a stolen session cookie"],
    ["Role-based access control", "User, admin and auditor roles with explicit permission sets", "Enforces least privilege and separation of duties"],
    ["Encrypted storage", "Envelope encryption with a unique key per file", "Protects file confidentiality and detects tampering"],
    ["Upload validation", "Type allow-list, magic-byte check, size limit, filename sanitisation", "Blocks disguised executables and path traversal"],
    ["Share links", "Random tokens with expiry, download limit and revocation", "Controls anonymous access to individual files"],
    ["Audit log", "Append-only, hash-chained record of every security event", "Supports accountability and detects tampering"],
    ["Security alerts", "Lockouts, privilege probes, integrity failures, download bursts, chain breaks", "Brings suspicious activity to administrators' attention"],
  ], [22, 42, 36]),
);

// ================================================================ CHAPTER 2
ch(2, "SCOPE AND RISK ASSESSMENT METHODOLOGY");
body.push(H2("2.1 Scope of the Assessment"),
  P("The assessment covers the VaultGuard application, its database, its encrypted file store and its key handling. Four areas are examined:"),
  H3("2.1.1 Identity, Authentication and Sessions"),
  P("This area covers registration, password storage, login, lockout, rate limiting, session creation, timeouts, logout and administrative revocation. The central question is whether VaultGuard reliably prevents unauthorised sign-in and stops honouring a session as soon as it should no longer be valid."),
  H3("2.1.2 Authorisation and Privilege Management"),
  P("This area covers the role and permission model, protection of administrative functions, object-level access to files, and the effect of role or status changes on existing sessions. Particular attention is given to separation of duties between administrators, auditors and file owners."),
  H3("2.1.3 Data Protection and File Handling"),
  P("This area covers encryption at rest, key management, integrity checking, upload validation, deletion and controlled sharing through links."),
  H3("2.1.4 Accountability and Monitoring"),
  P("This area covers the completeness, attribution and tamper resistance of the audit log, and the alerting of suspicious behaviour."),
  P("The operating system, network infrastructure, TLS termination and physical security of the host are outside the scope. Where these influence a risk (for example, where the master key is stored), the dependency is recorded as an assumption."),
  H2("2.2 Information Asset Profile"),
  P("An information asset is any data or service that has value to the organisation and therefore requires protection. Table 2.1 lists the nine assets considered in this assessment, their protection requirements and their importance."),
  caption("Table", "Information asset profile"),
  table(["ID", "Information asset", "Protection requirement", "Importance"], ASSETS, [7, 30, 47, 16], { center: [0, 3] }),
  P("The encryption keys (A5) deserve special mention. They are small in size but they protect every file: disclosure of the master key would undo the protection given by encryption, while loss of the master key would make every file permanently unreadable. Keys therefore have both a confidentiality and an availability requirement."),
  H2("2.3 Risk Assessment Process"),
  P("The assessment follows the risk management process described in ISO/IEC 27005 and NIST SP 800-30, adapted to the size of an academic project. It consists of the following steps:"),
  ...NL([
    "**Context and asset identification** – understand the system and list the assets to be protected (Section 2.2).",
    "**Threat identification** – catalogue relevant threats using STRIDE and MITRE ATT&CK (Section 3.2).",
    "**Vulnerability identification** – identify weaknesses that would allow each threat to succeed in a design without controls (Section 3.3).",
    "**Risk analysis** – combine threats and vulnerabilities into risk scenarios and score likelihood and impact (Sections 3.4 to 3.6).",
    "**Risk evaluation** – rank the risks and decide which require treatment (Section 3.8).",
    "**Risk treatment** – select and implement controls (Chapter 4).",
    "**Verification** – test each control and record evidence (Chapter 5).",
    "**Residual risk assessment and monitoring** – re-score each risk with verified controls and plan further treatment (Chapters 5 and 6).",
  ]),
  P("Two risk registers are produced. The **inherent** register scores each risk as it would exist in a basic file-sharing application without the specific controls. The **residual** register scores each risk after the controls have been implemented and verified by testing. Comparing the two shows the value of the controls."),
  H2("2.4 Risk Assessment Criteria"),
  P("A three-level scale is used for both likelihood and impact so that ratings are simple, consistent and easy to justify. Table 2.2 defines each level."),
  caption("Table", "Likelihood and impact criteria"),
  table(["Score", "Likelihood", "Impact"], [
    ["1 – Low", "Unlikely: significant barriers exist, or the attacker needs rare access or skill.", "Limited: minor inconvenience or exposure of a small amount of non-sensitive data."],
    ["2 – Medium", "Possible: requires additional conditions such as prior access or user error.", "Moderate: exposure or modification of some sensitive data, or temporary loss of service."],
    ["3 – High", "Likely: readily achievable with common tools by an ordinary attacker.", "Serious: compromise of many accounts or files, loss of key material, or loss of evidence."],
  ], [16, 42, 42]),
  P("The risk score is the product of the two values: **Risk Score = Likelihood × Impact**. Table 2.3 converts the score into a rating and a required response."),
  caption("Table", "Risk rating scale"),
  table(["Score", "Rating", "Required response"], [
    ["1 – 2", "Low", "Accept with documented reason; monitor during periodic review."],
    ["3 – 4", "Medium", "Treat within a planned time frame; verify existing controls."],
    ["6 – 9", "High", "Treat as a priority before production use; verify controls by testing."],
  ], [16, 16, 68], { center: [0, 1] }),
  P("The numerical scores support comparison between risks; they are not statistical probabilities. When a risk affects more than one CIA objective, the impact reflects the most serious credible consequence."),
  H2("2.5 Control Classification and Verification Approach"),
  P("Controls are classified by function. **Preventive** controls stop an unwanted event, **detective** controls identify and record it, and **corrective** controls limit the damage and restore a safe state. A balanced design uses all three, so that an attack that defeats a preventive control is still detected and contained."),
  P("Every implemented control was verified with an automated test written with the pytest framework. Each test sets up a known state, performs the attack or misuse described in the risk scenario, and checks the system's response and side-effects (for example, that a role really was not changed, or that an alert really was raised). Tests are recorded with an identifier (TC-xx), the related risk, the procedure, the expected behaviour and the actual result. Because the tests are automated, they can be re-run after every change, which supports continuous reassessment."),
  H2("2.6 Assumptions and Limitations"),
  B("VaultGuard is deployed behind HTTPS in production; transport encryption is assumed but not tested here."),
  B("The host operating system and the database file are protected by normal file permissions; an attacker with full administrator access to the host is considered only for key and audit-log risks."),
  B("Likelihood and impact ratings are expert academic judgements, not measurements from a production environment."),
  B("Tests were executed in a local test environment with demonstration accounts and synthetic documents. No real personal data was used."),
  B("The assessment does not constitute a full penetration test or a formal compliance audit."),
);

// ================================================================ CHAPTER 3
ch(3, "RISK IDENTIFICATION AND ASSESSMENT");
body.push(H2("3.1 Introduction"),
  P("This chapter applies the methodology from Chapter 2 to identify and assess the risks that VaultGuard must address. A risk exists when a threat can exploit a vulnerability to harm an asset. The chapter first catalogues threats, then identifies vulnerabilities, combines them into risk scenarios, analyses their effect on confidentiality, integrity and availability, and finally scores and prioritises them in the inherent risk register."),
  H2("3.2 Threat Identification"),
  P("Threats were identified by walking through each asset and each STRIDE category: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service and Elevation of privilege. Each threat was then mapped to the closest MITRE ATT&CK technique so that it can be related to real-world adversary behaviour. Table 3.1 presents the resulting threat catalogue."),
  caption("Table", "VaultGuard threat catalogue"),
  table(["ID", "Threat", "Source", "STRIDE", "MITRE ATT&CK", "Assets"], THREATS, [6, 30, 18, 16, 19, 11], { center: [0, 5] }),
  P("The catalogue describes events that could happen. It does not state that VaultGuard is vulnerable to them; whether a threat becomes a risk depends on the vulnerabilities identified next."),
  H2("3.3 Identification of Vulnerabilities"),
  P("A vulnerability is a weakness in design, implementation or configuration that a threat can exploit. To assess inherent risk, the vulnerabilities typical of a basic file-sharing application (one that has login and upload but no deliberate security engineering) were identified:"),
  ...NL([
    "**V1 – Unlimited login attempts.** No lockout or rate limiting, and different error messages for unknown users and wrong passwords.",
    "**V2 – Client-side or stateless sessions.** Logging out deletes the cookie in the browser but the server cannot invalidate a copied cookie; no inactivity timeout.",
    "**V3 – Authorisation enforced only in the user interface.** Admin links are hidden from users, but the corresponding server routes do not check the role.",
    "**V4 – Missing object-level checks.** Files are fetched by numeric ID without verifying ownership; administrators have unrestricted access.",
    "**V5 – Plaintext storage.** Files are written to disk under their original names without encryption or integrity checks.",
    "**V6 – Trusting the file extension.** Uploaded files are accepted based only on their name.",
    "**V7 – Key stored with data.** If encryption is added, the key is kept in source code or next to the database.",
    "**V8 – Permanent public links.** Share links never expire, have no download limit and cannot be revoked.",
    "**V9 – No CSRF or framing protection.** State-changing forms accept requests from other websites, and pages can be embedded in frames.",
    "**V10 – Editable logs.** Activity is logged in an ordinary table that any process with database access can change.",
    "**V11 – No behaviour monitoring.** Large volumes of downloads by one account are not noticed.",
    "**V12 – Single copy of data.** No backup of the database, file store or master key.",
  ]),
  H2("3.4 Threat–Vulnerability Pair Analysis"),
  P("Pairing each threat with the vulnerability it exploits produces the twelve risk scenarios that form the basis of the risk register. Table 3.2 shows the pairs."),
  caption("Table", "Threat–vulnerability pairs"),
  table(["Risk", "Threat", "Vulnerability", "Risk scenario"], RISKS.map((r, i) => [r[0], THREATS[i][0], "V" + (i + 1), r[1]]), [9, 10, 14, 67], { center: [0, 1, 2] }),
  H2("3.5 Impact on Confidentiality, Integrity and Availability"),
  H3("3.5.1 Confidentiality"),
  P("Confidentiality is the most significant concern for a file vault. Risks R1, R2, R4, R5, R7, R8 and R11 can each lead to disclosure of stored documents. R7 is especially severe because disclosure of the master key would expose every file at once, and R4 includes the insider case where an administrator reads documents that are outside their responsibilities."),
  H3("3.5.2 Integrity"),
  P("Integrity is affected when files, access rights or records are changed without authorisation. R3 (privilege escalation) and R9 (CSRF) could change roles or delete files. R5 includes silent modification of stored files. R10 affects the integrity of the audit log itself, which would undermine every investigation that relies on it."),
  H3("3.5.3 Availability"),
  P("Availability is affected by R12, where a disk failure or corrupted database without backups would cause permanent loss of files, and where repeated failed logins could be used to lock legitimate users out. R6 can also affect availability if malicious uploads exhaust storage. Loss of the master key is an availability risk as well as a confidentiality one, because encrypted files cannot be recovered without it."),
  caption("Table", "CIA impact of each risk"),
  table(["Risk", "Confidentiality", "Integrity", "Availability"], [
    ["R1", "Yes – account data and files", "Yes – files changed by attacker", "–"], ["R2", "Yes", "Yes", "–"], ["R3", "Yes", "Yes – roles, accounts", "Yes – accounts disabled"],
    ["R4", "Yes – other users' files", "Yes – deletion", "–"], ["R5", "Yes – stolen media", "Yes – silent modification", "–"], ["R6", "–", "Yes – malicious content", "Yes – storage abuse"],
    ["R7", "Yes – all files", "–", "Yes – if key lost"], ["R8", "Yes – forwarded links", "–", "–"], ["R9", "–", "Yes – forged actions", "Yes – deleted files"],
    ["R10", "–", "Yes – evidence", "–"], ["R11", "Yes – bulk exfiltration", "–", "–"], ["R12", "–", "Yes – corruption", "Yes – data loss, lockout"],
  ], [12, 30, 30, 28], { center: [0] }),
  H2("3.6 Inherent Risk Register"),
  P("Table 3.4 records the inherent rating of each risk, that is, the rating in a design that has the vulnerabilities listed in Section 3.3."),
  caption("Table", "Inherent risk register (before controls)"),
  table(["ID", "Risk scenario", "Assets", "L", "I", "Score", "Rating"],
    RISKS.map(([id, s, a, l, i]) => [id, s, a, String(l), String(i), String(l * i), rating(l * i)]), [7, 49, 12, 6, 6, 9, 11], { center: [0, 2, 3, 4, 5, 6] }),
  H2("3.7 Justification of Risk Ratings"),
  P("**R1 – Credential attack (L3 × I3 = 9, High).** Automated password guessing and credential stuffing are among the most common attacks against web applications and require only freely available tools. Without lockout or rate limiting nothing slows the attacker. A successful login gives full access to the victim's files."),
  P("**R2 – Session replay (L2 × I3 = 6, High).** The attacker must first obtain a cookie, for example from a shared computer or through malware, which lowers likelihood. However, a stateless cookie that cannot be revoked gives the attacker the same access as the victim for as long as the cookie lasts."),
  P("**R3 – Privilege escalation (L2 × I3 = 6, High).** Exploitation requires an account and some knowledge of the URLs, but hidden links are easily discovered. Gaining administrative rights would allow the attacker to change roles, disable accounts and hide activity."),
  P("**R4 – Unauthorised file access (L3 × I3 = 9, High).** Changing a numeric ID in a URL is trivial and is one of the most frequently reported web vulnerabilities. Combined with unrestricted administrator access, any user's document could be read."),
  P("**R5 – Storage compromise (L2 × I3 = 6, High).** Physical or host-level access is needed, which lowers likelihood, but plaintext storage would expose every file and allow undetectable modification."),
  P("**R6 – Malicious upload (L3 × I2 = 6, High).** Renaming a file is trivial. The impact is moderate because VaultGuard does not execute uploaded files, but stored malware could be passed on to other users through share links."),
  P("**R7 – Master key compromise (L2 × I3 = 6, High).** Requires access to the server, but the consequence is the loss of confidentiality of the whole vault."),
  P("**R8 – Share-link abuse (L3 × I2 = 6, High).** Links are frequently forwarded or posted in chats; permanent links remain exploitable indefinitely. The impact is limited to the shared file."),
  P("**R9 – CSRF and clickjacking (L2 × I2 = 4, Medium).** The victim must be logged in and must visit a malicious page. Impact is moderate because the attacker can trigger actions but cannot read responses."),
  P("**R10 – Audit tampering (L2 × I3 = 6, High).** Requires database access, but successful tampering removes the evidence needed for every other investigation."),
  P("**R11 – Insider exfiltration (L2 × I3 = 6, High).** A legitimate user already has access, so preventive controls cannot fully stop them; the risk depends on detection."),
  P("**R12 – Data loss (L2 × I3 = 6, High).** Hardware faults and accidental deletion are realistic over the life of a system, and without backups the loss is permanent."),
  H2("3.8 Risk Evaluation and Prioritisation"),
  P(`Table 3.5 places each risk in a likelihood–impact heat map. ${WORDS[INH_HIGH][0].toUpperCase() + WORDS[INH_HIGH].slice(1)} of the twelve inherent risks fall in the High region, and two (R1 and R4) reach the maximum score of 9, so these were treated first.`),
  caption("Table", "Inherent risk heat map"),
  heatmap(RISKS.map((r) => [r[0], r[3], r[4]])),
  P("The evaluation concludes that none of the High inherent risks are acceptable for a system that stores confidential documents. Each requires treatment by reduction (mitigation) through the controls described in Chapter 4. Even the Medium risk R9 was treated because the controls involved are inexpensive and well established."),
);

// ================================================================ CHAPTER 4
ch(4, "RISK TREATMENT: DESIGN AND IMPLEMENTATION OF CONTROLS");
body.push(H2("4.1 Introduction"),
  P("This chapter describes the controls that were implemented in VaultGuard to treat the risks identified in Chapter 3. The chosen treatment for every inherent risk was **risk reduction**: each vulnerability was removed or mitigated by one or more controls. Controls were combined in layers (defence in depth), so that the failure of one control does not by itself lead to compromise."),
  H2("4.2 Control Classification"),
  caption("Table", "Implemented controls classified by function"),
  table(["Category", "Controls in VaultGuard", "Risks treated"], [
    ["Preventive", "Password policy; scrypt hashing; account lockout; IP rate limiting; server-side sessions with timeouts; RBAC with separation of duties; ownership checks; envelope encryption; upload validation; share-link limits; CSRF tokens; security headers; append-only audit triggers", "R1–R10"],
    ["Detective", "Hash-chained audit log with verification; SHA-256 integrity check on download; alerts for lockout, rate limiting, privilege probes, integrity failure, download bursts and audit tampering; admin dashboard", "R3, R5, R10, R11"],
    ["Corrective", "Session revocation on logout, password change, role change and account disable; admin unlock and revoke-sessions; share revocation; crypto-shredding on delete", "R2, R3, R5, R8"],
  ], [16, 66, 18]),
  H2("4.3 Authentication Controls (R1)"),
  H3("4.3.1 Password Policy and Hashing"),
  P("New passwords must contain at least ten characters including upper-case and lower-case letters, a digit and a special character. Passwords on a list of common choices and passwords that contain the username are refused. Passwords are stored as salted **scrypt** hashes. Scrypt is deliberately slow and memory-hard, which makes offline guessing of a stolen hash database expensive."),
  ...shot("02_register_weak", "Registration rejecting a weak password with the list of policy violations"),
  H3("4.3.2 Lockout, Rate Limiting and Enumeration Resistance"),
  P("After five consecutive failed logins an account is locked for fifteen minutes and a high-severity alert is raised. During the lock even the correct password is refused. Independently, each source IP address may make at most twenty login attempts in ten minutes; further attempts receive HTTP 429. This second limit addresses credential stuffing, in which one attacker tries one password against many accounts and would never trigger a per-account lockout."),
  P("The login form returns the same message, “Invalid username or password.”, for unknown users, wrong passwords, disabled accounts and locked accounts. When a username does not exist, the password is still checked against a dummy hash so that response time does not reveal whether the account exists."),
  ...shot("09_lockout_login", "Login refused for a locked account with a generic message"),
  H2("4.4 Session Management Controls (R2)"),
  P("VaultGuard keeps sessions on the server. At login a 256-bit random session identifier is generated and stored in a signed, HttpOnly, SameSite=Lax cookie; the database stores only the SHA-256 digest of the identifier. On every request the session record is looked up and rejected if it is revoked, if the account is disabled, if it has been idle for more than 15 minutes or if it is more than 8 hours old. The session is renewed at login to prevent session fixation."),
  P("Because sessions are stored on the server, VaultGuard can end them at any time. Sessions are revoked on logout, when an administrator uses “Revoke sessions”, when a user's role is changed, when an account is disabled, and (for all other devices) when a user changes their password."),
  H2("4.5 Authorisation Controls (R3, R4)"),
  H3("4.5.1 Role and Permission Model"),
  P("Permissions are defined on the server as named capabilities, and each route declares the capability it requires. A request without that capability receives HTTP 403, is written to the audit log and raises a “privilege-probe” alert. Table 4.2 shows the permission matrix."),
  caption("Table", "Role–permission matrix"),
  table(["Permission", "User", "Admin", "Auditor"], [
    ["file.upload / file.read_own / file.share", "Yes", "No", "No"], ["user.manage (role, status, unlock)", "No", "Yes", "No"],
    ["session.revoke", "No", "Yes", "No"], ["audit.read", "No", "Yes", "Yes"], ["audit.verify", "No", "Yes", "Yes"],
    ["alert.read", "No", "Yes", "Yes"], ["alert.resolve", "No", "Yes", "No"],
  ], [52, 16, 16, 16], { center: [1, 2, 3] }),
  P("Two design principles are visible in the matrix. **Least privilege**: each role holds only the permissions its job needs. **Separation of duties**: the administrator, who controls accounts, cannot read files and cannot alter the audit log, while the auditor, who reviews activity, cannot change anything. An administrator also cannot change their own role or status from the admin panel."),
  ...shot("08_forbidden", "A normal user receives HTTP 403 when requesting the user-management page"),
  H3("4.5.2 Object-Level Access Control"),
  P("Every file operation loads the file and compares its owner with the current user. If they differ, or the file does not exist, VaultGuard returns HTTP 404 rather than 403, so that an attacker cannot even learn which file IDs exist. This removes the insecure direct object reference (IDOR) vulnerability V4."),
  ...shot("11_admin_users", "User management: roles, status, lock state and live sessions"),
  H2("4.6 Data Protection Controls (R5, R7)"),
  H3("4.6.1 Envelope Encryption"),
  P("VaultGuard uses envelope encryption (Figure 4.5). For every upload a new random data encryption key (DEK) is generated and used to encrypt the file with Fernet, which combines AES-128 in CBC mode with an HMAC-SHA256 authentication tag. The DEK is itself encrypted (“wrapped”) with the master key, or key encryption key (KEK), and only the wrapped DEK is stored in the database. The encrypted file is written to disk under a random name."),
  ...image("diagrams/envelope.png", 590, "Envelope encryption of an uploaded file"),
  P("This design has three benefits. A stolen disk or database reveals only ciphertext and wrapped keys. Rotating the master key requires re-wrapping only the small DEKs, not re-encrypting every file. And deleting a file can erase its wrapped DEK (“crypto-shredding”), so that any copy of the ciphertext left in a backup becomes unreadable."),
  H3("4.6.2 Integrity Verification"),
  P("The SHA-256 hash of each plaintext file is stored at upload. On download the file is decrypted, which also verifies the Fernet authentication tag, and the hash is recomputed. If either check fails, the download is refused and a high-severity “integrity-failure” alert is raised."),
  H3("4.6.3 Master Key Handling"),
  P("The master key is read from the VAULTGUARD_MASTER_KEY environment variable, which in production would be supplied by a secrets manager. For local demonstration, if the variable is absent, VaultGuard generates a key file in its instance folder and displays a warning to administrators. This fallback places the key on the same host as the data and is therefore recorded as a residual risk (R7)."),
  H2("4.7 Upload Validation (R6)"),
  P("Uploaded files must have an extension on an allow-list (pdf, png, jpg, jpeg, docx, xlsx, pptx, txt, csv), must not exceed 5 MB, and must have content that matches the extension. Binary formats are checked by their leading “magic bytes” (for example %PDF- for PDF files and PK for Office files); text files must be valid UTF-8 without null bytes. Filenames are reduced to their base name and stripped of unsafe characters, and the stored name is random, which prevents path traversal. Downloads are always sent as attachments with a generic content type so that the browser never renders uploaded content inside VaultGuard."),
  ...shot("04_upload_rejected", "An executable renamed to invoice.pdf is rejected because its content does not match"),
  ...shot("03_files", "The file list showing encrypted files, their SHA-256 fingerprints and actions"),
  H2("4.8 Controlled Sharing (R8)"),
  P("A file owner can create a share link valid for 1 hour to 7 days and for 1 to 20 downloads. The link contains a 256-bit random token. Only the SHA-256 digest of the token is stored, so the link is shown to the owner exactly once and cannot be recovered from the database. Links can be revoked at any time and are automatically revoked when the file is deleted. Every attempt to use a link, successful or not, is audited with the reason for any refusal."),
  ...shot("05_share_created", "A share link shown once to the owner with its expiry and download limit"),
  ...shot("06_shares", "Managing share links: status, downloads used and revocation"),
  H2("4.9 Web Application Protections (R9)"),
  P("Every state-changing request must include a per-session CSRF token that is compared in constant time. Responses carry a Content-Security-Policy that allows resources only from VaultGuard itself and forbids framing, together with X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer and Cache-Control: no-store. The session cookie is HttpOnly and SameSite=Lax, and is marked Secure when HTTPS is enabled."),
  H2("4.10 Audit Logging and Monitoring (R10, R11)"),
  H3("4.10.1 Tamper-Evident Audit Log"),
  P("Every security-relevant event is recorded with the time (UTC), actor, action, target, outcome, source IP and detail. Two independent mechanisms protect these records. First, database triggers make the audit table append-only, so any UPDATE or DELETE is aborted. Second, each record contains the SHA-256 hash of its own content combined with the hash of the previous record, forming a hash chain. If a record is modified, removed or reordered by an attacker who has bypassed the triggers, the chain no longer verifies. Administrators and auditors can verify the whole chain from the Audit Log page."),
  ...shot("14_audit_verified", "Audit log with a successful hash-chain verification"),
  H3("4.10.2 Security Alerts"),
  P("VaultGuard raises alerts automatically for account lockouts, IP rate-limit breaches, privilege probes, privilege changes, file integrity failures, audit-chain breaks and download bursts (ten or more downloads by one account within sixty seconds, a possible sign of data exfiltration). Alerts are shown on the dashboard and can be resolved by administrators; the resolving administrator is recorded."),
  ...shot("12_alerts", "Security alerts raised by a lockout and a privilege probe"),
  ...shot("10_admin_dashboard", "Administrator dashboard summarising accounts, open alerts and failed logins"),
);

// ================================================================ CHAPTER 5
ch(5, "CONTROL VERIFICATION AND RESIDUAL RISK");
const total = (fn) => RISKS.reduce((s, x) => s + fn(x), 0);
body.push(H2("5.1 Introduction"),
  P("A control that exists in the code is not necessarily effective. This chapter presents the practical tests used to verify each control, the evidence collected, and the residual risk that remains once the controls are in place."),
  H2("5.2 Test Environment"),
  caption("Table", "Test environment"),
  table(["Item", "Details"], [
    ["Operating system", "Windows 11"], ["Runtime", "Python 3.12.10, Flask 3.1.3, cryptography 50.0.2"],
    ["Test framework", "pytest with the Flask test client"], ["Database", "SQLite, fresh temporary database per test"],
    ["Keys", "Fresh random master key per test supplied through the environment"],
    ["Accounts", "admin, auditor, alice (user), bob (user) – demonstration accounts only"],
    ["Data", "Synthetic documents; no real personal data"], ["Command", "python -m pytest -v"],
  ], [28, 72]),
  P("Each test runs in isolation with its own database and storage directory, so tests cannot influence each other and every result is reproducible."),
  H2("5.3 Test Cases and Results"),
  P("Table 5.2 lists all 28 test cases, the risk each one verifies, the procedure, the expected behaviour and the result. Every test performs the attack and then checks both the response and the state of the database or file store."),
  caption("Table", "Security test cases and results"),
  table(["ID", "Risk", "Procedure", "Expected behaviour", "Result"], TESTS.map((t) => [...t, "Pass"]), [9, 7, 39, 35, 10], { center: [0, 1, 4] }),
  P("**Result: 28 of 28 tests passed** (execution time approximately 44 seconds). The full output is saved in test_results.txt in the project folder."),
  H2("5.4 Evidence from the Running Application"),
  P("In addition to the automated tests, the main scenarios were reproduced manually in the running application to collect visual evidence. Figures in Chapter 4 show weak-password rejection, a locked-out login, the 403 response to a privilege probe and the resulting alerts. Figure 5.1 shows an administrator being refused access to user files, demonstrating separation of duties."),
  ...shot("13_admin_no_files", "An administrator is refused access to the file area"),
  H3("5.4.1 Audit-Log Tampering Demonstration"),
  P("To demonstrate the hash chain, an attacker with direct access to the database file was simulated. The append-only trigger was dropped and the first failed login of the account “bob” was changed from “failure” to “success” to conceal the brute-force attempt. When the auditor next ran verification, VaultGuard reported that the chain was broken at exactly the modified record and raised a high-severity alert (Figure 5.2)."),
  ...shot("15_audit_tampered", "Hash-chain verification detecting the modified audit record"),
  H2("5.5 Residual Risk Assessment"),
  P("With the controls implemented and verified, each risk was re-scored. Likelihood was reduced where a tested preventive control now blocks the attack; impact was reduced only where a control limits the consequence (for example, download limits on share links). Table 5.3 shows the residual risk register."),
  caption("Table", "Residual risk register (after verified controls)"),
  table(["ID", "Key controls", "Verified by", "L", "I", "Score", "Rating"], RISKS.map(([id]) => {
    const [l, i] = RESID[id];
    const ctrl = {
      R1: "Policy, scrypt, lockout, IP rate limit, generic errors", R2: "Server-side sessions, timeouts, revocation", R3: "Server-side RBAC, re-auth on role change",
      R4: "Ownership checks, admin has no file permission", R5: "Envelope encryption, SHA-256 check, crypto-shredding", R6: "Allow-list, magic bytes, size, sanitised names",
      R7: "Key outside DB, wrapped DEKs (key-file fallback remains)", R8: "Expiry, download limit, revocation, hashed token", R9: "CSRF token, CSP, framing and cookie flags",
      R10: "Append-only triggers, hash chain, verification alert", R11: "Download-burst alert, audit trail", R12: "Lockout auto-expiry, admin unlock (no backups)",
    }[id];
    const tc = { R1: "TC-01–05", R2: "TC-06–09", R3: "TC-10–12, 15", R4: "TC-13–14", R5: "TC-16, 19, 20", R6: "TC-17–18", R7: "Design review", R8: "TC-21–22", R9: "TC-23–24", R10: "TC-25–27", R11: "TC-28", R12: "TC-04, design review" }[id];
    return [id, ctrl, tc, String(l), String(i), String(l * i), rating(l * i)];
  }), [7, 41, 17, 6, 6, 10, 13], { center: [0, 3, 4, 5, 6] }),
  caption("Table", "Residual risk heat map"),
  heatmap(RISKS.map((r) => [r[0], ...RESID[r[0]]])),
  caption("Table", "Comparison of inherent and residual risk"),
  table(["Rating", "Inherent (before controls)", "Residual (after controls)"],
    ["High", "Medium", "Low"].map((r) => [r, String(count(inh, r)), String(count(res, r))]).concat([["Total score", String(total(inh)), String(total(res))]]),
    [30, 35, 35], { center: [0, 1, 2] }),
  P(`The total risk score across all twelve risks fell from ${total(inh)} to ${total(res)} (a ${Math.round((1 - total(res) / total(inh)) * 100)}% reduction), and the number of High risks fell from ${WORDS[INH_HIGH]} to ${WORDS[RES_HIGH]}.`),
  H2("5.6 Residual Weaknesses"),
  P("The following weaknesses remain and explain the residual ratings that are not Low. They are recorded honestly so that they can be treated or formally accepted:"),
  B("**R7 – Key storage (High).** In the demonstration configuration the master key is kept in a file on the same host as the encrypted data. An attacker with full host access could read both. There is also no key rotation procedure."),
  B("**R12 – No backups (High).** The database, the file store and the master key exist as single copies. Hardware failure or accidental deletion would cause permanent loss."),
  B("**R1 – No multi-factor authentication (Medium).** A password obtained by phishing would still allow login, although lockout and rate limiting make guessing impractical. The IP rate limiter is held in memory and resets when the application restarts."),
  B("**R8 – Bearer links (Medium).** Anyone who obtains a valid link can use it within its limits; links are not bound to a recipient identity or password."),
  B("**R10 – Chain re-computation (Medium).** An attacker with full database access could rewrite the whole chain consistently, because the chain is not anchored to any record held outside the database."),
  B("**R11 – Detection only (Medium).** A legitimate user can still download their own files; the control detects bursts but does not prevent slower exfiltration."),
  B("**R6 – No malware scanning (Low).** Content validation blocks disguised executables, but a malicious document of an allowed type (for example a PDF with an exploit) is not scanned."),
);

// ================================================================ CHAPTER 6
ch(6, "RISK TREATMENT PLAN AND CONCLUSION");
body.push(H2("6.1 Risk Treatment Options"),
  P("Four standard options exist for treating a risk: **reduce** it with controls, **transfer** it to another party (for example through insurance or a managed service), **avoid** it by removing the activity that causes it, or **accept** it with a documented reason. In Chapter 4 every inherent risk was reduced. This chapter selects options for the residual risks."),
  H2("6.2 Recommended Treatments for Residual Risks"),
  caption("Table", "Residual risk treatment plan"),
  table(["Risk", "Option", "Recommended treatment", "Target", "Priority"], [
    ["R7", "Reduce / Transfer", "Store the master key in a managed KMS or HSM (e.g. a cloud KMS or HashiCorp Vault); remove the key-file fallback in production; rotate the KEK yearly by re-wrapping DEKs.", "Medium (1×3)", "1"],
    ["R12", "Reduce", "Daily encrypted backups of database and file store following the 3-2-1 rule; separate escrowed backup of the master key; quarterly restore test.", "Medium (1×3)", "1"],
    ["R1", "Reduce", "Add TOTP-based MFA, mandatory for administrators and auditors; move rate limiting to a shared store such as Redis.", "Low (1×2)", "2"],
    ["R10", "Reduce", "Periodically publish the latest chain hash to write-once storage or an external log service; use HMAC with a key held outside the database.", "Low (1×2)", "2"],
    ["R8", "Reduce", "Optional link passwords or recipient email verification; default to the shortest expiry; notify the owner on each download.", "Low (1×2)", "3"],
    ["R11", "Reduce", "Daily and weekly download quotas; user-behaviour baselines; automatic temporary suspension on high-volume alerts.", "Low (1×2)", "3"],
    ["R6", "Reduce", "Scan uploads with an antivirus engine (e.g. ClamAV) before encryption; quarantine detections.", "Low (1×1)", "4"],
    ["R2–R5, R9", "Accept", "Residual ratings are Medium or Low with verified controls; retain controls and re-test on every release.", "Unchanged", "–"],
  ], [10, 13, 51, 14, 12], { center: [0, 3, 4] }),
  H2("6.3 Implementation Roadmap"),
  caption("Table", "Proposed implementation sequence"),
  table(["Phase", "Time frame", "Activities"], [
    ["Phase 1 – Critical", "Before production", "KMS-held master key and removal of key-file fallback (R7); automated encrypted backups and first restore test (R12); enforce HTTPS and Secure cookies."],
    ["Phase 2 – High value", "Within 1 month", "MFA for privileged roles, then all users (R1); external anchoring of audit chain (R10); Redis-backed rate limiting."],
    ["Phase 3 – Hardening", "Within 3 months", "Download quotas and behaviour baselines (R11); share-link passwords and owner notifications (R8); antivirus scanning (R6)."],
    ["Phase 4 – Assurance", "Every 6 months", "Re-run all security tests, perform an external penetration test, and repeat this risk assessment."],
  ], [22, 18, 60]),
  H2("6.4 Supporting Policies and Responsibilities"),
  P("Technical controls must be supported by policy and by clearly assigned responsibilities:"),
  B("**Access control policy** – roles are assigned on the principle of least privilege; administrative roles are approved by the department head and reviewed every quarter."),
  B("**Password and authentication policy** – the in-application password policy is mandatory; MFA is required for administrators and auditors once implemented."),
  B("**Key management policy** – the master key is generated, stored, rotated and escrowed only through the approved KMS; no person may copy it to removable media."),
  B("**Data sharing policy** – share links should use the shortest practical expiry and download limit, and must not be used for restricted documents."),
  B("**Logging and monitoring policy** – the audit chain is verified daily by the auditor; high-severity alerts are investigated within 24 hours."),
  B("**Incident response** – lockout, integrity-failure and audit-tamper alerts trigger the incident procedure: contain (revoke sessions, disable account), investigate using the audit log, recover, and record lessons learned."),
  caption("Table", "Roles and responsibilities"),
  table(["Role", "Responsibilities"], [
    ["System owner", "Accepts residual risk; approves the treatment plan and policies."],
    ["Administrator", "Manages accounts and roles; responds to alerts; performs backups and restore tests; cannot read user files."],
    ["Auditor", "Verifies the audit chain; reviews alerts and privileged actions; reports findings independently of administrators."],
    ["Users", "Protect their passwords; share files responsibly; report suspicious activity."],
    ["Developers", "Keep dependencies patched; run the security test suite on every change."],
  ], [22, 78]),
  H2("6.5 Security Monitoring Measures"),
  P("The following key risk indicators are recommended so that changes in risk are noticed between formal assessments:"),
  caption("Table", "Key risk indicators"),
  table(["Indicator", "Source", "Threshold for review"], [
    ["Failed logins per day", "Audit log (auth.login, failure)", "More than 3× the 30-day average"],
    ["Account lockouts", "Alerts (account-lockout)", "Any lockout of an admin or auditor account"],
    ["Privilege probes", "Alerts (privilege-probe)", "Any occurrence; repeated probes by one user"],
    ["Integrity failures", "Alerts (integrity-failure)", "Any occurrence – treat as an incident"],
    ["Audit chain status", "Daily verification", "Any break – treat as an incident"],
    ["Download bursts", "Alerts (download-burst)", "Any occurrence; review with the user's manager"],
    ["Open alerts older than 24 h", "Alerts table", "More than zero"],
  ], [32, 34, 34]),
  H2("6.6 Future Enhancements"),
  B("Integration with an organisational identity provider (single sign-on through SAML or OpenID Connect)."),
  B("Client-side (end-to-end) encryption so that even the server never sees plaintext."),
  B("Data classification labels with stricter sharing rules for confidential documents."),
  B("Export of audit events to a SIEM platform for correlation with other systems."),
  B("Automated dependency and static-analysis scanning in a continuous-integration pipeline."),
  H2("6.7 Conclusion"),
  P(`This project applied the security risk management cycle end to end to a secure file vault. Nine information assets and twelve threats were identified, mapped to STRIDE and MITRE ATT&CK, and combined with vulnerabilities into twelve risk scenarios. The inherent assessment rated ${WORDS[INH_HIGH]} of these risks as High, showing how exposed a basic file-sharing application would be.`),
  P("Controls were then designed in direct response to each risk and implemented in VaultGuard: strong authentication with lockout and rate limiting, server-side revocable sessions, server-enforced role-based access with separation of duties, object-level ownership checks, envelope encryption with integrity verification, strict upload validation, limited share links, CSRF and browser protections, and a tamper-evident audit log with automated alerting. Twenty-eight attack-based tests verified that every control behaves as intended, and all passed."),
  P(`The residual assessment shows that the number of High risks fell from ${WORDS[INH_HIGH]} to ${WORDS[RES_HIGH]}, and that the total risk score fell from ${total(inh)} to ${total(res)}. The project also demonstrates an important principle of risk management: risk is reduced, not eliminated. The remaining High risks — master-key storage and the absence of backups — were identified honestly, and a prioritised treatment plan, supporting policies and monitoring indicators have been proposed so that VaultGuard can be brought to an acceptable level of risk before use with real confidential data.`),
);

body.push(H1("REFERENCES"), ...NL([
  "ISO/IEC 27005:2022, Information security, cybersecurity and privacy protection — Guidance on managing information security risks.",
  "ISO/IEC 27001:2022, Information security management systems — Requirements (Annex A controls).",
  "NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments, National Institute of Standards and Technology, 2012.",
  "NIST SP 800-63B, Digital Identity Guidelines: Authentication and Lifecycle Management.",
  "NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management, 2020.",
  "MITRE ATT&CK Enterprise Matrix, The MITRE Corporation, https://attack.mitre.org.",
  "OWASP Top 10 – 2021, The Open Worldwide Application Security Project.",
  "OWASP Application Security Verification Standard (ASVS) 4.0.3.",
  "OWASP Cheat Sheet Series: Session Management, Authentication, File Upload, CSRF Prevention and Logging.",
  "A. Shostack, Threat Modeling: Designing for Security, Wiley, 2014 (STRIDE model).",
  "Pallets Projects, Flask Documentation, https://flask.palletsprojects.com.",
  "Python Cryptographic Authority, cryptography — Fernet specification, https://cryptography.io.",
]));

body.push(H1("APPENDIX A: SETUP AND KEY CODE EXCERPTS"),
  H2("A.1 Running VaultGuard"),
  ...code(`python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
flask --app vaultguard seed          # creates demo accounts
flask --app vaultguard run           # http://127.0.0.1:5000
python -m pytest -v                  # runs the 28 security tests`),
  SP(),
  P("Demonstration accounts (local demonstration only): admin, auditor, alice and bob. Their passwords are listed in vaultguard/seed.py."),
  H2("A.2 Permission Check and Role Model"),
  ...code(`PERMISSIONS = {
    "user":    {"file.upload", "file.read_own", "file.share"},
    "admin":   {"user.manage", "session.revoke", "audit.read", "audit.verify",
                "alert.read", "alert.resolve"},
    "auditor": {"audit.read", "audit.verify", "alert.read"},
}

def permission_required(perm):
    def deco(view):
        @wraps(view)
        @login_required
        def wrapped(*a, **kw):
            if perm not in PERMISSIONS[g.user["role"]]:
                audit("authz.deny", request.path, "denied", f"needs {perm}")
                alert("medium", "privilege-probe", ...)
                abort(403)
            return view(*a, **kw)
        return wrapped
    return deco`),
  H2("A.3 Envelope Encryption"),
  ...code(`class KeyManager:
    def __init__(self, master_key):
        self._kek = Fernet(master_key)
    def new_wrapped_key(self):
        dek = Fernet.generate_key()            # one key per file
        return dek, self._kek.encrypt(dek)     # store only the wrapped DEK
    def unwrap(self, wrapped):
        return self._kek.decrypt(wrapped)`),
  H2("A.4 Audit Hash Chain and Append-Only Trigger"),
  ...code(`def audit_hash(prev_hash, ts, actor, action, target, outcome, ip, detail):
    material = "|".join([prev_hash, ts, actor, action, target, outcome, ip, detail])
    return hashlib.sha256(material.encode()).hexdigest()

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;`),
  H2("A.5 Session Validation"),
  ...code(`if row is None:                         reason = "unknown session"
elif row["revoked"]:                    reason = "revoked session"
elif row["status"] != "active":         reason = "account disabled"
elif now - last_seen > 15 minutes:      reason = "idle timeout"
elif now - created_at > 8 hours:        reason = "absolute timeout"
if reason: revoke session, clear cookie, redirect to login`),
);

// ---------------------------------------------------------------- document
const numbering = { config: [
  { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
  ...Array.from({ length: 20 }, (_, i) => ({ reference: "num" + i, levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] })),
] };
const footer = () => new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], size: 22 })] })] });
const page = { size: { width: 11906, height: 16838 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } };

const doc = new Document({
  creator: "VaultGuard project team", title: "VaultGuard Project Report",
  features: { updateFields: true },
  numbering,
  styles: {
    default: { document: { run: { font: FONT, size: 24 }, paragraph: { spacing: { line: 360 } } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 30, bold: true, color: "000000" }, paragraph: { alignment: AlignmentType.CENTER, spacing: { before: 0, after: 360 }, keepNext: true, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 26, bold: true, color: "000000" }, paragraph: { spacing: { before: 280, after: 120 }, keepNext: true, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true, color: "000000" }, paragraph: { spacing: { before: 200, after: 100 }, keepNext: true, outlineLevel: 2 } },
    ],
  },
  sections: [
    { properties: { page: { ...page, pageNumbers: { start: 1, formatType: NumberFormat.LOWER_ROMAN } } }, footers: { default: footer() }, children: front },
    { properties: { page: { ...page, pageNumbers: { start: 1, formatType: NumberFormat.DECIMAL } } }, footers: { default: footer() }, children: body },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  const out = path.join(DIR, "VaultGuard_Project_Report.docx");
  fs.writeFileSync(out, buf);
  console.log("wrote", out, "| inherent High:", INH_HIGH, "residual High:", RES_HIGH);
});
