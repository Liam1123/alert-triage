// Alert Triage web app. Plain JS, no build step, no dependencies.
//
// Security rule for this file: the alert is attacker-controlled input, and so
// is everything the API echoes back from it. Every value goes into the page as
// text (textContent or text nodes), never as HTML. innerHTML, outerHTML,
// insertAdjacentHTML and document.write are not used anywhere. Links are only
// built from fixed, known origins.

"use strict";

const DEMO_SKIP_REASON = "demo: not looked up"; // Matches api/demo.py.

const SOURCE_NAMES = { virustotal: "VirusTotal", abuseipdb: "AbuseIPDB" };
const TYPE_NAMES = { sha256: "hash", ip: "IP", domain: "domain" };
const FIELD_LABELS = {
  hostname: "Host",
  user: "User",
  sha256: "SHA-256",
  file_path: "File path",
  command_line: "Command line",
  parent_process: "Parent process",
  remote_ip: "Remote IP",
  domain: "Domain",
};
// Mirrors SEVERITY_VERDICT in behavior.py: what each severity does to the verdict.
const SEVERITY_EFFECT = {
  high: "High severity, counts as malicious.",
  medium: "Medium severity, counts as suspicious.",
  low: "Low severity, context only.",
};
const SEVERITY_VERDICT_WORD = { high: "malicious", medium: "suspicious" };
const ORIGIN_WORDS = { cached: "Cached", live: "Live", skipped: "Skipped", demo: "Demo", error: "Not checked" };
// Reasons are listed worst first, so the ones that decided the verdict lead.
const TAG_RANK = { malicious: 5, suspicious: 4, unknown: 3, context: 2, clean: 2, demo: 1, skipped: 0 };

// Permalinks come from the API, but a poisoned cache could hold anything, so
// only these origins become links.
const SAFE_LINK_ORIGINS = ["https://www.virustotal.com", "https://www.abuseipdb.com"];

const $ = (id) => document.getElementById(id);

const input = $("alert-input");
const gutter = $("gutter");
const editor = $("editor");
const editorStatus = $("editor-status");
const triageButton = $("triage-button");
const cardPane = $("card-pane");
const liveCheckbox = $("live");

const samples = new Map();
let busy = false;
let retryTimer = null;

// ---- DOM helper -------------------------------------------------------------

// el("p", { class: "x", text: "hi", attrs: { id: "y" } }, child1, child2)
// Text is always set with textContent. Children may be nodes or strings
// (strings become text nodes). There is deliberately no way to pass HTML.
function el(tag, options = {}, ...children) {
  const node = document.createElement(tag);
  if (options.class) node.className = options.class;
  if (options.text !== undefined) node.textContent = String(options.text);
  for (const [name, value] of Object.entries(options.attrs || {})) {
    node.setAttribute(name, value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function tag(word, kind = word) {
  return el("span", { class: `tag tag--${kind}`, text: capitalize(word) });
}

function safeLink(url) {
  try {
    const parsed = new URL(url);
    return SAFE_LINK_ORIGINS.includes(parsed.origin) ? parsed.href : null;
  } catch {
    return null;
  }
}

function externalLink(href, text) {
  return el("a", { text, attrs: { href, target: "_blank", rel: "noopener noreferrer" } });
}

// ---- Editor -------------------------------------------------------------------

function updateGutter(errorLine = null) {
  const count = (input.value || input.placeholder).split("\n").length;
  const numbers = [];
  for (let line = 1; line <= count; line++) {
    numbers.push(el("span", { class: line === errorLine ? "is-error" : "", text: line }));
  }
  gutter.replaceChildren(...numbers);
  gutter.scrollTop = input.scrollTop;
}

function clearEditorStatus() {
  editorStatus.replaceChildren();
  editor.classList.remove("has-error");
  updateGutter();
}

function showEditorError(message, details = [], errorLine = null) {
  editorStatus.replaceChildren(el("p", { text: message }));
  if (details.length) editorStatus.append(el("ul", {}, ...details.map((d) => el("li", { text: d }))));
  editor.classList.add("has-error");
  updateGutter(errorLine);
}

// JSON.parse errors say where they went wrong in one of two ways, depending on
// the browser: "(line 3 column 5)" or "at position 45". Turn either into a line.
function locateJsonError(text, error) {
  const message = String(error.message);
  const lineColumn = message.match(/line (\d+) column (\d+)/);
  if (lineColumn) return { line: Number(lineColumn[1]), column: Number(lineColumn[2]) };

  const position = message.match(/position (\d+)/);
  if (position) {
    const before = text.slice(0, Number(position[1]));
    const lines = before.split("\n");
    return { line: lines.length, column: lines[lines.length - 1].length + 1, offset: before.length };
  }
  if (/end of (JSON|data) input|unexpected end/i.test(message)) {
    const lines = text.split("\n");
    return { line: lines.length, column: lines[lines.length - 1].length + 1 };
  }
  return null;
}

function offsetOf(text, line, column) {
  const lines = text.split("\n");
  let offset = 0;
  for (let i = 0; i < line - 1 && i < lines.length; i++) offset += lines[i].length + 1;
  return offset + column - 1;
}

function parseEditor() {
  const text = input.value;
  if (!text.trim()) {
    showEditorError("The editor is empty. Paste an alert as JSON, or load a sample.");
    return null;
  }
  let alert;
  try {
    alert = JSON.parse(text);
  } catch (error) {
    const where = locateJsonError(text, error);
    // Strip the browser's own location suffix; we say it more plainly below.
    const reason = String(error.message)
      .replace(/\s*\(line \d+ column \d+\)/, "")
      .replace(/ in JSON at position \d+/, "")
      .replace(/^JSON\.parse: /, "");
    if (where) {
      showEditorError(`Invalid JSON on line ${where.line}, column ${where.column}: ${reason}.`, [], where.line);
      const offset = where.offset ?? offsetOf(text, where.line, where.column);
      input.focus();
      input.setSelectionRange(offset, Math.min(offset + 1, text.length));
    } else {
      showEditorError(`Invalid JSON: ${reason}.`);
    }
    return null;
  }
  if (alert === null || typeof alert !== "object" || Array.isArray(alert)) {
    showEditorError("An alert must be a JSON object, like { \"hostname\": \"WS-01\" }.");
    return null;
  }
  return alert;
}

// ---- Talking to the API -------------------------------------------------------

async function runTriage() {
  if (busy || retryTimer) return;
  clearEditorStatus();
  const alert = parseEditor();
  if (!alert) return;

  setBusy(true);
  showLoading(alert);

  const live = liveCheckbox.checked;
  let response;
  try {
    response = await fetch(`/api/triage${live ? "?live=true" : ""}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(alert),
    });
  } catch {
    setBusy(false);
    showProblem("Can't reach the server",
      "The request never got an answer. Check that the server is still running, then try again.");
    return;
  }

  let body = null;
  try {
    body = await response.json();
  } catch {
    // Non-JSON error page (a proxy, a crash). Handled by status below.
  }
  setBusy(false);

  if (response.ok && body) {
    renderResult(body, live);
    return;
  }
  handleError(response, body);
}

function handleError(response, body) {
  const status = response.status;
  if (status === 429) {
    const seconds = Number(response.headers.get("Retry-After")) || Number(body?.retry_after) || 60;
    showRateLimited(seconds);
  } else if (status === 422 && Array.isArray(body?.errors)) {
    showEditorError("The alert doesn't match the expected fields:",
      body.errors.map((e) => `${e.field}: ${e.message}`));
    restoreCard();
  } else if (status === 413) {
    showEditorError("This alert is larger than the server accepts (32 KB). Trim the long fields and try again.");
    restoreCard();
  } else if (status === 400) {
    showEditorError("The server couldn't read this as JSON.");
    restoreCard();
  } else if (status === 403) {
    showProblem("Live lookups are off on this server",
      "Untick Live lookups to triage in demo mode. To allow live lookups, restart the server with ALLOW_LIVE=1.");
  } else {
    showProblem("The server couldn't triage this alert",
      "Something went wrong on the server. Your alert is still in the editor, so you can try again. " +
      "If it keeps happening, the server log has the details.");
  }
}

function setBusy(value) {
  busy = value;
  triageButton.disabled = value;
  triageButton.textContent = value ? "Triaging…" : "Triage alert";
  cardPane.setAttribute("aria-busy", String(value));
}

// ---- Card states --------------------------------------------------------------

let lastCard = null; // What the card showed before a loading state, to restore on input errors.

function setCard(node) {
  cardPane.replaceChildren(node);
}

function showLoading(alert) {
  lastCard = cardPane.querySelector("article.card") || cardPane.firstElementChild;
  const host = typeof alert.hostname === "string" ? alert.hostname : "this alert";
  setCard(el("div", { class: "state is-loading" },
    el("h2", { class: "state-title", text: "Triaging…", attrs: { id: "card-title" } }),
    el("p", { text: `Running behavior rules and intel lookups for ${host}.` }),
  ));
}

function restoreCard() {
  if (lastCard) setCard(lastCard);
}

// A problem notice goes above the last triage card, so the analyst keeps
// their result while they wait or retry.
function showNotice(notice) {
  const previous = lastCard && lastCard.matches("article.card") ? lastCard : null;
  if (previous) previous.querySelector("#card-title")?.removeAttribute("id");
  cardPane.replaceChildren(notice);
  if (previous) cardPane.append(previous);
  cardPane.scrollTop = 0;
}

function showProblem(title, message) {
  showNotice(el("div", { class: "state is-error", attrs: { role: "alert" } },
    el("h2", { class: "state-title", text: title, attrs: { id: "card-title" } }),
    el("p", { text: message }),
  ));
}

function showRateLimited(seconds) {
  const countdown = el("strong", { text: `${seconds} s` });
  showNotice(el("div", { class: "state is-error", attrs: { role: "alert" } },
    el("h2", { class: "state-title", text: "Too many triages for now", attrs: { id: "card-title" } }),
    el("p", { text: "This server allows 10 triages a minute per client, and 2 a minute with live lookups. " +
      "Your alert is still in the editor." }),
    el("p", {}, "You can triage again in ", countdown, "."),
  ));

  let remaining = seconds;
  triageButton.disabled = true;
  triageButton.classList.add("is-waiting");
  triageButton.textContent = `Wait ${remaining} s`;
  retryTimer = setInterval(() => {
    remaining -= 1;
    if (remaining > 0) {
      countdown.textContent = `${remaining} s`;
      triageButton.textContent = `Wait ${remaining} s`;
      return;
    }
    clearInterval(retryTimer);
    retryTimer = null;
    countdown.textContent = "now";
    triageButton.disabled = false;
    triageButton.classList.remove("is-waiting");
    triageButton.textContent = "Triage alert";
  }, 1000);
}

// ---- The triage card ----------------------------------------------------------

function renderResult(result, live) {
  const card = el("article", { class: "card", attrs: { "aria-labelledby": "card-title" } },
    verdictBand(result),
    reasonsSection(result),
    findingsSection(result.behavior_findings),
    decodedSection(result.decoded_command),
    tacticsSection(result.tactics),
    intelSection(result.enrichments),
    alertSection(result.alert),
    el("p", { class: "card-foot", text: live
      ? "Live mode: indicators not in the cache were looked up just now."
      : "Demo mode: intel comes from the local cache only. Nothing was sent to any API." }),
  );
  setCard(card);
  cardPane.scrollTop = 0;
}

function verdictBand(result) {
  const verdict = result.verdict;
  const alert = result.alert;
  const findings = result.behavior_findings.length;
  const checked = result.enrichments.filter((e) => originOf(e) === "live" || originOf(e) === "cached").length;

  const subject = alert.user ? `${alert.hostname}, user ${alert.user}` : alert.hostname;
  const basis = `${plural(findings, "behavior finding")}, ` +
    `${checked} of ${plural(result.enrichments.length, "intel lookup")} with data.`;

  return el("header", { class: `verdict verdict--${verdict}` },
    el("p", { class: "verdict-label", text: "Overall verdict" }),
    el("h2", { class: "verdict-word", text: capitalize(verdict), attrs: { id: "card-title" } }),
    el("p", { class: "verdict-subject", text: subject }),
    el("p", { class: "verdict-basis", text: basis }),
  );
}

function reasonsSection(result) {
  const rows = [];
  const seen = new Set();
  const add = (word, kind, ...parts) => {
    const key = kind + parts.map((p) => (typeof p === "string" ? p : p.textContent)).join("");
    if (seen.has(key)) return; // Two sources skipping the same IP say the same thing.
    seen.add(key);
    rows.push({ kind, node: el("li", {}, tag(word, kind), el("span", { class: "sentence" }, ...parts)) });
  };

  for (const f of result.behavior_findings) {
    const word = f.severity === "low" ? "context" : SEVERITY_VERDICT_WORD[f.severity];
    add(word, word, `${f.rule_name}, found in the ${whereFound(f)}. ${SEVERITY_EFFECT[f.severity]}`);
  }
  for (const e of result.enrichments) {
    const [word, kind, parts] = enrichmentSentence(e);
    add(word, kind, ...parts);
  }
  // Notes from the core that aren't tied to one finding or lookup (escalation,
  // "no rules matched", "nothing to analyze"), shown as written.
  for (const reason of result.reasons) {
    if (/escalate/.test(reason)) add(result.verdict, result.verdict, sentence(reason.replace(/^behavior: /, "")));
    else if (/no behavior rules matched/.test(reason)) add("clean", "clean", "No behavior rule matched the process details.");
    else if (/nothing to analyze/.test(reason)) add("unknown", "unknown", sentence(reason));
  }

  rows.sort((a, b) => TAG_RANK[b.kind] - TAG_RANK[a.kind]);
  return section("Why", el("ul", { class: "reasons" }, ...rows.map((r) => r.node)));
}

function enrichmentSentence(e) {
  const source = SOURCE_NAMES[e.source] || e.source;
  const type = TYPE_NAMES[e.indicator_type] || e.indicator_type;
  const indicator = el("code", { text: shortIndicator(e) });
  const origin = originOf(e);

  if (origin === "demo") {
    return ["demo", "demo", [`Not looked up in ${source} (demo mode): ${type} `, indicator, "."]];
  }
  if (origin === "skipped") {
    return ["skipped", "skipped", [`Not looked up: ${type} `, indicator, ` is a ${e.skip_reason}.`]];
  }
  if (origin === "error") {
    return ["unknown", "unknown", [`${source} could not check ${type} `, indicator, `: ${sentence(e.error)}`]];
  }
  const verdict = e.verdict || "unknown";
  if (e.score !== null && e.score !== undefined) {
    return [verdict, verdict, [`${source} gives ${type} `, indicator,
      ` an abuse confidence of ${e.score}/100 from ${plural(e.report_count, "report")}.`]];
  }
  return [verdict, verdict, [`${e.malicious_count} of ${e.total_engines} ${source} engines flag ${type} `, indicator, "."]];
}

function findingsSection(findings) {
  if (!findings.length) return null;
  const items = findings.map((f) => el("li", { class: "finding" },
    el("div", { class: "finding-head" },
      tag(f.severity),
      el("h4", { class: "finding-name", text: f.rule_name }),
    ),
    el("p", { class: "finding-where", text: `Matched in the ${whereFound(f)}` }),
    el("ul", { class: "techniques" }, ...f.techniques.map((t) => el("li", {},
      techniqueLink(t.id),
      el("span", { text: t.name }),
    ))),
    evidence(f.evidence, f.highlights || []),
  ));
  return section("Behavior findings", el("ul", { class: "findings" }, ...items));
}

function techniqueLink(id) {
  // Only real technique IDs (T1059 or T1059.001) become links to MITRE.
  if (!/^T\d{4}(\.\d{3})?$/.test(id)) return el("code", { text: id });
  return externalLink(`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`, id);
}

// The evidence string with the matched ranges wrapped in <mark>. Each piece is
// a text node, so markup in the evidence stays visible text.
function evidence(text, highlights) {
  const block = el("p", { class: "evidence" });
  const ranges = highlights
    .map(([start, end]) => [Math.max(0, start), Math.min(text.length, end)])
    .filter(([start, end]) => end > start)
    .sort((a, b) => a[0] - b[0]);

  let position = 0;
  for (const [start, end] of ranges) {
    if (end <= position) continue; // Overlaps a range already marked.
    const from = Math.max(start, position);
    if (from > position) block.append(document.createTextNode(text.slice(position, from)));
    block.append(el("mark", { text: text.slice(from, end) }));
    position = end;
  }
  if (position < text.length) block.append(document.createTextNode(text.slice(position)));
  return block;
}

function decodedSection(decoded) {
  if (!decoded) return null;
  return section("Decoded PowerShell command",
    el("pre", { class: "code-block" }, el("code", { text: decoded })),
    el("p", { class: "code-note", text: "Decoded from the -EncodedCommand argument. Never executed." }),
  );
}

function tacticsSection(tactics) {
  if (!tactics.length) return null;
  return section("ATT&CK tactics, in kill-chain order",
    el("ol", { class: "tactics" }, ...tactics.map((t) => el("li", {}, el("span", { class: "tactic-name", text: t })))),
  );
}

function intelSection(enrichments) {
  if (!enrichments.length) {
    return section("Threat intel", el("p", { class: "muted", text: "This alert has no hash, IP or domain to look up." }));
  }
  const head = el("thead", {}, el("tr", {}, ...["Source", "Indicator", "Verdict", "Result", "Data", "Link"]
    .map((h) => el("th", { text: h, attrs: { scope: "col" } }))));

  const rows = enrichments.map((e) => {
    const origin = originOf(e);
    const counts = origin === "demo" || origin === "skipped" || origin === "error";
    const href = e.permalink ? safeLink(e.permalink) : null;
    return el("tr", {},
      cell("Source", SOURCE_NAMES[e.source] || e.source),
      indicatorCell(e),
      cell("Verdict", null, "verdict-cell", counts && origin !== "error" ? el("span", { class: "muted", text: "Not counted" }) : tag(e.verdict || "unknown")),
      cell("Result", resultText(e)),
      cell("Data", ORIGIN_WORDS[origin], "origin"),
      cell("Link", null, href ? "" : "is-empty",
        href ? externalLink(href, `Open in ${SOURCE_NAMES[e.source] || e.source}`) : el("span", { class: "muted", text: "None" })),
    );
  });
  return section("Threat intel", el("table", { class: "intel" }, head, el("tbody", {}, ...rows)));
}

// Hashes are shortened so the column stays narrow; the full value is in the
// tooltip and in the alert fields below.
function indicatorCell(e) {
  const td = cell("Indicator", `${TYPE_NAMES[e.indicator_type] || e.indicator_type} ${shortIndicator(e)}`, "indicator");
  if (shortIndicator(e) !== e.indicator) td.setAttribute("title", e.indicator);
  return td;
}

function cell(label, text, className = "", child = null) {
  const td = el("td", { class: className, attrs: { "data-label": label } });
  if (text !== null) td.textContent = text;
  if (child) td.append(child);
  return td;
}

function resultText(e) {
  const origin = originOf(e);
  if (origin === "demo") return "Not looked up in demo mode";
  if (origin === "skipped") return capitalize(e.skip_reason);
  if (origin === "error") return e.error;
  if (e.score !== null && e.score !== undefined) return `Score ${e.score}/100, ${plural(e.report_count, "report")}`;
  return `${e.malicious_count} / ${e.total_engines} engines`;
}

function alertSection(alert) {
  const rows = [];
  for (const [field, label] of Object.entries(FIELD_LABELS)) {
    const value = alert[field];
    if (value === null || value === undefined || value === "") continue;
    rows.push(el("dt", { text: label }), el("dd", { text: value }));
  }
  return section("Alert fields", el("dl", { class: "fields" }, ...rows));
}

function section(title, ...content) {
  return el("section", { class: "card-section" }, el("h3", { class: "section-title", text: title }), ...content);
}

// ---- Small helpers ------------------------------------------------------------

// Where an enrichment's data came from. Same idea as _origin() in cli.py, plus demo.
function originOf(e) {
  if (e.cached) return "cached";
  if (e.skip_reason === DEMO_SKIP_REASON) return "demo";
  if (e.skip_reason) return "skipped";
  if (e.error) return "error";
  return "live";
}

function whereFound(f) {
  if (f.from_decoded) return "decoded PowerShell command";
  return f.matched_field.split(", ").map((name) => name.replace("_", " ")).join(" and ");
}

function shortIndicator(e) {
  const value = e.indicator;
  return e.indicator_type === "sha256" && value.length > 20 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function capitalize(text) {
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}

function sentence(text) {
  const trimmed = capitalize(String(text).trim());
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

// ---- Samples, health, keyboard -----------------------------------------------

function loadSample(name) {
  const alert = samples.get(name);
  if (!alert) return;
  input.value = JSON.stringify(alert, null, 2);
  input.scrollTop = 0;
  clearEditorStatus();
}

function sampleLabel(name) {
  const words = name.replace(/_/g, " ").replace(/powershell/i, "PowerShell").replace(/^xss/i, "XSS");
  return capitalize(words);
}

async function loadSamples() {
  let list = [];
  try {
    const response = await fetch("/api/samples");
    if (response.ok) list = await response.json();
  } catch {
    return; // The menu just stays empty; pasting still works.
  }
  const select = $("samples");
  for (const item of list) {
    samples.set(item.name, item.alert);
    select.append(el("option", { text: sampleLabel(item.name), attrs: { value: item.name } }));
  }

  const tryButtons = $("try-buttons");
  for (const name of ["encoded_powershell", "multi_indicator", "office_macro", "benign_admin"]) {
    if (!samples.has(name) || !tryButtons) continue;
    const button = el("button", { class: "secondary", text: sampleLabel(name), attrs: { type: "button" } });
    button.addEventListener("click", () => { loadSample(name); runTriage(); });
    tryButtons.append(button);
  }
}

async function loadHealth() {
  try {
    const response = await fetch("/api/health");
    if (!response.ok) return;
    const health = await response.json();
    if (health.live_allowed) {
      liveCheckbox.disabled = false;
      $("live-off").remove();
    } else {
      $("live-toggle").classList.add("is-disabled");
    }
  } catch {
    // Stay in demo mode with the toggle disabled.
  }
}

function updateMode() {
  const live = liveCheckbox.checked;
  $("mode").classList.toggle("is-live", live);
  $("mode-name").textContent = live ? "Live mode" : "Demo mode";
  $("mode-note").textContent = live
    ? "Indicators not in the cache are sent to VirusTotal and AbuseIPDB. Uses API quota."
    : "Intel comes from the local cache only. No API calls.";
}

function init() {
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  $("mod-key").textContent = isMac ? "⌘" : "Ctrl";

  input.addEventListener("input", () => {
    if (editor.classList.contains("has-error")) clearEditorStatus();
    else updateGutter();
  });
  input.addEventListener("scroll", () => { gutter.scrollTop = input.scrollTop; });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      runTriage();
    }
  });

  triageButton.addEventListener("click", runTriage);
  $("samples").addEventListener("change", (event) => loadSample(event.target.value));
  liveCheckbox.addEventListener("change", updateMode);

  updateGutter();
  loadSamples();
  loadHealth();
}

init();
