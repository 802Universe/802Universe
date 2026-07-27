/* ============================================================================
   Packet Analyzer · 802 Universe
   Serverless pcap/pcapng dissection in the browser, powered by the real
   Wireshark engine compiled to WebAssembly (Wiregasm).

   Nothing is uploaded: the file is read locally, written into the WASM
   virtual filesystem, and dissected client-side.

   Engine is loaded on demand from jsDelivr the first time a capture is opened
   (~20 MB gzipped, then browser-cached). To vendor it locally instead, see
   README.md and point CDN below at "./vendor".
   ========================================================================== */

const WG_VER = "1.9.1";
const CDN    = `https://cdn.jsdelivr.net/npm/@goodtools/wiregasm@${WG_VER}/dist`;

/* -------------------------------------------------------------------- utils */
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const vec = (v) => { const a = []; const n = v.size(); for (let i = 0; i < n; i++) a.push(v.get(i)); return a; };

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function fmtBytes(n) {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 2 : 1)) + " " + u[i];
}
function fmtDur(s) {
  if (s == null) return "—";
  if (s < 1) return (s * 1000).toFixed(0) + " ms";
  if (s < 60) return s.toFixed(3) + " s";
  const m = Math.floor(s / 60), r = s % 60;
  return `${m}m ${r.toFixed(1)}s`;
}
function fmtTime(epoch) {
  if (!epoch) return "—";
  try { return new Date(epoch * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC"); }
  catch { return String(epoch); }
}
function isDefaultColor(bg, fg) {
  // white bg + black fg == no coloring rule; skip so themed rows stay clean
  return (bg >>> 0) === 0xffffff && (fg >>> 0) === 0x000000 || (bg === 0 && fg === 0);
}
const colorCss = (n) => { n = n >>> 0; return `rgb(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255})`; };

/* ---------------------------------------------------------------- app state */
const state = {
  wg: null,             // Wiregasm instance
  cols: [],             // column headers
  protoIdx: -1,
  filter: "",
  offset: 0,
  matched: 0,
  page: 500,
  selFrame: null,
  dsBytes: [],          // current frame's data sources as Uint8Array[]
  shownDs: -1,
};

/* ----------------------------------------------------------- engine loader */
function loadScript(src) {
  return new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = src; s.async = true;
    s.onload = () => res();
    s.onerror = () => rej(new Error("Failed to fetch the analysis engine. Check your connection and retry."));
    document.head.appendChild(s);
  });
}

async function ensureEngine() {
  if (state.wg) return state.wg;
  setStage("Loading the analysis engine…", "First time only · ~20 MB · cached by your browser afterwards");
  // ESM wrapper (small) — imported on demand so the page shell works even if the CDN is briefly unreachable
  const { Wiregasm } = await import(/* @vite-ignore */ `${CDN}/module.js`);
  // The emscripten glue is a UMD module; loading it as a classic script exposes window.loadWiregasm
  await loadScript(`${CDN}/wiregasm.js`);
  const loader = window.loadWiregasm;
  if (typeof loader !== "function") throw new Error("Engine loaded but no entry point was found.");
  const wg = new Wiregasm();
  await wg.init(loader, {
    locateFile: (p) => `${CDN}/${p}`,   // resolves wiregasm.wasm + wiregasm.data on the CDN
    print: () => {}, printErr: () => {},
  });
  state.wg = wg;
  state.cols = wg.columns();
  state.protoIdx = state.cols.indexOf("Protocol");
  return wg;
}

/* --------------------------------------------------------------- file flow */
async function handleFile(file) {
  if (!file) return;
  showErr(false);
  showProgress(true);
  try {
    setStage(`Reading ${file.name}…`, "");
    const buf = await file.arrayBuffer();

    await ensureEngine();

    setStage(`Dissecting ${file.name}…`, "");
    const bytes = new Uint8Array(buf);
    const res = state.wg.load(file.name, bytes);
    if (!res || res.code !== 0) {
      const msg = (res && res.error) ? res.error : "The engine could not read this file.";
      throw new FriendlyError(
        "That doesn't look like a capture this engine can read.",
        msg + " Supported formats are .pcap, .pcapng and .cap — make sure you're opening the capture itself, not a report or other document.");
    }
    const s = res.summary || {};
    if (!s.packet_count) {
      throw new FriendlyError("No packets found.", "The file opened but contains zero packets.");
    }

    onLoaded(file, s);
  } catch (e) {
    showProgress(false);
    if (e instanceof FriendlyError) showErr(true, e.title, e.detail);
    else showErr(true, "Something went wrong.", e && e.message ? e.message : String(e));
    console.error(e);
  }
}

class FriendlyError { constructor(title, detail){ this.title = title; this.detail = detail; } }

function onLoaded(file, summary) {
  // filechip + controls
  $("#fileChipName").textContent = file.name;
  $("#fileChip").classList.add("show");
  $("#newBtn").classList.remove("hidden");

  buildThead();
  renderOverview(file, summary);

  // reset packet list & selection
  state.filter = ""; $("#filterInput").value = "";
  clearDetail();
  loadPage(true);

  // switch screens
  showProgress(false);
  $("#dropScreen").style.display = "none";
  $("#analysis").classList.add("show");
  switchView("overview");
}

function reset() {
  state.filter = ""; state.offset = 0; state.matched = 0; state.selFrame = null;
  $("#analysis").classList.remove("show");
  $("#dropScreen").style.display = "";
  $("#fileChip").classList.remove("show");
  $("#newBtn").classList.add("hidden");
  showErr(false); showProgress(false);
  $("#fileInput").value = "";
}

/* ------------------------------------------------------------- progress UI */
function showProgress(on) { $("#progress").classList.toggle("show", on); }
function setStage(line, note) { $("#stageLine").textContent = line; $("#stageNote").textContent = note || ""; }
function showErr(on, title, detail) {
  const box = $("#errBox");
  box.classList.toggle("show", on);
  if (on) { box.querySelector("b").textContent = title || "Couldn't read that file."; $("#errMsg").textContent = detail || ""; }
}

/* ------------------------------------------------------------------ views */
function switchView(name) {
  $$(".nav-item[data-view]").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  $("#view-overview").style.display = name === "overview" ? "" : "none";
  $("#view-packets").style.display  = name === "packets"  ? "" : "none";
}

/* overview */
function renderOverview(file, s) {
  const cards = [
    ["File", `<span class="v sm" title="${esc(file.name)}">${esc(trunc(file.name, 26))}</span>`],
    ["Packets", `<span class="v">${(s.packet_count || 0).toLocaleString()}</span>`],
    ["Duration", `<span class="v sm">${fmtDur(s.elapsed_time)}</span>`],
    ["Size", `<span class="v sm">${fmtBytes(s.file_length)}</span>`],
    ["Link type", `<span class="v sm">${esc(s.file_encap_type || "—")}</span>`],
    ["Format", `<span class="v sm">${esc((s.file_type || "—").split(" - ").pop())}</span>`],
    ["First packet", `<span class="v sm">${fmtTime(s.start_time)}</span>`],
    ["Last packet", `<span class="v sm">${fmtTime(s.stop_time)}</span>`],
  ];
  $("#ovCards").innerHTML = cards.map(([k, v]) => `<div class="card"><div class="k">${k}</div>${v}</div>`).join("");
  renderProtoBreakdown(s.packet_count || 0);
}

const PROTO_CAP = 120000;
function renderProtoBreakdown(total) {
  const hint = $("#ovProtoHint"), host = $("#ovProtos");
  if (state.protoIdx < 0) { host.innerHTML = ""; hint.textContent = ""; return; }
  const n = Math.min(total, PROTO_CAP);
  hint.textContent = total > PROTO_CAP ? `top-level protocol · first ${PROTO_CAP.toLocaleString()} of ${total.toLocaleString()} packets` : "top-level protocol per packet";
  const fr = state.wg.frames("", 0, n);
  const counts = new Map();
  const arr = fr.frames; const size = arr.size();
  for (let i = 0; i < size; i++) {
    const cols = arr.get(i).columns;
    const p = cols.get(state.protoIdx) || "—";
    counts.set(p, (counts.get(p) || 0) + 1);
  }
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 14);
  const max = rows.length ? rows[0][1] : 1;
  host.innerHTML = rows.map(([p, c]) =>
    `<div class="prow"><span class="pn">${esc(p)}</span>
       <span class="pbar"><i style="width:${(c / max * 100).toFixed(1)}%"></i></span>
       <span class="pc">${c.toLocaleString()} · ${(c / n * 100).toFixed(1)}%</span></div>`).join("");
}

/* packet list */
function buildThead() {
  const clsFor = (c) => ({ "No.": "col-no", "Time": "col-time", "Length": "col-len", "Protocol": "col-proto", "Info": "info" }[c] || "");
  $("#pthead").innerHTML = "<tr>" + state.cols.map(c => `<th class="${clsFor(c)}">${esc(c)}</th>`).join("") + "</tr>";
}

function loadPage(resetList) {
  if (resetList) { state.offset = 0; $("#ptbody").innerHTML = ""; }
  const fr = state.wg.frames(state.filter, state.offset, state.page);
  state.matched = fr.matched;
  const rows = fr.frames; const size = rows.size();
  const clsFor = (i) => ({ [state.cols.indexOf("No.")]: "col-no", [state.cols.indexOf("Time")]: "col-time",
    [state.cols.indexOf("Length")]: "col-len", [state.cols.indexOf("Protocol")]: "col-proto",
    [state.cols.indexOf("Info")]: "info" }[i] || "");
  let html = "";
  for (let i = 0; i < size; i++) {
    const m = rows.get(i);
    const cols = vec(m.columns);
    let style = "";
    if (!isDefaultColor(m.bg, m.fg)) style = ` style="background:${colorCss(m.bg)};color:${colorCss(m.fg)}"`;
    html += `<tr data-fnum="${m.number}"${style}>` +
      cols.map((c, ci) => `<td class="${clsFor(ci)}">${esc(c)}</td>`).join("") + `</tr>`;
  }
  $("#ptbody").insertAdjacentHTML("beforeend", html);
  state.offset += size;

  $("#matchCount").innerHTML = `<b>${state.matched.toLocaleString()}</b> packet${state.matched === 1 ? "" : "s"}` +
    (state.filter ? " matched" : "");
  $("#loadMore").style.display = state.offset < state.matched ? "" : "none";
}

/* detail: tree + hex */
function showFrame(fnum) {
  state.selFrame = fnum;
  $$("#ptbody tr").forEach(tr => tr.classList.toggle("sel", +tr.dataset.fnum === fnum));
  const f = state.wg.frame(fnum);

  // data sources → bytes
  state.dsBytes = vec(f.data_sources).map(ds => b64ToBytes(ds.data));
  state.shownDs = state.dsBytes.length ? 0 : -1;
  renderHex(0);

  // tree
  $("#treeRoot").innerHTML = renderTree(vec(f.tree));
  $("#fieldFilter").innerHTML = "";
  wireTree();
  $("#detailPane").classList.add("show");
}

function clearDetail() {
  $("#detailPane").classList.remove("show");
  $("#treeRoot").innerHTML = ""; $("#hexView").innerHTML = ""; $("#fieldFilter").innerHTML = "";
  state.selFrame = null; state.dsBytes = []; state.shownDs = -1;
}

function renderTree(nodes) {
  return nodes.map(n => {
    const kids = vec(n.tree);
    const has = kids.length > 0;
    const meta = `data-start="${n.start}" data-len="${n.length}" data-ds="${n.data_source_idx}" data-filter="${escAttr(n.filter || "")}"`;
    return `<div class="tnode ${has ? "has-kids" : ""}">
      <div class="tlabel" ${meta}>${esc(n.label)}</div>
      ${has ? `<div class="kids">${renderTree(kids)}</div>` : ""}
    </div>`;
  }).join("");
}

function wireTree() {
  $$("#treeRoot .tlabel").forEach(lab => {
    lab.addEventListener("click", () => {
      const node = lab.parentElement;
      if (node.classList.contains("has-kids")) node.classList.toggle("open");
      $$("#treeRoot .tlabel").forEach(l => l.classList.remove("sel"));
      lab.classList.add("sel");
      const ds = +lab.dataset.ds || 0, start = +lab.dataset.start, len = +lab.dataset.len;
      if (ds !== state.shownDs) renderHex(ds);
      highlight(start, len);
      const flt = lab.dataset.filter;
      $("#fieldFilter").innerHTML = flt
        ? `field · <b title="Set as display filter">${esc(flt)}</b>`
        : "";
      const b = $("#fieldFilter b");
      if (b) b.addEventListener("click", () => applyFilter(flt));
    });
  });
}

const HEX_CAP = 4096;
function renderHex(dsIdx) {
  state.shownDs = dsIdx;
  const bytes = state.dsBytes[dsIdx] || new Uint8Array();
  const cap = Math.min(bytes.length, HEX_CAP);
  let html = "";
  for (let off = 0; off < cap; off += 16) {
    const end = Math.min(off + 16, cap);
    let hex = "", ascii = "";
    for (let i = off; i < end; i++) {
      hex += `<span data-b="${i}">${bytes[i].toString(16).padStart(2, "0")}</span> `;
      const c = bytes[i]; ascii += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
    }
    const pad = "   ".repeat(16 - (end - off));
    html += `<span class="off">${off.toString(16).padStart(4, "0")}</span>  ${hex}${pad} ${esc(ascii)}\n`;
  }
  if (bytes.length > HEX_CAP) html += `\n… ${(bytes.length - HEX_CAP).toLocaleString()} more bytes not shown`;
  $("#hexView").innerHTML = html;
}

let hiPrev = [];
function highlight(start, len) {
  hiPrev.forEach(el => el.classList.remove("hi")); hiPrev = [];
  if (start == null || len <= 0) return;
  for (let i = start; i < start + len && i < HEX_CAP; i++) {
    const el = $(`#hexView [data-b="${i}"]`);
    if (el) { el.classList.add("hi"); hiPrev.push(el); }
  }
  if (hiPrev.length) hiPrev[0].scrollIntoView({ block: "nearest" });
}

/* ------------------------------------------------------------ filter apply */
function applyFilter(f) {
  f = (f || "").trim();
  const box = $("#filterBox");
  if (f) {
    try {
      const chk = state.wg.test_filter(f);
      const ok = chk === true || chk == null || chk.ok === true || (typeof chk === "object" && !chk.error);
      if (!ok) { box.classList.add("invalid"); return; }
    } catch { box.classList.add("invalid"); return; }
  }
  box.classList.remove("invalid");
  state.filter = f;
  $("#filterInput").value = f;
  clearDetail();
  if ($("#view-packets").style.display === "none") switchView("packets");
  loadPage(true);
  $("#plistPane").scrollTop = 0;
}

/* ------------------------------------------------------------ small helpers */
function esc(s) { return String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function escAttr(s) { return esc(s).replace(/'/g, "&#39;"); }
function trunc(s, n) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

/* ------------------------------------------------------------------- wiring */
function init() {
  // theme toggle (shares 802u-theme with the main site)
  const root = document.documentElement, tBtn = $("#themeBtn");
  const setTheme = (t) => { root.setAttribute("data-theme", t); tBtn.setAttribute("aria-label", t === "dark" ? "Switch to light mode" : "Switch to dark mode"); };
  tBtn.addEventListener("click", () => {
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    setTheme(next); try { localStorage.setItem("802u-theme", next); } catch {}
  });

  // dropzone
  const dz = $("#dropzone"), fi = $("#fileInput");
  dz.addEventListener("click", () => fi.click());
  dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fi.click(); } });
  fi.addEventListener("change", () => handleFile(fi.files[0]));
  ["dragenter", "dragover"].forEach(ev => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) handleFile(f); });
  // allow dropping anywhere on the drop screen
  const ds = $("#dropScreen");
  ds.addEventListener("dragover", (e) => e.preventDefault());
  ds.addEventListener("drop", (e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) handleFile(f); });

  // nav
  $$(".nav-item[data-view]").forEach(b => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#newBtn").addEventListener("click", reset);

  // packet list interactions
  $("#ptbody").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-fnum]"); if (tr) showFrame(+tr.dataset.fnum);
  });
  $("#loadMore").addEventListener("click", () => loadPage(false));
  $("#plistPane").addEventListener("scroll", (e) => {
    const el = e.target;
    if (state.offset < state.matched && el.scrollTop + el.clientHeight >= el.scrollHeight - 120) loadPage(false);
  });

  // filter
  const fin = $("#filterInput");
  fin.addEventListener("keydown", (e) => { if (e.key === "Enter") applyFilter(fin.value); });
  fin.addEventListener("input", () => $("#filterBox").classList.remove("invalid"));
}

init();
