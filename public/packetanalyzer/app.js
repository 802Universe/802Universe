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

const VENDOR = ".";   // engine files sit alongside index.html (same folder). Use "./vendor" if you put them in a subfolder.
const MAX_MB = 100;   // in-browser ceiling so every view stays responsive (see README)

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
  convType: "IPv4",
  convCache: {},
  convInit: false,
  file: null,
  summary: null,
  rendered: {},
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
  // 1) download the compressed wasm (19 MB) with real progress, then decompress in-browser.
  //    We hand the bytes straight to the engine so nothing over 25 MiB is ever stored/served.
  setStage("Loading the analysis engine…", "First time only · ~19 MB · cached by your browser afterwards");
  setBarMode(true);
  const wasmBinary = await fetchWasmBinary();

  // 2) start the engine
  setStage("Starting the analysis engine…", "");
  setBarMode(false);
  const { Wiregasm } = await import(/* @vite-ignore */ `${VENDOR}/module.js`);
  await loadScript(`${VENDOR}/wiregasm.js`);   // UMD glue → window.loadWiregasm
  const loader = window.loadWiregasm;
  if (typeof loader !== "function") throw new Error("Engine loaded but no entry point was found.");
  const wg = new Wiregasm();
  await wg.init(loader, {
    wasmBinary,                          // bypasses the engine's own wasm fetch entirely
    locateFile: (p) => `${VENDOR}/${p}`, // used only for wiregasm.data
    print: () => {}, printErr: () => {},
  });
  state.wg = wg;
  state.cols = wg.columns();
  state.protoIdx = state.cols.indexOf("Protocol");
  return wg;
}

async function fetchWasmBinary() {
  let res;
  try { res = await fetch(`${VENDOR}/wiregasm.wasm.gz`); }
  catch { throw new Error("Couldn't reach the engine file. Check your connection and retry."); }
  if (!res.ok) throw new Error(`Couldn't load the engine (HTTP ${res.status}). Make sure vendor/wiregasm.wasm.gz is deployed next to this page.`);
  if (typeof DecompressionStream === "undefined")
    throw new Error("This browser can't decompress the engine. Please use a current version of Chrome, Edge, Firefox or Safari.");

  // stream with a progress bar
  const total = +(res.headers.get("content-length") || 0);
  const reader = res.body.getReader();
  const chunks = []; let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value); received += value.length;
    if (total) setBar(received / total);
  }
  setBar(1);

  // gunzip → ArrayBuffer
  const stream = new Blob(chunks).stream().pipeThrough(new DecompressionStream("gzip"));
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

/* --------------------------------------------------------------- file flow */
async function handleFile(file) {
  if (!file) return;
  showErr(false);
  if (file.size > MAX_MB * 1024 * 1024) {
    showErr(true, `That capture is ${(file.size / 1048576).toFixed(0)} MB — over the ${MAX_MB} MB limit.`,
      `This in-browser analyzer is tuned for captures up to ${MAX_MB} MB so every view stays instant. For a larger file, slice it first in Wireshark (File → Export Specified Packets, or the editcap tool) and open a smaller piece here.`);
    return;
  }
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

    await onLoaded(file, s);
  } catch (e) {
    showProgress(false);
    if (e instanceof FriendlyError) showErr(true, e.title, e.detail);
    else showErr(true, "Something went wrong.", e && e.message ? e.message : String(e));
    console.error(e);
  }
}

class FriendlyError { constructor(title, detail){ this.title = title; this.detail = detail; } }

async function onLoaded(file, summary) {
  $("#fileChipName").textContent = file.name;
  $("#fileChip").classList.add("show");
  $("#newBtn").classList.remove("hidden");
  state.file = file; state.summary = summary;
  state.filter = ""; $("#filterInput").value = "";
  state.convCache = {}; state.convType = "IPv4";
  clearDetail();
  buildThead();

  // precompute every view up front so switching sidebar pages is instant
  const steps = [
    ["Building overview…",            () => renderOverview(file, summary)],
    ["Analyzing conversations…",      () => { renderConvTabs(); loadConv(state.convType); }],
    ["Computing protocol hierarchy…", () => renderHierarchy()],
    ["Calculating statistics…",       () => renderStatistics()],
    ["Scanning for findings…",        () => renderFindings()],
    ["Inspecting 802.11 frames…",     () => renderWireless()],
    ["Mapping external endpoints…",   () => renderThreat()],
    ["Loading packet list…",          () => loadPage(true)],
  ];
  setBarMode(true);
  for (let i = 0; i < steps.length; i++) {
    setStage(steps[i][0], ""); setBar(i / steps.length); await tick();
    try { steps[i][1](); } catch (e) { console.error(steps[i][0], e); }
  }
  setBar(1);
  state.rendered = {}; VIEWS.forEach(v => state.rendered[v] = true);

  showProgress(false);
  $("#dropScreen").style.display = "none";
  $("#analysis").classList.add("show");
  switchView("overview");
}
function tick() { return new Promise(r => setTimeout(r, 0)); }

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
function setBarMode(determinate) { const b = $("#progBar"); b.classList.toggle("determinate", determinate); if (!determinate) { const i = $("#progBar > i"); if (i) i.style.width = ""; } }
function setBar(frac) { const i = $("#progBar > i"); if (i) i.style.width = (Math.max(0, Math.min(1, frac)) * 100).toFixed(1) + "%"; }
function showErr(on, title, detail) {
  const box = $("#errBox");
  box.classList.toggle("show", on);
  if (on) { box.querySelector("b").textContent = title || "Couldn't read that file."; $("#errMsg").textContent = detail || ""; }
}

/* ------------------------------------------------------------------ views */
const VIEWS = ["overview", "packets", "conversations", "hierarchy", "statistics", "findings", "wireless", "threat"];
function switchView(name) {
  $$(".nav-item[data-view]").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  VIEWS.forEach(v => { const el = $("#view-" + v); if (el) el.style.display = v === name ? "" : "none"; });
  if (!state.rendered[name]) { state.rendered[name] = true; renderView(name); }
}
function renderView(name) {
  switch (name) {
    case "conversations": renderConvTabs(); loadConv(state.convType); break;
    case "hierarchy":     renderHierarchy(); break;
    case "statistics":    renderStatistics(); break;
    case "findings":      renderFindings(); break;
    case "wireless":      renderWireless(); break;
    case "threat":        renderThreat(); break;
  }
}

// cheap, native, verified: count frames matching any display filter
function count(f) { try { return state.wg.frames(f, 0, 0).matched; } catch { return 0; } }

/* conversations */
const CONV_TYPES = ["Ethernet", "IPv4", "IPv6", "TCP", "UDP"];
function renderConvTabs() {
  $("#convTabs").innerHTML = CONV_TYPES.map(t =>
    `<button class="conv-tab ${t === state.convType ? "active" : ""}" data-conv="${t}">${t}</button>`).join("");
  $$("#convTabs .conv-tab").forEach(b => b.addEventListener("click", () => {
    state.convType = b.dataset.conv;
    $$("#convTabs .conv-tab").forEach(x => x.classList.toggle("active", x === b));
    loadConv(state.convType);
  }));
}

// classify an address: Public / Private / Multicast / Broadcast / Loopback / Link-local / CGNAT / Reserved
function classifyIP(ip) {
  if (!ip) return "";
  if (ip.includes(":")) {
    const s = ip.toLowerCase();
    if (s === "::1") return "Loopback";
    if (s === "::") return "Unspecified";
    if (s.startsWith("fe80")) return "Link-local";
    if (s.startsWith("fc") || s.startsWith("fd")) return "Unique-local";
    if (s.startsWith("ff")) return "Multicast";
    return "Public";
  }
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n) || n < 0 || n > 255)) return "";
  if (ip === "255.255.255.255") return "Broadcast";
  if (p[0] === 0) return "Reserved";
  if (p[0] === 10) return "Private";
  if (p[0] === 127) return "Loopback";
  if (p[0] === 169 && p[1] === 254) return "Link-local";
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return "Private";
  if (p[0] === 192 && p[1] === 168) return "Private";
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return "CGNAT";
  if (p[0] >= 224 && p[0] <= 239) return "Multicast";
  if (p[0] >= 240) return "Reserved";
  return "Public";
}

function loadConv(type) {
  const body = $("#convBody");
  let convs = state.convCache[type];
  if (convs === undefined) {
    try {
      const r = state.wg.tap({ tap0: `conv:${type}` });
      convs = (r.error || !r.taps.length) ? [] : (r.taps[0].convs || []);
    } catch { convs = []; }
    state.convCache[type] = convs;
  }
  if (!convs.length) { body.innerHTML = `<div class="conv-empty">No ${esc(type)} conversations in this capture.</div>`; return; }

  const hasPorts = type === "TCP" || type === "UDP";
  const isIP = type !== "Ethernet";
  const tag = a => isIP ? ` <span class="ipclass">${classifyIP(a) || "?"}</span>` : "";
  const rows = convs.map((c) => {
    const a = (hasPorts ? `${esc(c.saddr)}<b>:${esc(c.sport)}</b>` : esc(c.saddr)) + tag(c.saddr);
    const b = (hasPorts ? `${esc(c.daddr)}<b>:${esc(c.dport)}</b>` : esc(c.daddr)) + tag(c.daddr);
    const pkts = (c.tx_frames_total + c.rx_frames_total);
    const bytes = (c.tx_bytes_total + c.rx_bytes_total);
    const dur = (c.stop != null && c.start != null) ? fmtDur(c.stop - c.start) : "—";
    return `<tr data-filter="${escAttr(c.filter || "")}">
      <td class="addr">${a}</td><td class="addr">${b}</td>
      <td class="num">${pkts.toLocaleString()}</td><td class="num">${fmtBytes(bytes)}</td>
      <td class="num">${c.tx_frames_total.toLocaleString()}</td><td class="num">${fmtBytes(c.tx_bytes_total)}</td>
      <td class="num">${c.rx_frames_total.toLocaleString()}</td><td class="num">${fmtBytes(c.rx_bytes_total)}</td>
      <td class="num">${dur}</td></tr>`;
  }).join("");

  body.innerHTML =
    `<div class="conv-hint">${convs.length.toLocaleString()} conversation${convs.length === 1 ? "" : "s"} · click a row to <b>filter the packet list</b></div>
     <table class="ptable conv-table">
       <thead><tr>
         <th>Address A</th><th>Address B</th>
         <th class="col-len">Packets</th><th class="col-len">Bytes</th>
         <th class="col-len">A→B pkts</th><th class="col-len">A→B bytes</th>
         <th class="col-len">B→A pkts</th><th class="col-len">B→A bytes</th>
         <th class="col-len">Duration</th>
       </tr></thead><tbody>${rows}</tbody></table>`;

  $$("#convBody tbody tr").forEach(tr => tr.addEventListener("click", () => {
    const f = tr.dataset.filter; if (f) applyFilter(f);   // drills into the packet list
  }));
}

/* hierarchy — nested protocol counts via display-filter matching */
const HIER = [
  { n: "Ethernet", f: "eth", c: [
    { n: "ARP", f: "arp" },
    { n: "IPv4", f: "ip", c: [
      { n: "TCP", f: "ip && tcp", c: [{ n: "TLS/SSL", f: "tls" }, { n: "HTTP", f: "http" }, { n: "SSH", f: "ssh" }] },
      { n: "UDP", f: "ip && udp", c: [{ n: "DNS", f: "ip && dns" }, { n: "DHCP", f: "bootp || dhcp" }, { n: "QUIC", f: "quic" }, { n: "NTP", f: "ntp" }, { n: "mDNS/LLMNR", f: "mdns || llmnr" }] },
      { n: "ICMP", f: "icmp" }, { n: "IGMP", f: "igmp" }, { n: "GRE", f: "gre" }, { n: "ESP", f: "esp" },
    ] },
    { n: "IPv6", f: "ipv6", c: [
      { n: "TCP", f: "ipv6 && tcp" }, { n: "UDP", f: "ipv6 && udp" }, { n: "ICMPv6", f: "icmpv6" },
    ] },
    { n: "802.1Q VLAN", f: "vlan" }, { n: "STP", f: "stp" }, { n: "LLDP", f: "lldp" }, { n: "CDP", f: "cdp" }, { n: "LLC", f: "llc" },
  ] },
  { n: "802.11 (WLAN)", f: "wlan", c: [
    { n: "Management", f: "wlan.fc.type==0" }, { n: "Control", f: "wlan.fc.type==1" }, { n: "Data", f: "wlan.fc.type==2" },
  ] },
];
function renderHierarchy() {
  const total = state.summary.packet_count || 1;
  const rows = [];
  const walk = (nodes, depth) => nodes.forEach(nd => { const c = count(nd.f); if (c > 0) { rows.push({ name: nd.n, filter: nd.f, count: c, depth }); if (nd.c) walk(nd.c, depth + 1); } });
  walk(HIER, 0);
  const host = $("#hierBody");
  if (!rows.length) { host.innerHTML = `<div class="conv-empty">No recognized protocols.</div>`; return; }
  host.innerHTML = rows.map(r => `<div class="hier-row" data-filter="${escAttr(r.filter)}">
     <span class="hn">${"&nbsp;&nbsp;&nbsp;&nbsp;".repeat(r.depth)}${r.depth ? '<span class="tw">└ </span>' : ""}${esc(r.name)}</span>
     <span class="hc">${r.count.toLocaleString()}</span>
     <span class="hp">${(r.count / total * 100).toFixed(1)}%</span></div>`).join("");
  $$("#hierBody .hier-row").forEach(el => el.addEventListener("click", () => applyFilter(el.dataset.filter)));
}

/* statistics — summary metrics + packets-over-time from iograph */
function fmtBits(bps) { const u = ["bps", "Kbps", "Mbps", "Gbps"]; let i = 0; while (bps >= 1000 && i < u.length - 1) { bps /= 1000; i++; } return (i ? bps.toFixed(1) : bps.toFixed(0)) + " " + u[i]; }
function renderStatistics() {
  const s = state.summary, pkts = s.packet_count || 0, bytes = s.file_length || 0, dur = s.elapsed_time || 0;
  const cards = [
    ["Packets", pkts.toLocaleString()], ["Duration", fmtDur(dur)], ["Total bytes", fmtBytes(bytes)],
    ["Avg packet", pkts ? (bytes / pkts).toFixed(0) + " B" : "—"],
    ["Avg packets/s", dur ? (pkts / dur).toFixed(1) : "—"],
    ["Avg bit rate", dur ? fmtBits(bytes * 8 / dur) : "—"],
  ];
  $("#statCards").innerHTML = cards.map(([k, v]) => `<div class="card"><div class="k">${k}</div><div class="v sm">${v}</div></div>`).join("");
  let items = [];
  try { const g = state.wg.iograph({ graph0: "packets" }); if (g.iograph.length) items = g.iograph[0].items; } catch {}
  drawBars($("#statChart"), items, dur);
}
function drawBars(host, items, dur) {
  if (!items.length) { host.innerHTML = `<div class="conv-empty">No time-series data.</div>`; return; }
  const W = 900, H = 220, pad = 28, n = items.length, max = Math.max(...items, 1), bw = (W - pad * 2) / n;
  let bars = "";
  for (let i = 0; i < n; i++) { const h = (items[i] / max) * (H - pad * 2); bars += `<rect class="bar-r" x="${(pad + i * bw + 1).toFixed(2)}" y="${(H - pad - h).toFixed(2)}" width="${Math.max(bw - 2, 1).toFixed(2)}" height="${h.toFixed(2)}"><title>${items[i]} pkts</title></rect>`; }
  host.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
     <line class="axis" x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}"/>${bars}
     <text class="glabel" x="${pad}" y="14">peak ${max.toLocaleString()} pkts / interval</text>
     <text class="glabel" x="${pad}" y="${H - 8}">0</text>
     <text class="glabel" x="${W - pad}" y="${H - 8}" text-anchor="end">${dur ? fmtDur(dur) : ""}</text></svg>`;
  const interval = dur && n ? dur / n : 0;
  $("#statHint").textContent = interval ? `${n} intervals · ~${interval < 1 ? (interval * 1000).toFixed(0) + " ms" : interval.toFixed(2) + " s"} each` : `${n} intervals`;
}

/* findings — curated expert-style checks via filter counts */
const CHECKS = [
  { sev: "error", f: "tcp.analysis.retransmission", t: "TCP retransmissions", d: "Segments the sender had to resend — packet loss or congestion." },
  { sev: "error", f: "tcp.analysis.fast_retransmission", t: "Fast retransmissions", d: "Retransmit triggered by duplicate ACKs before a timeout." },
  { sev: "error", f: "tcp.analysis.lost_segment", t: "Previous segment not captured", d: "A gap in the TCP sequence — missing data on the wire or in the capture." },
  { sev: "error", f: "tcp.analysis.zero_window", t: "TCP zero window", d: "A receiver advertised no buffer space; the sender had to stall." },
  { sev: "warn", f: "tcp.analysis.window_full", t: "TCP window full", d: "The send window filled — throughput limited by window size." },
  { sev: "warn", f: "tcp.analysis.duplicate_ack", t: "Duplicate ACKs", d: "Repeated ACKs for the same sequence — loss or reordering." },
  { sev: "warn", f: "tcp.analysis.out_of_order", t: "Out-of-order segments", d: "Segments arrived out of sequence." },
  { sev: "warn", f: "tcp.flags.reset==1", t: "Connection resets (RST)", d: "Abruptly terminated TCP connections." },
  { sev: "warn", f: "icmp.type==3 || icmpv6.type==1", t: "Destination unreachable", d: "ICMP unreachable — routing, firewall or closed-port issues." },
  { sev: "warn", f: "dns.flags.rcode != 0", t: "DNS errors", d: "DNS responses with a non-zero reply code (NXDOMAIN, SERVFAIL…)." },
  { sev: "warn", f: "http.response.code >= 400", t: "HTTP error responses", d: "4xx / 5xx HTTP responses." },
  { sev: "note", f: "arp.duplicate-address-detected", t: "Duplicate ARP address", d: "Two hosts claiming the same IP." },
  { sev: "malformed", f: "_ws.malformed", t: "Malformed packets", d: "Packets the dissector couldn't fully parse." },
];
const SEV_ORDER = { error: 0, warn: 1, malformed: 2, note: 3 };
function renderFindings() {
  const found = CHECKS.map(c => ({ ...c, n: count(c.f) })).filter(c => c.n > 0)
    .sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || b.n - a.n);
  const host = $("#findingsBody");
  if (!found.length) { host.innerHTML = `<div class="finding-clean">✓ No common issues detected — no retransmissions, resets, DNS/HTTP errors or malformed frames.</div>`; return; }
  host.innerHTML = found.map(c => `<div class="finding" data-filter="${escAttr(c.f)}">
     <span class="sev ${c.sev}"></span>
     <div><div class="ftitle">${esc(c.t)}</div><div class="fdesc">${esc(c.d)}</div></div>
     <div class="fcount">${c.n.toLocaleString()}<small>${c.sev}</small></div></div>`).join("");
  $$("#findingsBody .finding").forEach(el => el.addEventListener("click", () => applyFilter(el.dataset.filter)));
}

/* wireless — 802.11 frame-type / management / retry breakdown */
function renderWireless() {
  const host = $("#wirelessBody"), wlan = count("wlan");
  if (!wlan) { host.innerHTML = `<div class="empty"><div><div class="big">∿</div><h3>No 802.11 frames</h3><p>This capture has no wireless frames. Wireless analysis needs a monitor-mode / radiotap capture.</p></div></div>`; return; }
  const group = (title, rows) => {
    const items = rows.map(([t, f]) => [t, f, count(f)]).filter(r => r[2] > 0);
    if (!items.length) return "";
    return `<div class="wsec"><div class="section-h"><h2>${title}</h2></div><div class="protos">` +
      items.map(([t, f, n]) => `<div class="prow" data-filter="${escAttr(f)}" style="cursor:pointer">
        <span class="pn">${esc(t)}</span><span class="pbar"><i style="width:${(n / wlan * 100).toFixed(1)}%"></i></span>
        <span class="pc">${n.toLocaleString()}</span></div>`).join("") + `</div></div>`;
  };
  host.innerHTML =
    `<div class="cards">
       <div class="card"><div class="k">802.11 frames</div><div class="v">${wlan.toLocaleString()}</div></div>
       <div class="card"><div class="k">Retries</div><div class="v sm">${count("wlan.fc.retry==1").toLocaleString()}</div></div>
       <div class="card"><div class="k">Protected</div><div class="v sm">${count("wlan.fc.protected==1").toLocaleString()}</div></div>
     </div>` +
    group("Frame types", [["Management", "wlan.fc.type==0"], ["Control", "wlan.fc.type==1"], ["Data", "wlan.fc.type==2"]]) +
    group("Management subtypes", [
      ["Beacon", "wlan.fc.type_subtype==0x08"], ["Probe request", "wlan.fc.type_subtype==0x04"],
      ["Probe response", "wlan.fc.type_subtype==0x05"], ["Authentication", "wlan.fc.type_subtype==0x0b"],
      ["Association request", "wlan.fc.type_subtype==0x00"], ["Association response", "wlan.fc.type_subtype==0x01"],
      ["Reassociation request", "wlan.fc.type_subtype==0x02"], ["Deauthentication", "wlan.fc.type_subtype==0x0c"],
      ["Disassociation", "wlan.fc.type_subtype==0x0a"], ["Action", "wlan.fc.type_subtype==0x0d"]]) +
    group("Control & QoS", [["QoS Data", "wlan.fc.type_subtype==0x28"], ["Block Ack", "wlan.fc.type_subtype==0x19"],
      ["RTS", "wlan.fc.type_subtype==0x1b"], ["CTS", "wlan.fc.type_subtype==0x1c"], ["ACK", "wlan.fc.type_subtype==0x1d"]]);
  $$("#wirelessBody .prow[data-filter]").forEach(el => el.addEventListener("click", () => applyFilter(el.dataset.filter)));
}

/* threat intel — external (public) endpoints; GeoIP + IOC enrichment lands next */
function isPrivate4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(isNaN)) return true;   // not a plain IPv4 → skip
  if (p[0] === 10 || p[0] === 127 || p[0] === 0 || p[0] >= 224 || p[0] === 255) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  return false;
}
function renderThreat() {
  const host = $("#threatBody"), ext = new Map();
  try {
    const r = state.wg.tap({ tap0: "conv:IPv4" });
    if (!r.error && r.taps.length) for (const c of r.taps[0].convs) {
      const pk = c.tx_frames_total + c.rx_frames_total, by = c.tx_bytes_total + c.rx_bytes_total;
      for (const addr of [c.saddr, c.daddr]) {
        if (isPrivate4(addr)) continue;
        const e = ext.get(addr) || { pkts: 0, bytes: 0 }; e.pkts += pk; e.bytes += by; ext.set(addr, e);
      }
    }
  } catch {}
  const rows = [...ext.entries()].sort((a, b) => b[1].bytes - a[1].bytes);
  if (!rows.length) { host.innerHTML = `<div class="conv-empty">No external (public) IPv4 endpoints in this capture.</div>`; return; }
  host.innerHTML =
    `<div class="conv-hint">${rows.length.toLocaleString()} external endpoint${rows.length === 1 ? "" : "s"} · country &amp; threat flags activate once GeoIP / IOC data is added</div>
     <table class="ptable"><thead><tr><th>IP address</th><th>Country</th><th>Threat</th><th class="col-len">Packets</th><th class="col-len">Bytes</th></tr></thead><tbody>` +
    rows.map(([ip, e]) => `<tr data-filter="${escAttr("ip.addr==" + ip)}"><td class="mono">${esc(ip)}</td>
       <td class="mono" style="color:var(--muted)">—</td><td class="mono" style="color:var(--muted)">—</td>
       <td class="col-len">${e.pkts.toLocaleString()}</td><td class="col-len">${fmtBytes(e.bytes)}</td></tr>`).join("") +
    `</tbody></table>`;
  $$("#threatBody tbody tr").forEach(tr => tr.addEventListener("click", () => applyFilter(tr.dataset.filter)));
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
  let fr;
  try { fr = state.wg.frames(state.filter, state.offset, state.page); }
  catch { $("#filterBox").classList.add("invalid"); $("#matchCount").innerHTML = `<b>0</b> packets · invalid filter`; $("#loadMore").style.display = "none"; return; }
  $("#filterBox").classList.remove("invalid");
  state.matched = fr.matched;
  const rows = fr.frames; const size = rows.size();
  const clsFor = (i) => ({ [state.cols.indexOf("No.")]: "col-no", [state.cols.indexOf("Time")]: "col-time",
    [state.cols.indexOf("Length")]: "col-len", [state.cols.indexOf("Protocol")]: "col-proto",
    [state.cols.indexOf("Info")]: "info" }[i] || "");
  let html = "";
  for (let i = 0; i < size; i++) {
    const m = rows.get(i);
    const cols = vec(m.columns);
    html += `<tr data-fnum="${m.number}">` +
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
  state.filter = f;
  $("#filterInput").value = f;
  clearDetail();
  if ($("#view-packets").style.display === "none") switchView("packets");
  loadPage(true);   // marks the filter box invalid itself if the engine rejects the filter
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
  $("#resetBtn").addEventListener("click", () => { switchView("packets"); applyFilter(""); });
}

init();
