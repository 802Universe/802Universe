# Aruba Datapath Session Analyzer

A single-file, browser-based dashboard for analysing **`show datapath session internal`** output from Aruba Networks tech-support log files. No installation, no server, no dependencies to install — just open the HTML file in any modern browser and drop your log file in.

---

## Screenshot

> Upload your `tech-support.log` file to see the full interactive dashboard.

---

## Features

### 📂 File Handling
- Drag-and-drop or browse to upload any Aruba `tech-support.log` file
- Automatically locates and extracts the `show datapath session internal` block from 700+ command logs
- Also parses `show user-table verbose` and `show station-table` to enrich session data with user and station labels

### 📊 Overview Stats (12 cards)
| Card | Description |
|---|---|
| Total Sessions | All parsed entries |
| L3 Sessions | IP-based sessions (%) |
| L2 Sessions | MAC-based sessions (%) |
| DENIED | Sessions with D flag |
| Local Dest | Locally destined sessions |
| Tunnel Dest | Tunnelled sessions |
| Protocols | Unique protocol count |
| App Classified | Sessions with DPI app ID |
| High-Risk WebCC | WebCC reputation score 1–20 |
| CP-BWM Policed | Sessions policed by CP-BWM contracts |
| Total Packets | Sum of all session packets (hex parsed) |
| Total Bytes | Human-readable total bytes across all sessions |

### 📈 Analytics Charts (6 panels, each expandable)
- **Protocol Distribution** — donut chart of top 8 protocols
- **Top Destination IPs** — bar chart, top 10
- **Top Source IPs** — bar chart, top 10
- **Top Applications** — DPI app name bar chart, top 10
- **Web Content Categories** — WebCC category bar chart, top 10 (excludes Not-Classified)
- **Destination Types** — dynamic bar chart; groups tunnel/local/pc0/pc1/other — only shows what exists in the data; hover Tunnel bar for per-tunnel-ID breakdown

> Click the **⤢** icon on any chart to expand it into a full detail popup.

### 🔍 Session Table
- Fixed-width column parser — reads 38 columns from separator line
- Infinite scroll — loads 200 rows at a time as you scroll
- Click any row to open a full **6-panel detail modal**:
  - 🌐 Endpoints (src, dst, protocol, ports, country, labels)
  - ⚙️ Forwarding (destination, CPU, age, tunnel, VLAN)
  - 📊 Traffic Stats (packets, bytes, DPI counters)
  - 🚦 QoS (priority, ToS/DSCP, CP-BWM contract)
  - 🔬 App / DPI / Threat (app name, WebCC rep & category, threat, URL)
  - 🏳️ Flags (all flags decoded with full descriptions)

### 🔎 Filtering System
| Filter | Description |
|---|---|
| Search | Free-text across all fields (IP, port, app, flag, URL, country) |
| Proto | Dropdown of protocols found in the data |
| Dest | Dynamic dropdown — shows only destination types found in the file |
| Type | L2 (MAC) or L3 (IP) |
| FLAGS | Grouped dropdown — 27 flags across 10 groups, multi-select |
| LABELS | Grouped dropdown — filter by user, station, loopback, apipa, multicast, broadcast, research, private |

- **CLEAR** resets all filters instantly
- **⬇ CSV** exports the current filtered view

### 🏷️ IP & MAC Labels
Sessions are automatically annotated with coloured inline labels:

| Label | Colour | Meaning |
|---|---|---|
| `user` | 🟢 Green | IP or MAC found in `show user-table verbose` |
| `station` | 🟦 Teal | MAC found in `show station-table` |
| `private` | Gray | RFC1918 address (10.x, 172.16–31.x, 192.168.x) |
| `loopback` | 🟡 Amber | 127.x.x.x |
| `apipa` | 🟡 Amber | 169.254.x.x |
| `multicast` | 🟡 Amber | 224.x.x.x – 239.x.x.x |
| `broadcast` | 🟡 Amber | 255.255.255.255 |
| `research` | 🟡 Amber | 240.x.x.x – 254.x.x.x |
| `unknown` | 🟡 Amber | 0.0.0.0 |

Labels appear in both the session table and the detail popup.

### 🎨 Themes
Three built-in themes — switchable live with no page reload:
- **● DARK** — deep navy / cyan (default, NOC-style)
- **◑ GRAY** — charcoal / desaturated cyan
- **☀ LIGHT** — white / dark navy

Theme preference is saved to `localStorage`.

### 📖 Lookup Tables
- **200+ port names** — standard well-known ports plus full Aruba-specific port range (8209–9551, 15101–16716)
- **25 IP protocol names** — ICMP through Ethernet
- **28 Ethernet protocol names** — IPv4, ARP, LLDP, MPLS, PPPoE, 802.1x, Cisco CDP/DTP, and more
- **ToS/DSCP mapping** — 0–63 → CS0/BE, EF-Voice, AF11–43, CS1–7
- **27 session flags** — all decoded with full descriptions

---

## How to Use

1. **Download** `Aruba - Datapath Session Analyzer - Version 1.html`
2. **Open** it in any modern browser (Chrome, Firefox, Edge, Safari)
3. **Upload** your Aruba `tech-support.log` file by dragging it onto the upload zone or clicking Browse
4. The dashboard populates automatically — explore charts, filter the table, click rows for details

> No internet connection is required after the page loads. All processing happens locally in your browser. Your log file is never uploaded anywhere.

---

## Compatibility

| Browser | Status |
|---|---|
| Chrome 90+ | ✅ Fully supported |
| Firefox 88+ | ✅ Fully supported |
| Edge 90+ | ✅ Fully supported |
| Safari 14+ | ✅ Fully supported |

---

## Aruba Log Requirements

The tool expects a standard Aruba `tech-support.log` file containing at minimum:

```
show datapath session internal
```

Optional but recommended for full label enrichment:

```
show user-table verbose
show station-table
```

The parser detects each command block automatically and stops at the next `show` command.

---

## Technical Notes

- **Single HTML file** — all CSS, JS, and Chart.js (CDN) in one file. No build step, no npm, no Python.
- **Fixed-width column parser** — reads column boundaries from the separator line (`---`) rather than splitting on whitespace, making it robust across different ArubaOS versions.
- **Chart.js 4.4** loaded from cdnjs for charting.
- **Google Fonts** (Space Mono, Rajdhani) loaded for UI typography.
- Tested against ArubaOS 8.x tech-support log files.

---

## Changelog

### Version 1 — February 2026
- Initial release
- Full datapath session parser with 38-column support
- 12 stat cards, 6 expandable charts
- Infinite scroll session table with 6-panel detail modal
- 27-flag grouped dropdown filter
- IP/MAC label system (user-table + station-table enrichment)
- LABELS grouped dropdown filter
- 200+ port name lookups including full Aruba-specific port range
- Dynamic Destination Types chart with tunnel breakdown tooltip
- Three-theme system (Dark / Gray / Light)

---

## License

BSD 2-Clause License — see [LICENSE](LICENSE) for details.

---

## Author

**Manish Sharma**
GitHub: [@welcomemanish](https://github.com/welcomemanish)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
