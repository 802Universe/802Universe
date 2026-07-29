# What's new — the "download tool" feature

This is your **complete site**, with the new download-tool feature fully wired.
You were confused because it was arriving as separate files — this package puts
everything in the right place so you can just commit and deploy.

## What was ALREADY in your repo (you had applied these)
- `worker/index.js` — the `/download/<slug>` route
- `public/content.default.json` — the "Aruba Datapath Session Analyzer" tile
- `public/packetanalyzer/vendor/` — already deleted (good, it was 22 MB of dead files)

## What this package ADDS (the pieces that were missing — this is why the page didn't work yet)
- `public/tool-template.html` .......... the reusable tool landing page
- `public/datapathanalyzer/index.html` .. your first tool's page (a copy of the template)
- `public/readmes/datapathanalyzer.md` .. the README as a local backup (only used if you set readme "from":"file")

## How to use this zip
1. Extract it. It contains your whole site.
2. Either replace your local repo's files with these, **or** just copy the three
   files above into your repo (everything else is unchanged from your GitHub).
3. Commit and deploy the way you normally do.
4. Open **https://802universe.com/datapathanalyzer/** — you should see the styled page,
   the README, and a **"Analyzer (HTML)"** download button. Click it: the file downloads
   and GitHub never appears.

## Adding your NEXT download tool (3 steps)
1. In `/admin`, add a tile with these fields:
   `kind:"Tool"`, `title`, `desc`, `tags`, `icon`, `cat`,
   `href:"/<slug>/"`, `slug:"<slug>"`, `readme:{"from":"repo"}`,
   and a `files` array — one entry per download button:
   `{ "label":"Windows build (EXE)", "url":"<the normal GitHub /blob/ URL>" }`
2. Copy `public/tool-template.html` to `public/<slug>/index.html` (no edits needed).
3. Done. Multiple files in `files` = multiple download buttons automatically.

Notes:
- Paste the normal GitHub URL you see in the browser (`.../blob/main/...`). The Worker
  converts it to the raw download URL itself.
- `readme:{"from":"repo"}` pulls the README live from that tool's GitHub repo.
  Alternatives: `{"from":"file","path":"/readmes/<slug>.md"}` or `{"from":"inline","md":"..."}`.
- If a tool is ever over 25 MB, upload it to a GitHub **Release** and point the
  `files[].url` at the release download link — nothing else changes.

## Not touched by this package (separate items)
- Your favicon and your `packetanalyzer/` app are exactly as they are on GitHub.
  If you'd like the "802" favicon folded in, or the latest packet-analyzer build,
  ask and I'll make a second package.

---

# Site-wide favicon (the "802" icon)

The "802" favicon is now the icon for the **whole site**, and future pages inherit it automatically:

- The canonical files live at the site **root** (`public/favicon.svg`, `favicon.ico`, the PNG sizes,
  `apple-touch-icon.png`, `android-chrome-*.png`, `site.webmanifest`).
- The homepage and `project-template.html` previously hard-coded a small inline favicon — that override
  was removed and replaced with the standard `<head>` block that points at the root files.
- The packet analyzer and the new tool pages already point at the root files.
- The wiki (and any page that doesn't set its own icon) automatically falls back to the root `/favicon.ico`.

**For every new page you build:** either paste this block into its `<head>`, or set no icon at all
(the browser will use the root `/favicon.ico`):

```html
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#1141B8">
```

Note: if you ever **rebuild the wiki** from its Astro source, set the 802 favicon in that project too,
or it will regenerate with the Astro default.
