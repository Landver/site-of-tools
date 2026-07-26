# Pre-launch Step 0 Remainder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the three open items of `promo/01-pre-launch-checklist.md` Step 0: GitHub About/topics/social-preview, OpenGraph/Twitter meta tags on all pages, and the FAQ skim crib.

**Architecture:** OG tags go in the one shared head partial (`shared/templates/partials/head.html`) that every full page already includes; per-page descriptions arrive via a new `"Desc"` key in existing handler maps. The social card is a 1280×640 PNG composed locally (puppeteer screenshot of the live botcheck verdict + Pillow composition) and committed to `shared/static/img/` (auto-embedded, served at `/static`) and `docs/assets/` (for the GitHub upload).

**Tech Stack:** Go 1.26 `html/template` (Echo v5 renderer), existing Go test packages, puppeteer (existing `automation-harness` node_modules), Python 3 + Pillow in a local venv, `gh` CLI, kimi-webbridge skill.

**Spec:** `docs/superpowers/specs/2026-07-26-pre-launch-og-design.md`

## Global Constraints

- Repo works directly on `master`; `go vet` + `go test` gate before every commit (repo convention).
- No new Go dependencies. Pillow is installed ONLY into `automation-harness/.venv` (never globally).
- `automation-harness/` is gitignored as a whole — scripts there are local tooling, never committed; only the two output PNGs are committed.
- `shared/static/` is embedded via `//go:embed all:static` (recursive) — `shared/static/img/og-cover.png` needs no embed.go change.
- `og:image` URL is exactly `https://corpberry.com/static/img/og-cover.png` (apex always resolves; unversioned, no `?v=` hash).
- No `og:url`, no `twitter:site` (per spec — don't invent values).
- Copy tone per `promo/00-message-kit.md`: plain, specific, no hype adjectives.
- GitHub repo: `Landver/site-of-tools`; `gh` is authenticated as Landver with `repo` scope.
- Description strings must be byte-identical between handler code and test assertions.

---

### Task 1: OG/Twitter meta tags + per-page descriptions

**Files:**
- Modify: `shared/templates/partials/head.html`
- Modify: `site/site.go:33-36`
- Modify: `tools/botcheck/handler.go:90-92`
- Modify: `tools/iptools/handler.go` (add const block after imports; edit maps at :63-65, :78, :87, :116-119, :177)
- Test: `site/tests/site_test.go` (append `TestHomeOGTags`)
- Test: `tools/botcheck/tests/handler_test.go` (append `TestIndexOGTags`)
- Test: `tools/iptools/tests/handler_test.go` (append `TestOGTags`)
- Also staged in the commit: `docs/superpowers/specs/2026-07-26-pre-launch-og-design.md` (already-edited line-ref fix, uncommitted on disk)

**Interfaces:**
- Consumes: existing renderer contract — every full-page handler passes `map[string]any` with `"Title"`; `{{template "partials/head" .}}` receives the same map.
- Produces: `"Desc"` string key on every full-page render map; head partial falls back to a generic description via `{{or .Desc "…"}}` when absent (fragments, tests building bare maps).

- [ ] **Step 1: Write the failing test for apex**

Append to `site/tests/site_test.go`:

```go
func TestHomeOGTags(t *testing.T) {
	body := get(newTestApp(), "text/html").Body.String()
	for _, want := range []string{
		`<meta property="og:type" content="website">`,
		`<meta property="og:site_name" content="corpberry.com">`,
		`<meta property="og:title" content="Stas — corpberry.com">`,
		`<meta property="og:image" content="https://corpberry.com/static/img/og-cover.png">`,
		`<meta name="twitter:card" content="summary_large_image">`,
		`content="Open-source web tools by Stas`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("home <head> missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Write the failing test for botcheck**

Append to `tools/botcheck/tests/handler_test.go`:

```go
func TestIndexOGTags(t *testing.T) {
	body := get(newTestApp(fakeLooker{}), "/", map[string]string{"Accept": "text/html"}).Body.String()
	for _, want := range []string{
		`<meta property="og:type" content="website">`,
		`<meta property="og:title" content="Bot check">`,
		`<meta property="og:image" content="https://corpberry.com/static/img/og-cover.png">`,
		`<meta name="twitter:card" content="summary_large_image">`,
		`content="Open-source bot-detection self-test`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("botcheck index <head> missing %q", want)
		}
	}
}
```

- [ ] **Step 3: Write the failing test for iptools**

Append to `tools/iptools/tests/handler_test.go`:

```go
func TestOGTags(t *testing.T) {
	app := newTestApp(fakeLooker{res: &iptools.Result{IP: "8.8.8.8"}})
	for _, tc := range []struct{ target, desc string }{
		{"/", "Look up any IP"},
		{"/?ip=8.8.8.8", "Look up any IP"},
		{"/cidr", "CIDR subnet calculator"},
		{"/history", "Recent IP lookups"},
	} {
		body := do(app, tc.target, map[string]string{"Accept": "text/html"}).Body.String()
		for _, want := range []string{
			`<meta property="og:type" content="website">`,
			`<meta property="og:image" content="https://corpberry.com/static/img/og-cover.png">`,
			`<meta name="twitter:card" content="summary_large_image">`,
			`content="` + tc.desc,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s <head> missing %q", tc.target, want)
			}
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `go test ./site/tests/ ./tools/botcheck/tests/ ./tools/iptools/tests/ 2>&1 | tail -20`
Expected: FAIL — `missing "<meta property=\"og:type\" content=\"website\">"` in all three packages.

- [ ] **Step 5: Rewrite the head partial with OG/Twitter tags**

Replace the whole of `shared/templates/partials/head.html` with (only the meta block after `<title>` is new; everything below `{{$desc ...}}`…`twitter:image` lines stays byte-identical to the old file):

```html
{{define "partials/head"}}
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{.Title}}</title>
  {{$desc := or .Desc "Open-source web tools by Stas: a transparent bot-detection self-test and IP tools. One Go binary, no tracking."}}
  <meta name="description" content="{{$desc}}">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="corpberry.com">
  <meta property="og:title" content="{{.Title}}">
  <meta property="og:description" content="{{$desc}}">
  <meta property="og:image" content="https://corpberry.com/static/img/og-cover.png">
  <meta property="og:image:width" content="1280">
  <meta property="og:image:height" content="640">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="{{.Title}}">
  <meta name="twitter:description" content="{{$desc}}">
  <meta name="twitter:image" content="https://corpberry.com/static/img/og-cover.png">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='11' fill='%23b83266'/%3E%3C/svg%3E">
  <!-- Set theme before first paint (saved choice, else OS pref) → avoids flash.
       Also exposes toggleTheme() for header button. -->
  <script>
    (function () {
      var el = document.documentElement;
      var saved = localStorage.getItem("theme");
      // typeof-guard: stripped/hardened JS env w/o matchMedia (see botcheck's
      // matchmedia_missing check) → throws here otherwise, before toggleTheme()
      // below even defined.
      var prefersDark = typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
      el.setAttribute("data-theme", saved || (prefersDark ? "dark" : "light"));
      window.toggleTheme = function () {
        var next = el.getAttribute("data-theme") === "dark" ? "light" : "dark";
        localStorage.setItem("theme", next);
        el.setAttribute("data-theme", next);
      };
    })();
  </script>
  <link rel="stylesheet" href="{{asset "css/styles.css"}}">
  <!-- htmx first (no defer), Alpine last (MUST defer). Both vendored. -->
  <script src="{{asset "js/htmx.min.js"}}"></script>
  <script defer src="{{asset "js/alpine.min.js"}}"></script>
</head>
{{end}}
```

- [ ] **Step 6: Add `Desc` to the apex home handler**

In `site/site.go`, change:

```go
		data := map[string]any{
			"Title": "Stas — corpberry.com",
			"Tools": Tools(cfg),
		}
```

to:

```go
		data := map[string]any{
			"Title": "Stas — corpberry.com",
			"Desc":  "Open-source web tools by Stas: Bot check (transparent 68-signal bot-detection self-test) and IP Tools (lookup, reputation, subnet calculator). One Go binary, no tracking.",
			"Tools": Tools(cfg),
		}
```

- [ ] **Step 7: Add `Desc` to the botcheck index handler**

In `tools/botcheck/handler.go`, change:

```go
	return c.Render(http.StatusOK, "botcheck/index", map[string]any{
		"Title": "Bot check", "Attribution": true,
	})
```

to:

```go
	return c.Render(http.StatusOK, "botcheck/index", map[string]any{
		"Title":       "Bot check",
		"Desc":        "Open-source bot-detection self-test: see which of 68 signals give your browser away. Client fingerprint, HTTP headers, and IP reputation, cross-checked. Every signal shown, nothing blocked.",
		"Attribution": true,
	})
```

- [ ] **Step 8: Add `Desc` to the iptools handlers**

In `tools/iptools/handler.go`, add immediately after the import block:

```go
// Page descriptions, surfaced as <meta name="description"> + og:description by
// shared/templates/partials/head.html via the "Desc" VM key.
const (
	lookupDesc  = "Look up any IP: geolocation, ASN, VPN/proxy/Tor and blocklist reputation, and open ports. Or inspect your own connection. Free, open source, with a curl-able JSON API."
	cidrDesc    = "CIDR subnet calculator: network range, broadcast address, netmask, and host counts for any CIDR. Free, open source, JSON API included."
	historyDesc = "Recent IP lookups made from this browser."
)
```

Then five map edits (only the changed line shown, rest of the map unchanged):

1. The empty-lookup render (`"Title": "IP Tools", "Active": "lookup", "Query": "", …`):
   → `"Title": "IP Tools", "Desc": lookupDesc, "Active": "lookup", "Query": "", "Attribution": true, "Conn": platform.Conn(c),`
2. The empty-cidr render (:78):
   → `map[string]any{"Title": "Subnet calculator", "Desc": cidrDesc, "Active": "cidr", "Query": ""}`
3. The cidr result vm (:87):
   → `vm := map[string]any{"Title": "Subnet calculator", "Desc": cidrDesc, "Active": "cidr", "Query": input}`
4. The history vm (:116-119): first line becomes
   → `"Title": "Lookup history", "Desc": historyDesc, "Active": "history",`
5. The show vm (:177):
   → `vm := map[string]any{"Title": "IP Tools", "Desc": lookupDesc, "Active": "lookup", "Query": ip, "Self": self, "Attribution": true}`

- [ ] **Step 9: Format, run tests and vet**

Run: `gofmt -w site/site.go tools/botcheck/handler.go tools/iptools/handler.go site/tests/site_test.go tools/botcheck/tests/handler_test.go tools/iptools/tests/handler_test.go && go vet ./... && go test ./... 2>&1 | tail -20`
Expected: vet clean; all packages `ok` (including the three new tests).

- [ ] **Step 10: Commit**

```bash
git add shared/templates/partials/head.html site/site.go tools/botcheck/handler.go tools/iptools/handler.go site/tests/site_test.go tools/botcheck/tests/handler_test.go tools/iptools/tests/handler_test.go docs/superpowers/specs/2026-07-26-pre-launch-og-design.md
git commit -m "Add OpenGraph/Twitter meta tags with per-page descriptions"
```

---

### Task 2: Capture the raw "caught red-handed" screenshot

**Files:**
- Create: `automation-harness/og-screenshot.mjs` (gitignored directory — local tooling, never committed)
- Produces: `automation-harness/og-raw.png` (consumed by Task 3)

**Interfaces:**
- Consumes: live `https://botcheck.corpberry.com/` (check auto-runs on page load; result fragment lands in `#result [data-score]` — same selector the existing harness probes wait on).
- Produces: PNG at path printed on stdout, read by Task 3's `compose-og.py` constant `RAW`.

- [ ] **Step 1: Write the screenshot script**

Create `automation-harness/og-screenshot.mjs`:

```js
// One-off marketing asset: screenshot the LIVE botcheck verdict for the
// social-preview / OG card. Headless Chromium trips bot checks on purpose —
// that's the "caught red-handed" shot the launch checklist wants.
// Output: automation-harness/og-raw.png (consumed by compose-og.py).
import puppeteer from "puppeteer";

const TARGET = "https://botcheck.corpberry.com/";
const OUT = new URL("./og-raw.png", import.meta.url).pathname;

async function main() {
  const browser = await puppeteer.launch({ headless: true });
  try {
    const page = await browser.newPage();
    // 2x scale so the screenshot stays crisp when scaled into the card.
    await page.setViewport({ width: 1280, height: 800, deviceScaleFactor: 2 });
    await page.goto(TARGET, { waitUntil: "networkidle0" });
    // Same completion signal the other harness probes use: scored fragment in DOM.
    await page.waitForSelector("#result [data-score]", { timeout: 30000 });
    await page.screenshot({ path: OUT });
    console.log("saved", OUT);
  } finally {
    await browser.close();
  }
}

main().catch((e) => {
  console.error("FATAL", e);
  process.exit(1);
});
```

- [ ] **Step 2: Run it**

Run: `cd automation-harness && node og-screenshot.mjs`
Expected: `saved /Users/user/Documents/projects/site-of-tools/automation-harness/og-raw.png` within ~30 s.
Fallback if Cloudflare challenges the headless browser (timeout waiting for `#result [data-score]`): run the dev server (`go run .` — harness probes use `http://botcheck.localhost:8080/`), set `TARGET` to that URL, re-run.

- [ ] **Step 3: Verify the image**

Open `automation-harness/og-raw.png` with the image reader.
Expected: botcheck page with a rendered verdict (score + per-signal breakdown). If the verdict is missing, do not proceed — re-run Step 2.

(No commit — `automation-harness/` is gitignored.)

---

### Task 3: Compose the 1280×640 branded card

**Files:**
- Create: `automation-harness/compose-og.py` (gitignored — local tooling)
- Create: `shared/static/img/og-cover.png` (committed — served as og:image)
- Create: `docs/assets/social-preview.png` (committed — for GitHub upload)

**Interfaces:**
- Consumes: `automation-harness/og-raw.png` from Task 2.
- Produces: two identical 1280×640 PNGs at the paths above; `og:image` tags from Task 1 point at the deployed URL of the first one.

- [ ] **Step 1: Create the venv and install Pillow**

Run: `python3 -m venv automation-harness/.venv && automation-harness/.venv/bin/pip install pillow 2>&1 | tail -2`
Expected: `Successfully installed pillow-…` (nothing installed globally; venv lives inside the gitignored harness dir).

- [ ] **Step 2: Write the compose script**

Create `automation-harness/compose-og.py`:

```python
#!/usr/bin/env python3
"""Compose the 1280x640 social-preview / og:image card for Bot check.

Input:  automation-harness/og-raw.png (raw puppeteer screenshot, Task 2)
Output: shared/static/img/og-cover.png   (served as og:image)
        docs/assets/social-preview.png   (uploaded to GitHub social preview)

Layout: dark canvas; left panel = accent bar, title, tagline, URL;
right panel = screenshot in a rounded, bordered frame.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "automation-harness" / "og-raw.png"
OUT_STATIC = ROOT / "shared" / "static" / "img" / "og-cover.png"
OUT_DOCS = ROOT / "docs" / "assets" / "social-preview.png"

W, H = 1280, 640
BG = (15, 23, 42)        # slate-900
FG = (248, 250, 252)     # slate-50
MUTED = (148, 163, 184)  # slate-400
ACCENT = (184, 50, 102)  # #b83266 — site favicon/brand color
FRAME = (51, 65, 85)     # slate-700

TITLE = "Bot check"
TAGLINE = ("A live score of how much your browser looks like a human vs. "
           "an automated bot. Open source — shows every signal it checks.")
URL = "botcheck.corpberry.com"

FONT_REGULAR = ["/System/Library/Fonts/Supplemental/Arial.ttf",
                "/System/Library/Fonts/Helvetica.ttc"]
FONT_BOLD = ["/System/Library/Fonts/Supplemental/Arial Bold.ttf",
             "/System/Library/Fonts/Helvetica.ttc"]


def font(paths, size):
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()


def wrap(draw, text, fnt, width):
    lines, cur = [], ""
    for word in text.split():
        trial = (cur + " " + word).strip()
        if draw.textlength(trial, font=fnt) <= width:
            cur = trial
        else:
            lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def rounded(img, radius):
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, *img.size], radius=radius, fill=255)
    out = img.convert("RGBA")
    out.putalpha(mask)
    return out


def main():
    card = Image.new("RGBA", (W, H), BG + (255,))
    draw = ImageDraw.Draw(card)

    # Left panel.
    x, y = 64, 120
    draw.rectangle([x, y, x + 64, y + 8], fill=ACCENT)
    y += 48
    draw.text((x, y), TITLE, font=font(FONT_BOLD, 76), fill=FG)
    y += 116
    f_tag = font(FONT_REGULAR, 30)
    for line in wrap(draw, TAGLINE, f_tag, 500):
        draw.text((x, y), line, font=f_tag, fill=MUTED)
        y += 42
    y += 56
    draw.text((x, y), URL, font=font(FONT_BOLD, 30), fill=ACCENT)

    # Right panel: framed screenshot (560 px wide, keeps aspect → 350 px tall
    # for the 1280x800 source; vertically centered).
    shot = Image.open(RAW).convert("RGBA")
    fw = 560
    fh = shot.height * fw // shot.width
    shot = rounded(shot.resize((fw, fh), Image.LANCZOS), 16)
    sx, sy = W - fw - 64, (H - fh) // 2
    border = Image.new("RGBA", (fw + 8, fh + 8), (0, 0, 0, 0))
    ImageDraw.Draw(border).rounded_rectangle([0, 0, fw + 8, fh + 8], radius=20, fill=FRAME + (255,))
    card.paste(border, (sx - 4, sy - 4), border)
    card.paste(shot, (sx, sy), shot)

    OUT_STATIC.parent.mkdir(parents=True, exist_ok=True)
    OUT_DOCS.parent.mkdir(parents=True, exist_ok=True)
    card.convert("RGB").save(OUT_STATIC, optimize=True)
    card.convert("RGB").save(OUT_DOCS, optimize=True)
    print(f"wrote {OUT_STATIC} and {OUT_DOCS} ({W}x{H})")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run it**

Run: `automation-harness/.venv/bin/python automation-harness/compose-og.py`
Expected: `wrote …/shared/static/img/og-cover.png and …/docs/assets/social-preview.png (1280x640)`

- [ ] **Step 4: Verify the card**

Open `shared/static/img/og-cover.png` with the image reader.
Expected: 1280×640, dark background; left = pink accent bar, "Bot check", 3–4 line tagline, "botcheck.corpberry.com" in pink; right = framed screenshot, nothing clipped. If text overflows or the screenshot is wrong, fix constants and re-run (iterate until it looks right — this is the launch's share image).

- [ ] **Step 5: Commit**

```bash
git add shared/static/img/og-cover.png docs/assets/social-preview.png
git commit -m "Add 1280x640 social-preview/OG cover image"
```

---

### Task 4: Apply GitHub About + topics

**Files:** none (remote metadata only, via authenticated `gh`).

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: repo description/homepage/topics visible on GitHub.

- [ ] **Step 1: Apply**

```bash
gh repo edit Landver/site-of-tools \
  --description "Open-source bot-detection self-test: 68 signals, every check shown, client + server + IP cross-checked. Plus IP tools — one Go/htmx binary, zero npm." \
  --homepage "https://botcheck.corpberry.com" \
  --add-topic bot-detection,browser-fingerprinting,fingerprinting,anti-bot,go,golang,htmx,web-scraping,security,privacy,echo
```

Expected: exits 0 (gh prints the repo URL or nothing).

- [ ] **Step 2: Verify**

Run: `gh repo view --json description,homepageUrl,repositoryTopics -q '{desc: .description, home: .homepageUrl, topics: [.repositoryTopics[].name]}'`
Expected: `desc` and `home` match Step 1; `topics` lists all 11 names.

(No commit.)

---

### Task 5: Upload the GitHub social-preview image via kimi-webbridge

**Files:** none (browser action; user chose webbridge over manual upload).

**Interfaces:**
- Consumes: `docs/assets/social-preview.png` from Task 3 (absolute path: `/Users/user/Documents/projects/site-of-tools/docs/assets/social-preview.png`).
- Produces: repo social preview set on GitHub.

- [ ] **Step 1: Invoke the kimi-webbridge skill** and read its connection instructions (it drives the user's real browser with their GitHub session).

- [ ] **Step 2: Navigate to `https://github.com/Landver/site-of-tools/settings`.**

- [ ] **Step 3: In "Social preview", click Edit/Upload, select `/Users/user/Documents/projects/site-of-tools/docs/assets/social-preview.png`, and save.** (If a file-chooser dialog can't be driven, fall back: tell the user the exact image path and have them drop it in — 30 seconds.)

- [ ] **Step 4: Verify** — screenshot the settings section; the new card should render as the preview thumbnail.

(No commit.)

---

### Task 6: Checklist bookkeeping + FAQ crib

**Files:**
- Modify: `promo/README.md:37-39` (Step 0 checkboxes — `promo/` is untracked, no commit)
- Modify: `promo/01-pre-launch-checklist.md` items 4 & 5 (mark DONE, mirroring the style of items 1–3)

**Interfaces:**
- Consumes: completed Tasks 1–5.
- Produces: up-to-date launch playbook; final summary carries the FAQ crib.

- [ ] **Step 1: Tick the checkboxes in `promo/README.md`**

Change:

```markdown
- [ ] Set GitHub **About + topics + social-preview image**.
- [ ] Add **OpenGraph tags** so links unfurl nicely.
- [ ] Skim the **FAQ** in [00-message-kit.md](00-message-kit.md) so you can answer fast.
```

to:

```markdown
- [x] Set GitHub **About + topics + social-preview image**.
- [x] Add **OpenGraph tags** so links unfurl nicely.
- [x] Skim the **FAQ** in [00-message-kit.md](00-message-kit.md) so you can answer fast — condensed crib delivered 2026-07-26.
```

- [ ] **Step 2: Mark items 4 and 5 DONE in `promo/01-pre-launch-checklist.md`**

Change the `## 🟡 4.` heading to `## ✅ 4. Set the GitHub repo "About" + topics + social preview — DONE (2026-07-26)` and prepend a status line: `About/homepage/topics applied via gh; 1280×640 card at docs/assets/social-preview.png, uploaded to repo social preview.`. Same for `## 🟡 5.` → `## ✅ 5. Add OpenGraph / preview tags to the sites — DONE (2026-07-26)` with status line: `OG/Twitter tags live in shared/templates/partials/head.html w/ per-page "Desc"; og:image = https://corpberry.com/static/img/og-cover.png. Goes live on next deploy.`

- [ ] **Step 3: Final gate**

Run: `go vet ./... && go test ./... 2>&1 | tail -10`
Expected: all `ok`, vet clean.

- [ ] **Step 4: Deliver the final summary** — what changed, what went where, the FAQ crib (7 condensed Q&As from `promo/00-message-kit.md`), and the reminder that OG tags + og-cover.png go live on the next deploy.

(No commit — `promo/` is untracked by design; user's call whether to track it.)

---

## Self-Review Notes

- **Spec coverage:** A → Task 4; B → Tasks 2–3; C → Task 1; D → Task 5; E → Task 6 (crib in final summary); verification commands present in Tasks 1, 3, 4, 6. ✓
- **Placeholders:** none — all code/scripts/commands complete.
- **Type consistency:** `"Desc"` key name identical in template (`{{or .Desc …}}`), all handler maps, and spec; description strings byte-identical between `handler.go`/`site.go` and test assertions; `lookupDesc`/`cidrDesc`/`historyDesc` const names match between definition (Step 8 const block) and usages.
