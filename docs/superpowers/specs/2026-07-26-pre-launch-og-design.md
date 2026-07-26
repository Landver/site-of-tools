# Pre-launch Step 0 remainder: GitHub metadata, social card, OG tags

Date: 2026-07-26. Status: approved by user (design presented in session, approved with
"webbridge uploads preview" option).

Scope: the three open items from `promo/01-pre-launch-checklist.md` Step 0 —
GitHub About/topics/social-preview, OpenGraph tags, FAQ skim. Everything else in the
checklist is out of scope.

## A. GitHub About + topics

Applied with `gh repo edit Landver/site-of-tools` (gh CLI already authed as Landver,
`repo` scope):

- Description: `Open-source bot-detection self-test: 68 signals, every check shown, client + server + IP cross-checked. Plus IP tools — one Go/htmx binary, zero npm.`
- Homepage: `https://botcheck.corpberry.com`
- Topics: `bot-detection, browser-fingerprinting, fingerprinting, anti-bot, go, golang, htmx, web-scraping, security, privacy, echo`

Rationale: launch playbook says botcheck is the star and leads every channel; description
leads with it but mentions IP tools since the repo covers both. Topics list is verbatim
from the checklist.

## B. 1280×640 composed branded card

One PNG serves two consumers: GitHub social preview (1280×640 recommended) and the
sites' `og:image` (1200×630 recommended — 1280×640 is accepted by all target crawlers).

Pipeline:

1. `automation-harness/og-screenshot.mjs` — new puppeteer script (reuses the harness's
   existing node_modules + `.chromium-cache`) that loads `https://botcheck.corpberry.com`,
   waits for the verdict UI to render, and saves a raw screenshot. Headless Chromium
   scores as a bot — this is the "caught red-handed" asset the checklist calls the best
   marketing image. Runs against the live site; no local server needed.
2. Compose the card with Python/Pillow in a venv created inside the working directory
   (nothing installed globally): dark left panel with `Bot check` title, tagline from
   `promo/00-message-kit.md` ("A live score of how much your browser looks like a human
   vs. an automated bot. Open source — shows every signal it checks."), and the URL
   `botcheck.corpberry.com`; screenshot in a framed window on the right.
3. Outputs:
   - `shared/static/img/og-cover.png` — served by every subdomain (each app mounts the
     shared static FS), referenced by `og:image` as the stable, unversioned absolute URL
     `https://corpberry.com/static/img/og-cover.png` (apex always resolves; no `?v=` hash
     so the URL stays stable for crawler caches).
   - `docs/assets/social-preview.png` — copy for the GitHub social-preview upload.

## C. OG / Twitter meta tags

Single template edit in `shared/templates/partials/head.html` — that partial is included
by every full page (apex home, botcheck index, ip index/cidr/history); result templates
are htmx fragments without `<head>` and are unaffected.

Tags added:

- `<meta name="description">`
- `og:type=website`, `og:title` (reuses `.Title`), `og:description` (new `.Desc`),
  `og:image` (apex URL above), `og:site_name=corpberry.com`
- `twitter:card=summary_large_image`, `twitter:title`, `twitter:description`, `twitter:image`

Per-page descriptions come from a new `"Desc"` key added to every handler map that
renders a full page: `site/site.go` (apex home), `tools/botcheck/handler.go` (botcheck
index), and `tools/iptools/handler.go` (ip index, both cidr renders, history, and the
lookup-result render when it produces a full page). Head partial uses
`{{or .Desc "<generic fallback>"}}` so fragment renders and tests that omit `Desc` still
work.

Deliberately omitted: `og:url` (correct value varies per subdomain and handlers don't
pass the request URL; not worth plumbing for launch), `twitter:site` (no known handle —
don't invent one).

## D. Social-preview upload

GitHub has no API for the social-preview image. User chose: upload via the
`kimi-webbridge` skill driving their real browser (repo → Settings → General → Social
preview → upload `docs/assets/social-preview.png`).

## E. FAQ skim

Checklist item is for the user (rehearse answers). Deliverable from my side: a condensed
crib of the 7 FAQ answers in `promo/00-message-kit.md`, included in the final summary.

## Verification

- `go vet ./... && go test ./...` after the template/handler edits.
- Render check: run the app in dev and `curl` each host's `/` HTML, grep for the og
  tags (or assert via existing Go tests if simpler).
- Read the composed PNG back (image tool) to confirm it looks right before uploading.
- `gh repo view --json description,homepageUrl,repositoryTopics` to confirm A applied.

Deployment note: OG tags + `og-cover.png` go live on the user's next deploy; nothing in
this change deploys anything.
