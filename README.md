# FOOTPRINT // Recon Toolbox v2

A local, zero-dependency dashboard for auditing **your own** digital footprint — so you know what's exposed before someone else finds it. Built for cybersecurity / HTB-style self-audit with a full terminal-hacker aesthetic (CRT scanlines, boot sequence, command REPL). No AI, no external SDKs — the "intelligence" is deterministic engines: a self-calibrating scanner, a rule-based correlation engine, and a handle-permutation generator.

```
npm start          # or: node server.js
→ http://localhost:1337
```

Requires Node.js 18+ (built-in `fetch`). Nothing to install. Binds to `127.0.0.1` only.

## Tools

| Tab | What it does |
|---|---|
| **★ FOOTPRINT** | The headline aggregator. Enter any identifiers → it runs every source, **fetches and scrapes the discovered pages/endpoints one by one**, extracts the actual data (emails, phones, names, locations, linked accounts via regex + JSON-LD), **scores each page for how likely it's actually you** (entity-resolution algorithm), filters out the noise, checks the **dark web** (Ahmia) and **Wayback Machine** (deleted/archived versions), correlates everything with per-fact source counts, and **pivots** on new leads. Streams live over SSE into one consolidated, exportable dossier. |

### Relevance / entity-resolution scoring
Every scraped page and search result is scored 0–100 for how likely it's about *you*: your identifiers (name, city, email, phone, username, employer) are weighted by how uniquely they identify someone — matching a rare **username/email/phone (~40 pts)** ≫ a **common first name (~3 pts)** — with a **co-occurrence multiplier** (2–3 strong identifiers together ≈ certain) and a common-name penalty. Pages scoring below the threshold are discarded so other people's data doesn't pollute your dossier. Add **EMPLOYER/SCHOOL** for sharper disambiguation.

### Deep web (Tor)
- **No Tor needed:** dark-web mentions are searched via **Ahmia**, which indexes `.onion` sites and is reachable over clearnet.
- **To fetch `.onion` page contents:** run the Tor daemon (SOCKS on `127.0.0.1:9050`) and start with `TOR=1 node server.js` — onion fetches route through the system `curl --socks5-hostname` (no npm dependency). `TOR_SOCKS=host:port` overrides the address.
| **EMAIL** | Gravatar avatar check **plus a full public-profile pivot** (real name, username, location, bio, linked accounts from one MD5 hash) **plus live DNS/mail intelligence** — MX host + provider fingerprint, SPF/DMARC posture, disposable/freemail/custom-domain classification, and a WHOIS pivot for custom domains. Optional HIBP breach lookup. |
| **PHONE** | Number intel with **real NANP area-code geolocation** (300+ codes → city/state/timezone), line-type classification, every searchable format, and a **persistent data-broker opt-out campaign tracker** — check off each of 10 brokers as you file, with auto-generated CCPA/GDPR deletion emails. |
| **USERNAME** | **QUICK**: 15 API-grade probes in seconds. **FULL SWEEP**: 450+ platforms via the live [Sherlock](https://github.com/sherlock-project/sherlock) database, streamed over SSE. Every confirmed account is **deep-enriched** — the tool reads the actual public profile behind it (real name, location, bio, join date, follower counts, and linked accounts including Keybase cryptographic proofs), then a **cross-platform synthesis** folds it into one picture: which real name/location recur across platforms, and which *other* identities the accounts link to. |
| **PASSWORD** | **k-anonymity check** against the 800M+ Pwned Passwords corpus. The password is SHA-1'd in your browser; only the first **5 hash characters** ever leave the page (server proxies the range query with padding). The protocol is printed live so you can audit that nothing sensitive is transmitted. Free, no API key. |
| **CARD** | **100% in-browser** — the number never hits the network (verify in devtools). Luhn + BIN/network identification, then a guided audit of every place a card is typically stored, with removal links. |
| **SELF** | Fingerprints this browser the way ad-tech does — canvas + WebGL hashes, font enumeration, WebRTC local-IP leak test, screen/hardware entropy — and computes a **trackability score** (bits of entropy → "1 in N browsers"). Fully local. |
| **PROFILE** | Runs every scan in parallel, then: computes a 0–100 exposure score, renders a **force-directed identity link graph** (canvas, draggable, click nodes to open), runs a **correlation engine** that explains how the identifiers connect, generates **handle permutations** to scan, builds a Google-dork pack, and exports a printable **dossier**. |
| **FRAMEWORK** | The full [OSINT Framework](https://osintframework.com/) as a contextual launcher — 140+ tools across 20 categories (username, email, domain, IP, images, social, people-search, phone, public/business records, dark web, geolocation, metadata, threat-intel, crypto, and more). Type a target and it's auto-injected into every query-able tool; filter the tree live. |

**More retrieval tools folded into the tabs above:**
- **Email → registered accounts** (Holehe-style): checks signup/validation endpoints (Spotify, GitHub, Pinterest, Imgur) to reveal where an email is registered — no login, no mail sent.
- **Certificate transparency** (crt.sh): custom-domain emails → all subdomains/hosts from public CT logs.
- **Reverse image search**: your Gravatar/avatar → one-click Yandex/Google Lens/Bing/TinEye lookups.
- **Phone carrier/line-type** (PhoneInfoga-style): area-code geolocation always; live carrier + line-type with `NUMVERIFY_KEY`.
- **Property / voter / court dorks** added to the name-recon set.

### Command REPL
Press **`/`** anywhere to focus the command bar. `help`, `email x@y.com`, `user torvalds full`, `phone +1…`, `pw`, `self`, `history`, `clear`. Up/down arrows recall history.

## What makes the scanner trustworthy (not just big)

Most username checkers report false positives because many sites return HTTP 200 for missing profiles (soft-404s) or serve bot-challenge pages that look like hits. FOOTPRINT defends against both:

1. **Control-probe calibration** — before trusting a "found", it probes the *same site* with a random gibberish handle. If garbage also reads "exists", the site is a soft-404 and the result is demoted to inconclusive.
2. **Challenge-page detection** — any positive whose body matches known interstitials (Cloudflare, DataDome, PerimeterX, hCaptcha…) is rejected.
3. **Reproducibility guard** — a positive must reproduce on a second probe, killing flaky detectors.

Verified: a full 465-site sweep on a random gibberish handle returns **zero** false positives, while `torvalds` surfaces 89 real accounts.

## Timeline

Every scan is snapshotted to `data/history.json`. Re-scanning the same target diffs against the previous snapshot — **`+ NEW`** / **`− GONE`** — so you can watch your footprint drift over time. This is the one thing no one-shot web tool can do.

## Optional: real email-breach lookups

The [HaveIBeenPwned account API](https://haveibeenpwned.com/API/Key) needs a paid key. Without it, the email tab links you to the free web check — and the **password** tab works fully key-free via k-anonymity.

```
HIBP_API_KEY=your-key node server.js
```

## Honest limitations (by design)

- **Card → "which sites stored it"**: no legitimate public database maps card numbers to merchants — anything claiming to is a scam or a criminal checker. The tool audits where cards actually live (your wallets/autofill) and points you to bank alerts, the only real feed.
- **Big social platforms** (Instagram, Facebook, LinkedIn, TikTok…) block automated checks; you get one-click manual verification links instead of guesses.
- FULL SWEEP results marked **inconclusive** mean the site rate-limited or challenged the probe — verify via the provided link.

## Files
`server.js` (recon engines + SSE + proxies) · `public/index.html` · `public/styles.css` · `public/app.js` (client + all renderers) · `public/graph.js` (force-directed graph). Runtime data in `data/` (gitignored): the Sherlock DB cache and scan history.

## Ethics
For **self-audit and authorized assessments only**. The same lookups are available to anyone — the point is to run them on yourself first, then close the holes with the opt-out, deletion, and hardening links the toolbox gives you.
