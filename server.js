#!/usr/bin/env node
/**
 * FOOTPRINT — Recon Toolbox (local self-audit dashboard)
 *
 * Zero-dependency Node.js server. Serves the dashboard and exposes recon
 * APIs for auditing YOUR OWN digital footprint.
 *
 * Engines:
 *  - Username scanner: Sherlock site database (400+ platforms, fetched at boot,
 *    disk-cached) + curated core checks, streamed live over SSE, with
 *    control-probe calibration — every positive is re-verified against a random
 *    gibberish handle on the same site, so soft-404 sites can't fake a FOUND.
 *  - Email recon: Gravatar avatar + full public-profile pivot, optional HIBP.
 *  - Password exposure: k-anonymity proxy to the Pwned Passwords range API
 *    (browser sends a 5-char SHA-1 prefix; the password never leaves the page).
 *  - Timeline: every scan snapshotted to data/history.json; re-scans diff
 *    against the previous snapshot for the same target.
 *
 * Privacy: binds to 127.0.0.1. Card tool is 100% client-side.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;

const PORT = process.env.PORT || 1337;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const HIBP_KEY = process.env.HIBP_API_KEY || '';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// Full realistic browser header set — many "blocks" are just missing headers.
const BROWSER_HEADERS = {
  'User-Agent': UA,
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
  'Sec-Ch-Ua-Mobile': '?0',
  'Sec-Ch-Ua-Platform': '"Windows"',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Upgrade-Insecure-Requests': '1',
};

// Optional: route requests through your own residential/VPN proxy to beat
// datacenter-IP blocks (e.g. RECON_PROXY=http://user:pass@host:port).
const PROXY = process.env.RECON_PROXY || '';
let PROXY_DISPATCHER = null;
if (PROXY) {
  try { PROXY_DISPATCHER = new (require('undici').ProxyAgent)(PROXY); }
  catch (e) { console.warn('proxy setup failed:', e.message); }
}

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------------------------------------------------------------- helpers */

async function probe(url, { method = 'GET', headers = {}, body = null, wantBody = false, redirect = 'follow', timeout = 7000, browser = false } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const baseHeaders = browser ? BROWSER_HEADERS : { 'User-Agent': UA, Accept: '*/*' };
    const opts = {
      method,
      headers: { ...baseHeaders, ...headers },
      body,
      redirect,
      signal: ctrl.signal,
    };
    if (PROXY_DISPATCHER) opts.dispatcher = PROXY_DISPATCHER;
    const res = await fetch(url, opts);
    const text = wantBody ? await res.text() : '';
    return { status: res.status, body: text };
  } catch (err) {
    return { status: 0, error: err.name === 'AbortError' ? 'timeout' : err.message.slice(0, 80) };
  } finally {
    clearTimeout(timer);
  }
}

// Web search via DuckDuckGo's HTML endpoint (no key). Returns parsed results
// with real titles + snippets — used to reach bot-walled sites (LinkedIn,
// Facebook, data brokers) *through* the search engine, and to surface what the
// open web actually says about an identifier.
async function searchWeb(query, limit = 6) {
  const r = await probe(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, { wantBody: true, browser: true, timeout: 12000 });
  if (r.status !== 200 || !r.body) return [];
  const out = [];
  const snips = [];
  const snipRe = /class="result__snippet"[^>]*>(.*?)<\/a>/gs;
  let sm;
  while ((sm = snipRe.exec(r.body))) snips.push(stripHtml(sm[1]));
  const linkRe = /class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)<\/a>/gs;
  let m, i = 0;
  while ((m = linkRe.exec(r.body)) && out.length < limit) {
    let url = m[1];
    const ud = url.match(/uddg=([^&]+)/);
    if (ud) { try { url = decodeURIComponent(ud[1]); } catch { /* keep */ } }
    if (url.startsWith('//')) url = 'https:' + url;
    const title = stripHtml(m[2]);
    if (title) out.push({ title, url, snippet: snips[i] || '' });
    i++;
  }
  return out;
}

// Search-mediated identity recon: reach blocked platforms via `site:` dorks and
// return the actual result snippets (which often contain the data itself).
async function nameRecon(name, city) {
  const loc = city ? ` ${city}` : '';
  const dorks = [
    { label: 'LinkedIn', query: `site:linkedin.com/in "${name}"${loc}` },
    { label: 'Facebook', query: `site:facebook.com "${name}"${loc}` },
    { label: 'People-search brokers', query: `(site:fastpeoplesearch.com OR site:truepeoplesearch.com OR site:spokeo.com OR site:thatsthem.com) "${name}"${loc}` },
    { label: 'Open web', query: city ? `"${name}" ${city}` : `"${name}"` },
    { label: 'Documents (CV / rosters / PDFs)', query: `"${name}" (resume OR cv OR filetype:pdf)` },
  ];
  return Promise.all(dorks.map(async d => ({ label: d.label, query: d.query, results: await searchWeb(d.query, 5) })));
}

// Public & government records — real free sources (SEC EDGAR full-text,
// CourtListener federal/state cases) plus search-mediated dorks into county
// property/voter/business-registration sites that don't expose an API.
async function publicRecords(name, city) {
  const q = `"${name}"`;
  const [edgar, courts, business, gov] = await Promise.allSettled([
    // SEC EDGAR full-text search — corporate/financial filings naming the person.
    (async () => {
      const r = await probe(`https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(q)}`, {
        wantBody: true, timeout: 12000,
        headers: { 'User-Agent': 'footprint-recon self-audit (local tool)', Accept: 'application/json' },
      });
      if (r.status !== 200) return [];
      const hits = (JSON.parse(r.body).hits?.hits) || [];
      return hits.slice(0, 5).map(h => {
        const s = h._source || {};
        return {
          title: (s.display_names || []).join(', ') || 'SEC filing',
          detail: `${s.file_type || s.root_form || 'filing'} · ${s.file_date || '?'}`,
          url: `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=${encodeURIComponent(name)}&type=&dateb=&owner=include&count=40`,
        };
      });
    })(),
    // CourtListener — federal & state court opinions/dockets (RECAP).
    (async () => {
      const r = await probe(`https://www.courtlistener.com/api/rest/v4/search/?q=${encodeURIComponent(q)}&type=o&order_by=score%20desc`, {
        wantBody: true, timeout: 12000, headers: { Accept: 'application/json' },
      });
      if (r.status !== 200) return { count: 0, items: [] };
      const j = JSON.parse(r.body);
      return {
        count: j.count || 0,
        items: (j.results || []).slice(0, 5).map(c => ({
          title: c.caseName || c.case_name || 'case',
          detail: `${c.court || c.court_id || ''} · ${(c.dateFiled || c.date_filed || '').slice(0, 10)}`,
          url: c.absolute_url ? 'https://www.courtlistener.com' + c.absolute_url : 'https://www.courtlistener.com/?q=' + encodeURIComponent(q),
        })),
      };
    })(),
    // Business registrations / company officers (OpenCorporates has no free API
    // key anymore — reach it through search).
    searchWeb(`site:opencorporates.com "${name}"`, 4),
    // Government + property/voter records via search-mediated dorks.
    searchWeb(`("${name}"${city ? ` ${city}` : ''}) (site:.gov OR "property records" OR "voter" OR "assessor" OR "case number")`, 6),
  ]);

  return {
    sec: edgar.status === 'fulfilled' ? edgar.value : [],
    courts: courts.status === 'fulfilled' ? courts.value : { count: 0, items: [] },
    business: business.status === 'fulfilled' ? business.value : [],
    government: gov.status === 'fulfilled' ? gov.value : [],
  };
}

// Free, keyless breach intelligence via XposedOrNot — breach names, exposed
// data categories, risk score, and password-strength breakdown.
async function xonBreaches(email) {
  const r = await probe(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`, { wantBody: true, timeout: 12000 });
  if (r.status !== 200) return { count: 0, breaches: [], risk: null, passwordStrength: null };
  let j;
  try { j = JSON.parse(r.body); } catch { return null; }
  const details = (j.ExposedBreaches && j.ExposedBreaches.breaches_details) || [];
  const riskArr = j.BreachMetrics && j.BreachMetrics.risk;
  const pwArr = j.BreachMetrics && j.BreachMetrics.passwords_strength;
  return {
    count: details.length,
    breaches: details.map(b => ({
      name: b.breach,
      date: b.xposed_date || null,
      domain: b.domain || null,
      industry: b.industry || null,
      dataClasses: (b.xposed_data || '').split(';').map(s => s.trim()).filter(Boolean),
      passwordRisk: b.password_risk || null,
      verified: b.verified === 'Yes',
      desc: b.details || null,
    })),
    risk: riskArr && riskArr[0] ? { label: riskArr[0].risk_label, score: riskArr[0].risk_score } : null,
    passwordStrength: pwArr && pwArr[0] ? pwArr[0] : null,
    pastes: (j.ExposedPastes && j.ExposedPastes.pastes_details ? j.ExposedPastes.pastes_details.length : 0),
  };
}

function stripHtml(s) {
  return String(s || '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&#x27;|&#39;/g, "'").replace(/&quot;/g, '"').replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ').trim();
}

async function runPool(items, worker, concurrency, onResult, isCancelled) {
  let cursor = 0;
  const lanes = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      if (isCancelled && isCancelled()) return;
      const idx = cursor++;
      let result;
      try { result = await worker(items[idx], idx); }
      catch (err) { result = { error: err.message }; }
      onResult(result, idx);
    }
  });
  await Promise.all(lanes);
}

/* ----------------------------------------------- core sites (API-quality) */

async function byStatus(url) {
  const r = await probe(url);
  if (r.status === 200) return true;
  if (r.status === 404) return false;
  return null;
}

const CORE_SITES = [
  { name: 'GitHub', cat: 'dev', profile: u => `https://github.com/${u}`,
    check: u => byStatus(`https://api.github.com/users/${u}`) },
  { name: 'GitLab', cat: 'dev', profile: u => `https://gitlab.com/${u}`,
    check: async u => {
      const r = await probe(`https://gitlab.com/api/v4/users?username=${u}`, { wantBody: true });
      if (r.status !== 200) return null;
      try { return JSON.parse(r.body).length > 0; } catch { return null; }
    } },
  { name: 'Reddit', cat: 'social', profile: u => `https://www.reddit.com/user/${u}`,
    check: async u => {
      const r = await probe(`https://www.reddit.com/user/${u}/about.json`);
      return r.status === 200 ? true : r.status === 404 ? false : null;
    } },
  { name: 'Hacker News', cat: 'dev', profile: u => `https://news.ycombinator.com/user?id=${u}`,
    check: async u => {
      const r = await probe(`https://hacker-news.firebaseio.com/v0/user/${u}.json`, { wantBody: true });
      if (r.status !== 200) return null;
      return r.body.trim() !== 'null';
    } },
  { name: 'Chess.com', cat: 'gaming', profile: u => `https://www.chess.com/member/${u}`,
    check: u => byStatus(`https://api.chess.com/pub/player/${u}`) },
  { name: 'Lichess', cat: 'gaming', profile: u => `https://lichess.org/@/${u}`,
    check: u => byStatus(`https://lichess.org/api/user/${u}`) },
  { name: 'npm', cat: 'dev', profile: u => `https://www.npmjs.com/~${u}`,
    check: u => byStatus(`https://www.npmjs.com/~${u}`) },
  { name: 'Keybase', cat: 'security', profile: u => `https://keybase.io/${u}`,
    check: async u => {
      const r = await probe(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${u}`, { wantBody: true });
      if (r.status !== 200) return null;
      try { const j = JSON.parse(r.body); return Boolean(j.them && j.them[0]); } catch { return null; }
    } },
  { name: 'Mastodon (.social)', cat: 'social', profile: u => `https://mastodon.social/@${u}`,
    check: u => byStatus(`https://mastodon.social/api/v1/accounts/lookup?acct=${u}`) },
  { name: 'DEV.to', cat: 'dev', profile: u => `https://dev.to/${u}`,
    check: u => byStatus(`https://dev.to/api/users/by_username?url=${u}`) },
  { name: 'Duolingo', cat: 'lifestyle', profile: u => `https://www.duolingo.com/profile/${u}`,
    check: async u => {
      const r = await probe(`https://www.duolingo.com/2017-06-30/users?username=${u}`, { wantBody: true });
      if (r.status !== 200) return null;
      try { return JSON.parse(r.body).users.length > 0; } catch { return null; }
    } },
  { name: 'Vimeo', cat: 'media', profile: u => `https://vimeo.com/${u}`,
    check: u => byStatus(`https://vimeo.com/${u}`) },
  { name: 'SoundCloud', cat: 'media', profile: u => `https://soundcloud.com/${u}`,
    check: u => byStatus(`https://soundcloud.com/${u}`) },
  { name: 'Medium', cat: 'social', profile: u => `https://medium.com/@${u}`,
    check: u => byStatus(`https://medium.com/@${u}`) },
  { name: 'Wikipedia (EN user)', cat: 'social', profile: u => `https://en.wikipedia.org/wiki/User:${u}`,
    check: u => byStatus(`https://en.wikipedia.org/wiki/User:${u}`) },
  // TikTok via its public oEmbed endpoint (clean 200/404 signal, no auth).
  { name: 'TikTok', cat: 'social', profile: u => `https://www.tiktok.com/@${u}`,
    check: async u => {
      const r = await probe(`https://www.tiktok.com/oembed?url=https://www.tiktok.com/@${u}`);
      return r.status === 200 ? true : r.status === 404 ? false : null;
    } },
  // Instagram via the public web_profile_info API + X-IG-App-ID (works from
  // residential IPs — i.e. the user's own machine — even though it 429s from
  // datacenter IPs; calibration + challenge detection guard false positives).
  { name: 'Instagram', cat: 'social', profile: u => `https://www.instagram.com/${u}/`,
    check: async u => {
      const r = await probe(`https://i.instagram.com/api/v1/users/web_profile_info/?username=${u}`, {
        wantBody: true, timeout: 8000,
        headers: { 'X-IG-App-ID': '936619743392459', 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15' },
      });
      if (r.status === 404) return false;
      if (r.status !== 200) return null;
      try { return Boolean(JSON.parse(r.body).data && JSON.parse(r.body).data.user); } catch { return null; }
    } },
];

/* ------------------------------------------------- profile enrichment ----
 * For a CONFIRMED account, pull the actual public profile the platform exposes:
 * real name, location, bio, join date, follower counts, and — critically —
 * any OTHER accounts it links to (Keybase proofs, DEV.to's github/twitter,
 * Mastodon profile fields). This is what turns "you have a GitHub" into a
 * cross-referenced dossier. Each returns a normalized shape or null.
 */

function normEnrich(o) {
  return {
    realName: o.realName || null,
    location: o.location || null,
    bio: o.bio ? String(o.bio).slice(0, 220) : null,
    joined: o.joined || null,
    stats: o.stats || null,
    fields: (o.fields || []).filter(f => f && f.v),
    links: (o.links || []).filter(l => l && l.url),
  };
}

const ENRICHERS = {
  'GitHub': async u => {
    const r = await probe(`https://api.github.com/users/${u}`, { wantBody: true });
    if (r.status !== 200) return null;
    const j = JSON.parse(r.body);
    const links = [];
    if (j.blog) links.push({ platform: 'website', url: j.blog.startsWith('http') ? j.blog : 'https://' + j.blog });
    if (j.twitter_username) links.push({ platform: 'twitter', url: `https://x.com/${j.twitter_username}` });
    return normEnrich({
      realName: j.name, location: j.location, bio: j.bio,
      joined: (j.created_at || '').slice(0, 10),
      stats: `${j.public_repos} repos · ${j.followers} followers · ${j.following} following`,
      fields: [j.company && { k: 'company', v: j.company }, j.email && { k: 'public email', v: j.email },
      j.hireable && { k: 'hireable', v: 'yes' }],
      links,
    });
  },
  'GitLab': async u => {
    const r = await probe(`https://gitlab.com/api/v4/users?username=${u}`, { wantBody: true });
    if (r.status !== 200) return null;
    const j = (JSON.parse(r.body) || [])[0];
    if (!j) return null;
    const links = [];
    if (j.website_url) links.push({ platform: 'website', url: j.website_url });
    if (j.twitter) links.push({ platform: 'twitter', url: `https://x.com/${j.twitter}` });
    if (j.linkedin) links.push({ platform: 'linkedin', url: `https://www.linkedin.com/in/${j.linkedin}` });
    return normEnrich({
      realName: j.name, location: j.location, bio: j.bio,
      joined: (j.created_at || '').slice(0, 10),
      fields: [j.organization && { k: 'org', v: j.organization }, j.job_title && { k: 'title', v: j.job_title }],
      links,
    });
  },
  'Reddit': async u => {
    const r = await probe(`https://www.reddit.com/user/${u}/about.json`, { wantBody: true });
    if (r.status !== 200) return null;
    const d = (JSON.parse(r.body).data) || {};
    const karma = d.total_karma != null ? d.total_karma : (d.link_karma || 0) + (d.comment_karma || 0);
    return normEnrich({
      bio: d.subreddit && stripHtml(d.subreddit.public_description),
      joined: d.created_utc ? new Date(d.created_utc * 1000).toISOString().slice(0, 10) : null,
      stats: `${karma.toLocaleString()} karma`,
      fields: [d.is_gold && { k: 'premium', v: 'yes' }, d.verified != null && { k: 'verified email', v: String(d.verified) },
      d.is_mod && { k: 'moderator', v: 'yes' }],
      links: d.subreddit && d.subreddit.url ? [{ platform: 'reddit', url: 'https://www.reddit.com' + d.subreddit.url }] : [],
    });
  },
  'Hacker News': async u => {
    const r = await probe(`https://hacker-news.firebaseio.com/v0/user/${u}.json`, { wantBody: true });
    if (r.status !== 200 || r.body.trim() === 'null') return null;
    const j = JSON.parse(r.body);
    return normEnrich({
      bio: stripHtml(j.about),
      joined: j.created ? new Date(j.created * 1000).toISOString().slice(0, 10) : null,
      stats: j.karma != null ? `${j.karma.toLocaleString()} karma · ${(j.submitted || []).length} submissions` : null,
    });
  },
  'Chess.com': async u => {
    const r = await probe(`https://api.chess.com/pub/player/${u}`, { wantBody: true });
    if (r.status !== 200) return null;
    const j = JSON.parse(r.body);
    const country = j.country ? j.country.split('/').pop() : null;
    return normEnrich({
      realName: j.name, location: j.location || country,
      joined: j.joined ? new Date(j.joined * 1000).toISOString().slice(0, 10) : null,
      stats: j.followers != null ? `${j.followers.toLocaleString()} followers` : null,
      fields: [j.title && { k: 'title', v: j.title }, country && { k: 'country', v: country },
      j.status && { k: 'account', v: j.status }],
      links: j.url ? [{ platform: 'chess.com', url: j.url }] : [],
    });
  },
  'Lichess': async u => {
    const r = await probe(`https://lichess.org/api/user/${u}`, { wantBody: true });
    if (r.status !== 200) return null;
    const j = JSON.parse(r.body);
    const p = j.profile || {};
    const links = [];
    if (p.links) String(p.links).split(/[\s,]+/).forEach(l => l && links.push({ platform: 'link', url: l.startsWith('http') ? l : 'https://' + l }));
    return normEnrich({
      realName: [p.firstName, p.lastName].filter(Boolean).join(' '),
      location: p.location || p.country, bio: p.bio,
      joined: j.createdAt ? new Date(j.createdAt).toISOString().slice(0, 10) : null,
      stats: j.count ? `${(j.count.all || 0).toLocaleString()} games` : null,
      fields: [j.title && { k: 'title', v: j.title }, p.fideRating && { k: 'FIDE', v: p.fideRating }],
      links,
    });
  },
  'Keybase': async u => {
    const r = await probe(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${u}&fields=profile,proofs_summary`, { wantBody: true });
    if (r.status !== 200) return null;
    const t = ((JSON.parse(r.body).them) || [])[0];
    if (!t) return null;
    const prof = t.profile || {};
    const proofs = (t.proofs_summary && t.proofs_summary.all) || [];
    const links = proofs.map(p => ({ platform: p.proof_type, url: p.service_url || p.proof_url, nametag: p.nametag }));
    return normEnrich({
      realName: prof.full_name, location: prof.location, bio: prof.bio,
      stats: proofs.length ? `${proofs.length} cryptographic identity proofs` : null,
      links,
    });
  },
  'Mastodon (.social)': async u => {
    const r = await probe(`https://mastodon.social/api/v1/accounts/lookup?acct=${u}`, { wantBody: true });
    if (r.status !== 200) return null;
    const j = JSON.parse(r.body);
    const links = (j.fields || []).map(f => {
      const href = (f.value.match(/href="([^"]+)"/) || [])[1];
      return { platform: stripHtml(f.name), url: href || (/^https?:/.test(stripHtml(f.value)) ? stripHtml(f.value) : null) };
    });
    return normEnrich({
      realName: j.display_name, bio: stripHtml(j.note),
      joined: (j.created_at || '').slice(0, 10),
      stats: `${j.followers_count} followers · ${j.statuses_count} posts`,
      links,
    });
  },
  'DEV.to': async u => {
    const r = await probe(`https://dev.to/api/users/by_username?url=${u}`, { wantBody: true });
    if (r.status !== 200) return null;
    const j = JSON.parse(r.body);
    const links = [];
    if (j.twitter_username) links.push({ platform: 'twitter', url: `https://x.com/${j.twitter_username}` });
    if (j.github_username) links.push({ platform: 'github', url: `https://github.com/${j.github_username}` });
    if (j.website_url) links.push({ platform: 'website', url: j.website_url });
    return normEnrich({ realName: j.name, location: j.location, bio: j.summary, joined: j.joined_at, links });
  },
  'Duolingo': async u => {
    const r = await probe(`https://www.duolingo.com/2017-06-30/users?username=${u}`, { wantBody: true });
    if (r.status !== 200) return null;
    const j = (JSON.parse(r.body).users || [])[0];
    if (!j) return null;
    const langs = (j.courses || []).map(c => c.title).join(', ');
    return normEnrich({
      realName: j.name,
      joined: j.creationDate ? new Date(j.creationDate * 1000).toISOString().slice(0, 10) : null,
      stats: `${j.streak || 0}-day streak · ${(j.totalXp || 0).toLocaleString()} XP`,
      fields: [langs && { k: 'learning', v: langs }, j.hasPlus && { k: 'super', v: 'yes' }],
    });
  },
  'TikTok': async u => {
    const r = await probe(`https://www.tiktok.com/oembed?url=https://www.tiktok.com/@${u}`, { wantBody: true });
    if (r.status !== 200) return null;
    const j = JSON.parse(r.body);
    return normEnrich({
      realName: j.author_name, bio: j.title,
      links: j.author_url ? [{ platform: 'tiktok', url: j.author_url }] : [],
    });
  },
  'Instagram': async u => {
    const r = await probe(`https://i.instagram.com/api/v1/users/web_profile_info/?username=${u}`, {
      wantBody: true, timeout: 8000,
      headers: { 'X-IG-App-ID': '936619743392459', 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15' },
    });
    if (r.status !== 200) return null;
    let user;
    try { user = JSON.parse(r.body).data.user; } catch { return null; }
    if (!user) return null;
    const links = [];
    if (user.external_url) links.push({ platform: 'website', url: user.external_url });
    return normEnrich({
      realName: user.full_name, bio: user.biography,
      stats: `${(user.edge_followed_by?.count ?? 0).toLocaleString()} followers · ${(user.edge_owner_to_timeline_media?.count ?? 0).toLocaleString()} posts`,
      fields: [{ k: 'private', v: user.is_private ? 'yes' : 'no' }, user.is_verified && { k: 'verified', v: 'yes' },
      user.business_email && { k: 'business email', v: user.business_email }, user.public_phone_number && { k: 'public phone', v: (user.public_phone_country_code || '') + user.public_phone_number }],
      links,
    });
  },
};

const MANUAL_SITES = [
  { name: 'Facebook', profile: u => `https://www.facebook.com/${u}` },
  { name: 'X / Twitter', profile: u => `https://x.com/${u}` },
  { name: 'LinkedIn', profile: u => `https://www.linkedin.com/in/${u}` },
  { name: 'YouTube', profile: u => `https://www.youtube.com/@${u}` },
  { name: 'Threads', profile: u => `https://www.threads.net/@${u}` },
  { name: 'Snapchat', profile: u => `https://www.snapchat.com/add/${u}` },
  { name: 'Pinterest', profile: u => `https://www.pinterest.com/${u}/` },
  { name: 'Twitch', profile: u => `https://www.twitch.tv/${u}` },
  { name: 'Steam', profile: u => `https://steamcommunity.com/id/${u}` },
  { name: 'Telegram', profile: u => `https://t.me/${u}` },
  { name: 'Spotify', profile: u => `https://open.spotify.com/user/${u}` },
  { name: 'Tumblr', profile: u => `https://${u}.tumblr.com` },
  { name: 'PyPI', profile: u => `https://pypi.org/user/${u}/` },
];

/* -------------------------------------------------- Sherlock site database */

const SHERLOCK_URL = 'https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json';
const SHERLOCK_CACHE = path.join(DATA_DIR, 'sherlock-db.json');
const SHERLOCK_MAX_AGE = 7 * 24 * 3600 * 1000;

let sherlockDB = {};   // { siteName: definition }
let sherlockMeta = { count: 0, source: 'none', fetchedAt: null };

const CORE_NAME_KEYS = new Set(CORE_SITES.map(s => s.name.toLowerCase().replace(/[^a-z]/g, '')));

function usableSherlockSite(name, def) {
  if (name.startsWith('$')) return false;
  if (def.isNSFW) return false;
  if (!def.url || !def.errorType) return false;
  const method = (def.request_method || 'GET').toUpperCase();
  if (method !== 'GET' && !def.request_payload) return false;
  if (CORE_NAME_KEYS.has(name.toLowerCase().replace(/[^a-z]/g, ''))) return false; // core engine covers it better
  return true;
}

async function loadSherlockDB() {
  // fresh disk cache?
  try {
    const cached = JSON.parse(fs.readFileSync(SHERLOCK_CACHE, 'utf8'));
    if (Date.now() - cached.fetchedAt < SHERLOCK_MAX_AGE) {
      sherlockDB = cached.sites;
      sherlockMeta = { count: Object.keys(sherlockDB).length, source: 'disk-cache', fetchedAt: cached.fetchedAt };
      return;
    }
  } catch { /* no cache */ }

  const r = await probe(SHERLOCK_URL, { wantBody: true, timeout: 15000 });
  if (r.status === 200) {
    try {
      const raw = JSON.parse(r.body);
      const sites = {};
      for (const [name, def] of Object.entries(raw)) {
        if (usableSherlockSite(name, def)) sites[name] = def;
      }
      sherlockDB = sites;
      sherlockMeta = { count: Object.keys(sites).length, source: 'live', fetchedAt: Date.now() };
      fs.writeFileSync(SHERLOCK_CACHE, JSON.stringify({ fetchedAt: Date.now(), sites }));
      return;
    } catch { /* fall through */ }
  }
  // stale cache beats nothing
  try {
    const cached = JSON.parse(fs.readFileSync(SHERLOCK_CACHE, 'utf8'));
    sherlockDB = cached.sites;
    sherlockMeta = { count: Object.keys(sherlockDB).length, source: 'stale-cache', fetchedAt: cached.fetchedAt };
  } catch {
    sherlockMeta = { count: 0, source: 'unavailable', fetchedAt: null };
  }
}

function substitutePayload(value, username) {
  if (typeof value === 'string') return value.replaceAll('{}', username);
  if (Array.isArray(value)) return value.map(v => substitutePayload(v, username));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substitutePayload(v, username)]));
  }
  return value;
}

// Anti-bot interstitials (Cloudflare, Fastly, PerimeterX, DataDome...) return
// 200 with a challenge page — which naive checkers read as "profile exists".
// Any positive whose body looks like a challenge is inconclusive, never FOUND.
const CHALLENGE_RE = /client challenge|just a moment|attention required|access denied|verifying you are human|are you a human|unusual traffic|cf-browser-verification|__cf_chl|challenge-platform|perimeterx|datadome|_incapsula_|distil_r_captcha|px-captcha|hcaptcha|g-recaptcha/i;
function looksLikeChallenge(body) {
  return body.length > 0 && body.length < 25000 && CHALLENGE_RE.test(body);
}

// Evaluate one Sherlock site definition. Returns true / false / null (inconclusive).
async function checkSherlockSite(def, username) {
  if (def.regexCheck) {
    try { if (!new RegExp(def.regexCheck).test(username)) return { exists: false, reason: 'handle-format' }; }
    catch { /* bad regex in DB — ignore */ }
  }
  const target = (def.urlProbe || def.url).replaceAll('{}', encodeURIComponent(username));
  const method = (def.request_method || 'GET').toUpperCase();
  const headers = { ...(def.headers || {}) };
  let body = null;
  if (def.request_payload) {
    body = JSON.stringify(substitutePayload(def.request_payload, username));
    if (!headers['Content-Type']) headers['Content-Type'] = 'application/json';
  }
  const redirect = def.errorType === 'response_url' ? 'manual' : 'follow';
  // Always fetch the body: challenge-page detection needs it for every positive.
  const r = await probe(target, { method, headers, body, wantBody: true, redirect, timeout: 6000 });
  if (r.status === 0) return { exists: null, reason: r.error };

  const positive = () => looksLikeChallenge(r.body)
    ? { exists: null, reason: 'bot-challenge page' }
    : { exists: true };

  switch (def.errorType) {
    case 'message': {
      if (r.status >= 500) return { exists: null, reason: `http-${r.status}` };
      const msgs = (Array.isArray(def.errorMsg) ? def.errorMsg : [def.errorMsg]).filter(Boolean);
      if (msgs.some(m => r.body.includes(m))) return { exists: false };
      if (r.status === 404 || r.status === 410) return { exists: false };
      return r.status < 400 ? positive() : { exists: null, reason: `http-${r.status}` };
    }
    case 'response_url': {
      if (r.status >= 200 && r.status < 300) return positive();
      if (r.status >= 300 && r.status < 400) return { exists: false }; // redirected away = no profile
      if (r.status === 404 || r.status === 410) return { exists: false };
      return { exists: null, reason: `http-${r.status}` };
    }
    default: { // status_code
      const errCodes = def.errorCode ? [].concat(def.errorCode) : [404];
      if (errCodes.includes(r.status)) return { exists: false };
      if (r.status >= 200 && r.status < 300) return positive();
      return { exists: null, reason: `http-${r.status}` };
    }
  }
}

/* -------------------------------------- control-probe calibration engine */

// A site only counts as FOUND if a random gibberish handle on the same site
// reads NOT FOUND. Sites that say "found" for garbage are soft-404s and get
// demoted to inconclusive. Calibration results are cached per site.
const calibrationCache = new Map(); // siteName -> true(=soft404) | false(=trustworthy) | null(=couldn't verify)

function controlHandle() {
  return 'zx' + crypto.randomBytes(6).toString('hex') + 'q7';
}

// Run fresh on every positive so the control sees the SAME site state
// (rate-limit interstitials, captchas) as the real probe did. Only permanent
// soft-404 verdicts are cached; healthy verdicts are re-earned each time.
async function calibrate(siteName, checkFn) {
  if (calibrationCache.get(siteName) === true) return true;
  let verdict = null;
  try {
    const control = await checkFn(controlHandle());
    const exists = typeof control === 'object' ? control.exists : control;
    if (exists === true) verdict = true;        // soft-404: garbage "exists" too
    else if (exists === false) verdict = false; // detector healthy right now
    else verdict = null;                        // couldn't verify
  } catch { verdict = null; }
  if (verdict === true) calibrationCache.set(siteName, true);
  return verdict;
}

/* ----------------------------------------------------- unified scan units */

function buildScanUnits(mode) {
  const units = CORE_SITES.map(site => ({
    name: site.name,
    source: 'core',
    profileUrl: u => site.profile(u),
    run: async u => {
      const exists = await site.check(encodeURIComponent(u));
      return { exists };
    },
    calibrator: async () => calibrate(site.name, async ctrl => site.check(ctrl)),
    enrich: ENRICHERS[site.name] ? u => ENRICHERS[site.name](encodeURIComponent(u)) : null,
  }));
  if (mode === 'full') {
    for (const [name, def] of Object.entries(sherlockDB)) {
      units.push({
        name,
        source: 'sherlock',
        profileUrl: u => def.url.replaceAll('{}', encodeURIComponent(u)),
        run: u => checkSherlockSite(def, u),
        calibrator: async () => calibrate(name, ctrl => checkSherlockSite(def, ctrl)),
      });
    }
  }
  return units;
}

async function scanOne(unit, username) {
  const started = Date.now();
  let outcome;
  try { outcome = await unit.run(username); }
  catch (err) { outcome = { exists: null, reason: err.message.slice(0, 60) }; }
  const result = {
    name: unit.name,
    source: unit.source,
    url: unit.profileUrl(username),
    exists: outcome.exists,
    reason: outcome.reason || null,
    verified: null,
    ms: Date.now() - started,
  };
  if (result.exists === true) {
    const soft404 = await unit.calibrator();
    if (soft404 === true) {
      result.exists = null;
      result.reason = 'soft-404 (site claims gibberish handles exist too)';
      return result;
    }
    // Flaky-detector guard: a positive must reproduce on a second probe.
    // Kills sites that nondeterministically serve search/interstitial pages.
    try {
      const again = await unit.run(username);
      if (again.exists !== true) {
        result.exists = null;
        result.reason = 'unreproducible (site answered differently on re-probe)';
        return result;
      }
    } catch { /* keep first reading, mark unverified below */ }
    result.verified = soft404 === false; // control probe confirmed the detector works

    // Deep pull: read the actual public profile behind the confirmed account.
    if (unit.enrich) {
      try {
        const e = await unit.enrich(username);
        if (e && (e.realName || e.location || e.bio || e.joined || e.stats || e.fields.length || e.links.length)) {
          result.enrich = e;
        }
      } catch { /* enrichment is best-effort */ }
    }
  }
  return result;
}

/* -------------------------------------------------------- history / diffs */

const HISTORY_FILE = path.join(DATA_DIR, 'history.json');

function loadHistory() {
  try { return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); } catch { return []; }
}

function saveSnapshot(tool, target, summary) {
  const history = loadHistory();
  const key = `${tool}:${target.toLowerCase()}`;
  const prev = [...history].reverse().find(s => s.key === key) || null;
  const snap = { key, tool, target, ts: Date.now(), summary };
  history.push(snap);
  while (history.length > 300) history.shift();
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 1));

  if (!prev) return { first: true };
  const before = new Set(prev.summary.found || []);
  const after = new Set(summary.found || []);
  return {
    first: false,
    prevTs: prev.ts,
    added: [...after].filter(x => !before.has(x)),
    removed: [...before].filter(x => !after.has(x)),
  };
}

/* --------------------------------------------------- email domain intel */

const FREEMAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'hotmail.co.uk',
  'live.com', 'msn.com', 'yahoo.com', 'yahoo.co.uk', 'ymail.com', 'icloud.com', 'me.com', 'mac.com',
  'proton.me', 'protonmail.com', 'pm.me', 'aol.com', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com',
  'yandex.ru', 'zoho.com', 'fastmail.com', 'tutanota.com', 'tuta.io', 'hey.com']);

const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'temp-mail.org',
  'throwawaymail.com', 'yopmail.com', 'getnada.com', 'trashmail.com', 'sharklasers.com', 'maildrop.cc',
  'dispostable.com', 'fakeinbox.com', 'tempmail.com', 'moakt.com', 'mohmal.com']);

const MX_PROVIDERS = [
  ['Google Workspace / Gmail', /google|gmail|googlemail/],
  ['Microsoft 365 / Outlook', /outlook|microsoft|office365|hotmail/],
  ['Proton Mail', /proton/],
  ['Apple iCloud', /icloud|apple\.com/],
  ['Yahoo', /yahoo/],
  ['Fastmail', /fastmail|messagingengine/],
  ['Zoho', /zoho/],
  ['Amazon SES', /amazonaws|amazonses/],
  ['Cloudflare Email', /cloudflare/],
  ['ProtonMail', /protonmail/],
];

async function domainIntel(domain) {
  const out = { domain, mx: [], spf: null, dmarc: false, dmarcPolicy: null, provider: null, disposable: DISPOSABLE.has(domain), freemail: FREEMAIL.has(domain), custom: false };
  const [mx, txt, dmarc] = await Promise.allSettled([
    dns.resolveMx(domain),
    dns.resolveTxt(domain),
    dns.resolveTxt('_dmarc.' + domain),
  ]);
  if (mx.status === 'fulfilled') out.mx = mx.value.sort((a, b) => a.priority - b.priority).map(m => m.exchange.toLowerCase());
  if (txt.status === 'fulfilled') out.spf = txt.value.map(t => t.join('')).find(t => /^v=spf1/i.test(t)) || null;
  if (dmarc.status === 'fulfilled') {
    const rec = dmarc.value.map(t => t.join('')).find(t => /^v=DMARC1/i.test(t));
    if (rec) { out.dmarc = true; out.dmarcPolicy = (rec.match(/p=(\w+)/) || [])[1] || 'none'; }
  }
  const mxStr = out.mx.join(' ');
  for (const [name, re] of MX_PROVIDERS) { if (re.test(mxStr) || re.test(domain)) { out.provider = name; break; } }
  out.custom = out.mx.length > 0 && !out.freemail && !out.disposable;
  return out;
}

/* ------------------------------------------------------------ email recon */

async function reconEmail(email) {
  const clean = email.trim().toLowerCase();
  const [localPart, domain] = clean.split('@');
  const md5 = crypto.createHash('md5').update(clean).digest('hex');

  const [grav, gravProfile, domain_intel] = await Promise.all([
    probe(`https://gravatar.com/avatar/${md5}?d=404`),
    probe(`https://gravatar.com/${md5}.json`, { wantBody: true, headers: { Accept: 'application/json' } }),
    domainIntel(domain),
  ]);
  const gravatar = grav.status === 200 ? true : grav.status === 404 ? false : null;

  // The pivot: Gravatar's public profile JSON can leak name, username,
  // location and every account the person linked — from just an email hash.
  let profile = null;
  if (gravProfile.status === 200) {
    try {
      const entry = JSON.parse(gravProfile.body).entry?.[0];
      if (entry) {
        profile = {
          displayName: entry.displayName || null,
          username: entry.preferredUsername || null,
          location: entry.currentLocation || null,
          about: entry.aboutMe ? String(entry.aboutMe).slice(0, 300) : null,
          accounts: (entry.accounts || []).map(a => ({ platform: a.shortname || a.name, url: a.url })),
          urls: (entry.urls || []).map(l => ({ title: l.title, url: l.value })),
          profileUrl: entry.profileUrl || null,
        };
      }
    } catch { /* not a profile */ }
  }

  // Breaches: prefer HIBP if a key is configured; otherwise use the free,
  // keyless XposedOrNot source so breach data works out of the box.
  let breaches = null, breachSource = null, breachExtra = null;
  const [hibpRes, xon, webMentions] = await Promise.all([
    HIBP_KEY
      ? probe(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(clean)}?truncateResponse=false`,
        { wantBody: true, headers: { 'hibp-api-key': HIBP_KEY } })
      : Promise.resolve(null),
    xonBreaches(clean),
    searchWeb(`"${clean}"`, 5),
  ]);
  if (hibpRes) {
    if (hibpRes.status === 200) {
      try {
        breaches = JSON.parse(hibpRes.body).map(b => ({
          name: b.Title || b.Name, domain: b.Domain, date: b.BreachDate,
          count: b.PwnCount, dataClasses: b.DataClasses,
        }));
        breachSource = 'HaveIBeenPwned';
      } catch { breaches = null; }
    } else if (hibpRes.status === 404) { breaches = []; breachSource = 'HaveIBeenPwned'; }
  }
  if (breaches === null && xon) {
    breaches = xon.breaches;
    breachSource = 'XposedOrNot (free)';
  }
  if (xon) breachExtra = { risk: xon.risk, passwordStrength: xon.passwordStrength, pastes: xon.pastes };

  return {
    email: clean, gravatar, md5,
    gravatarUrl: gravatar ? `https://gravatar.com/avatar/${md5}?s=200` : null,
    profile,
    breaches, breachSource, breachExtra, hibpEnabled: Boolean(HIBP_KEY),
    webMentions,
    derivedUsername: localPart.replace(/[+.].*$/, ''),
    domain,
    domainIntel: domain_intel,
    whois: domain_intel.custom ? `https://who.is/whois/${encodeURIComponent(domain)}` : null,
    manualChecks: [
      { name: 'HaveIBeenPwned (breach database)', url: 'https://haveibeenpwned.com/' },
      { name: 'Mozilla Monitor (breach + broker scan)', url: 'https://monitor.mozilla.org/' },
      { name: 'Google results for this email', url: `https://www.google.com/search?q=%22${encodeURIComponent(clean)}%22` },
      { name: 'EPIEOS (email → Google/Skype account discovery)', url: `https://epieos.com/?q=${encodeURIComponent(clean)}&t=email` },
      { name: 'GitHub commits exposing this email', url: `https://github.com/search?q=%22${encodeURIComponent(clean)}%22&type=commits` },
      { name: 'Pastebin dumps (via Google)', url: `https://www.google.com/search?q=site:pastebin.com+%22${encodeURIComponent(clean)}%22` },
    ],
    tips: [
      'Password-reset pages on major sites reveal whether this email has an account — check Amazon/Netflix/PayPal manually.',
      'Use unique aliases per service (SimpleLogin, Firefox Relay, iCloud Hide My Email) so leaks are traceable and revocable.',
      'If breached: rotate that password everywhere it was reused, then enable 2FA.',
    ],
  };
}

/* ------------------------------------------------------------ phone recon */

const COUNTRY_CODES = [
  ['1', 'US / Canada'], ['7', 'Russia / Kazakhstan'], ['20', 'Egypt'], ['27', 'South Africa'],
  ['30', 'Greece'], ['31', 'Netherlands'], ['32', 'Belgium'], ['33', 'France'], ['34', 'Spain'],
  ['39', 'Italy'], ['40', 'Romania'], ['41', 'Switzerland'], ['43', 'Austria'], ['44', 'United Kingdom'],
  ['45', 'Denmark'], ['46', 'Sweden'], ['47', 'Norway'], ['48', 'Poland'], ['49', 'Germany'],
  ['52', 'Mexico'], ['55', 'Brazil'], ['61', 'Australia'], ['62', 'Indonesia'], ['63', 'Philippines'],
  ['64', 'New Zealand'], ['65', 'Singapore'], ['66', 'Thailand'], ['81', 'Japan'], ['82', 'South Korea'],
  ['86', 'China'], ['90', 'Turkey'], ['91', 'India'], ['92', 'Pakistan'], ['212', 'Morocco'],
  ['234', 'Nigeria'], ['254', 'Kenya'], ['255', 'Tanzania'], ['256', 'Uganda'], ['351', 'Portugal'],
  ['353', 'Ireland'], ['358', 'Finland'], ['380', 'Ukraine'], ['420', 'Czechia'], ['971', 'UAE'],
  ['972', 'Israel'], ['974', 'Qatar'],
].sort((a, b) => b[0].length - a[0].length);

// NANP (+1) area code → [primary region, timezone]. Real geographic data.
const AREA_CODES = {
  '201': ['Jersey City, NJ', 'ET'], '202': ['Washington, DC', 'ET'], '203': ['New Haven, CT', 'ET'],
  '205': ['Birmingham, AL', 'CT'], '206': ['Seattle, WA', 'PT'], '207': ['Maine', 'ET'],
  '208': ['Idaho', 'MT'], '209': ['Stockton, CA', 'PT'], '210': ['San Antonio, TX', 'CT'],
  '212': ['Manhattan, NY', 'ET'], '213': ['Los Angeles, CA', 'PT'], '214': ['Dallas, TX', 'CT'],
  '215': ['Philadelphia, PA', 'ET'], '216': ['Cleveland, OH', 'ET'], '217': ['Springfield, IL', 'CT'],
  '218': ['Duluth, MN', 'CT'], '219': ['Gary, IN', 'CT'], '224': ['Evanston, IL', 'CT'],
  '225': ['Baton Rouge, LA', 'CT'], '228': ['Gulfport, MS', 'CT'], '229': ['Albany, GA', 'ET'],
  '231': ['Muskegon, MI', 'ET'], '234': ['Akron, OH', 'ET'], '239': ['Fort Myers, FL', 'ET'],
  '240': ['Maryland', 'ET'], '248': ['Oakland County, MI', 'ET'], '251': ['Mobile, AL', 'CT'],
  '252': ['Greenville, NC', 'ET'], '253': ['Tacoma, WA', 'PT'], '254': ['Waco, TX', 'CT'],
  '256': ['Huntsville, AL', 'CT'], '260': ['Fort Wayne, IN', 'ET'], '262': ['Kenosha, WI', 'CT'],
  '267': ['Philadelphia, PA', 'ET'], '269': ['Kalamazoo, MI', 'ET'], '270': ['Bowling Green, KY', 'CT'],
  '276': ['Bristol, VA', 'ET'], '281': ['Houston, TX', 'CT'], '301': ['Maryland', 'ET'],
  '302': ['Delaware', 'ET'], '303': ['Denver, CO', 'MT'], '304': ['West Virginia', 'ET'],
  '305': ['Miami, FL', 'ET'], '307': ['Wyoming', 'MT'], '308': ['Nebraska', 'CT'],
  '309': ['Peoria, IL', 'CT'], '310': ['West Los Angeles, CA', 'PT'], '312': ['Chicago, IL', 'CT'],
  '313': ['Detroit, MI', 'ET'], '314': ['St. Louis, MO', 'CT'], '315': ['Syracuse, NY', 'ET'],
  '316': ['Wichita, KS', 'CT'], '317': ['Indianapolis, IN', 'ET'], '318': ['Shreveport, LA', 'CT'],
  '319': ['Cedar Rapids, IA', 'CT'], '320': ['St. Cloud, MN', 'CT'], '321': ['Orlando, FL', 'ET'],
  '323': ['Los Angeles, CA', 'PT'], '325': ['Abilene, TX', 'CT'], '330': ['Akron, OH', 'ET'],
  '334': ['Montgomery, AL', 'CT'], '336': ['Greensboro, NC', 'ET'], '337': ['Lafayette, LA', 'CT'],
  '339': ['Boston, MA', 'ET'], '347': ['New York, NY', 'ET'], '351': ['Massachusetts', 'ET'],
  '352': ['Gainesville, FL', 'ET'], '360': ['Bellingham, WA', 'PT'], '361': ['Corpus Christi, TX', 'CT'],
  '386': ['Daytona Beach, FL', 'ET'], '401': ['Rhode Island', 'ET'], '402': ['Omaha, NE', 'CT'],
  '404': ['Atlanta, GA', 'ET'], '405': ['Oklahoma City, OK', 'CT'], '406': ['Montana', 'MT'],
  '407': ['Orlando, FL', 'ET'], '408': ['San Jose, CA', 'PT'], '409': ['Beaumont, TX', 'CT'],
  '410': ['Baltimore, MD', 'ET'], '412': ['Pittsburgh, PA', 'ET'], '413': ['Springfield, MA', 'ET'],
  '414': ['Milwaukee, WI', 'CT'], '415': ['San Francisco, CA', 'PT'], '417': ['Springfield, MO', 'CT'],
  '419': ['Toledo, OH', 'ET'], '423': ['Chattanooga, TN', 'ET'], '424': ['Los Angeles, CA', 'PT'],
  '425': ['Bellevue, WA', 'PT'], '430': ['Tyler, TX', 'CT'], '432': ['Midland, TX', 'CT'],
  '434': ['Lynchburg, VA', 'ET'], '435': ['Utah (rural)', 'MT'], '440': ['Cleveland suburbs, OH', 'ET'],
  '442': ['Oceanside, CA', 'PT'], '443': ['Baltimore, MD', 'ET'], '469': ['Dallas, TX', 'CT'],
  '470': ['Atlanta, GA', 'ET'], '475': ['Connecticut', 'ET'], '478': ['Macon, GA', 'ET'],
  '479': ['Fort Smith, AR', 'CT'], '480': ['Mesa, AZ', 'MT'], '484': ['Allentown, PA', 'ET'],
  '501': ['Little Rock, AR', 'CT'], '502': ['Louisville, KY', 'ET'], '503': ['Portland, OR', 'PT'],
  '504': ['New Orleans, LA', 'CT'], '505': ['Albuquerque, NM', 'MT'], '507': ['Rochester, MN', 'CT'],
  '508': ['Worcester, MA', 'ET'], '509': ['Spokane, WA', 'PT'], '510': ['Oakland, CA', 'PT'],
  '512': ['Austin, TX', 'CT'], '513': ['Cincinnati, OH', 'ET'], '515': ['Des Moines, IA', 'CT'],
  '516': ['Long Island, NY', 'ET'], '517': ['Lansing, MI', 'ET'], '518': ['Albany, NY', 'ET'],
  '520': ['Tucson, AZ', 'MT'], '530': ['Redding, CA', 'PT'], '540': ['Roanoke, VA', 'ET'],
  '541': ['Eugene, OR', 'PT'], '551': ['New Jersey', 'ET'], '559': ['Fresno, CA', 'PT'],
  '561': ['West Palm Beach, FL', 'ET'], '562': ['Long Beach, CA', 'PT'], '563': ['Davenport, IA', 'CT'],
  '567': ['Toledo, OH', 'ET'], '570': ['Scranton, PA', 'ET'], '571': ['Northern Virginia', 'ET'],
  '573': ['Columbia, MO', 'CT'], '574': ['South Bend, IN', 'ET'], '575': ['Las Cruces, NM', 'MT'],
  '580': ['Lawton, OK', 'CT'], '585': ['Rochester, NY', 'ET'], '586': ['Warren, MI', 'ET'],
  '601': ['Jackson, MS', 'CT'], '602': ['Phoenix, AZ', 'MT'], '603': ['New Hampshire', 'ET'],
  '605': ['South Dakota', 'CT'], '606': ['Eastern Kentucky', 'ET'], '607': ['Binghamton, NY', 'ET'],
  '608': ['Madison, WI', 'CT'], '609': ['Trenton, NJ', 'ET'], '610': ['Allentown, PA', 'ET'],
  '612': ['Minneapolis, MN', 'CT'], '614': ['Columbus, OH', 'ET'], '615': ['Nashville, TN', 'CT'],
  '616': ['Grand Rapids, MI', 'ET'], '617': ['Boston, MA', 'ET'], '618': ['Southern Illinois', 'CT'],
  '619': ['San Diego, CA', 'PT'], '620': ['Dodge City, KS', 'CT'], '623': ['Phoenix, AZ', 'MT'],
  '626': ['Pasadena, CA', 'PT'], '628': ['San Francisco, CA', 'PT'], '629': ['Nashville, TN', 'CT'],
  '630': ['Aurora, IL', 'CT'], '631': ['Long Island, NY', 'ET'], '636': ['O\'Fallon, MO', 'CT'],
  '641': ['Mason City, IA', 'CT'], '646': ['Manhattan, NY', 'ET'], '650': ['San Mateo, CA', 'PT'],
  '651': ['St. Paul, MN', 'CT'], '657': ['Anaheim, CA', 'PT'], '660': ['Sedalia, MO', 'CT'],
  '661': ['Bakersfield, CA', 'PT'], '662': ['Tupelo, MS', 'CT'], '667': ['Baltimore, MD', 'ET'],
  '678': ['Atlanta, GA', 'ET'], '681': ['West Virginia', 'ET'], '682': ['Fort Worth, TX', 'CT'],
  '701': ['North Dakota', 'CT'], '702': ['Las Vegas, NV', 'PT'], '703': ['Northern Virginia', 'ET'],
  '704': ['Charlotte, NC', 'ET'], '706': ['Augusta, GA', 'ET'], '707': ['Santa Rosa, CA', 'PT'],
  '708': ['Cicero, IL', 'CT'], '712': ['Sioux City, IA', 'CT'], '713': ['Houston, TX', 'CT'],
  '714': ['Anaheim, CA', 'PT'], '715': ['Eau Claire, WI', 'CT'], '716': ['Buffalo, NY', 'ET'],
  '717': ['Lancaster, PA', 'ET'], '718': ['NYC (outer boroughs), NY', 'ET'], '719': ['Colorado Springs, CO', 'MT'],
  '720': ['Denver, CO', 'MT'], '724': ['Western Pennsylvania', 'ET'], '727': ['St. Petersburg, FL', 'ET'],
  '731': ['Jackson, TN', 'CT'], '732': ['Toms River, NJ', 'ET'], '734': ['Ann Arbor, MI', 'ET'],
  '737': ['Austin, TX', 'CT'], '740': ['Southeastern Ohio', 'ET'], '747': ['San Fernando Valley, CA', 'PT'],
  '754': ['Fort Lauderdale, FL', 'ET'], '757': ['Norfolk, VA', 'ET'], '760': ['Palm Springs, CA', 'PT'],
  '763': ['Brooklyn Park, MN', 'CT'], '765': ['Muncie, IN', 'ET'], '769': ['Jackson, MS', 'CT'],
  '770': ['Atlanta suburbs, GA', 'ET'], '772': ['Port St. Lucie, FL', 'ET'], '773': ['Chicago, IL', 'CT'],
  '774': ['Massachusetts', 'ET'], '775': ['Reno, NV', 'PT'], '779': ['Rockford, IL', 'CT'],
  '781': ['Boston suburbs, MA', 'ET'], '785': ['Topeka, KS', 'CT'], '786': ['Miami, FL', 'ET'],
  '801': ['Salt Lake City, UT', 'MT'], '802': ['Vermont', 'ET'], '803': ['Columbia, SC', 'ET'],
  '804': ['Richmond, VA', 'ET'], '805': ['Santa Barbara, CA', 'PT'], '806': ['Lubbock, TX', 'CT'],
  '808': ['Hawaii', 'HT'], '810': ['Flint, MI', 'ET'], '812': ['Evansville, IN', 'ET'],
  '813': ['Tampa, FL', 'ET'], '814': ['Erie, PA', 'ET'], '815': ['Rockford, IL', 'CT'],
  '816': ['Kansas City, MO', 'CT'], '817': ['Fort Worth, TX', 'CT'], '818': ['San Fernando Valley, CA', 'PT'],
  '828': ['Asheville, NC', 'ET'], '830': ['New Braunfels, TX', 'CT'], '831': ['Salinas, CA', 'PT'],
  '832': ['Houston, TX', 'CT'], '843': ['Charleston, SC', 'ET'], '845': ['Poughkeepsie, NY', 'ET'],
  '847': ['Northern Chicago suburbs, IL', 'CT'], '848': ['New Jersey', 'ET'], '850': ['Tallahassee, FL', 'CT'],
  '856': ['Camden, NJ', 'ET'], '857': ['Boston, MA', 'ET'], '858': ['San Diego, CA', 'PT'],
  '859': ['Lexington, KY', 'ET'], '860': ['Hartford, CT', 'ET'], '862': ['Newark, NJ', 'ET'],
  '863': ['Lakeland, FL', 'ET'], '864': ['Greenville, SC', 'ET'], '865': ['Knoxville, TN', 'ET'],
  '870': ['Jonesboro, AR', 'CT'], '872': ['Chicago, IL', 'CT'], '878': ['Pittsburgh, PA', 'ET'],
  '901': ['Memphis, TN', 'CT'], '903': ['Tyler, TX', 'CT'], '904': ['Jacksonville, FL', 'ET'],
  '906': ['Upper Peninsula, MI', 'ET'], '907': ['Alaska', 'AKT'], '908': ['New Jersey', 'ET'],
  '909': ['San Bernardino, CA', 'PT'], '910': ['Fayetteville, NC', 'ET'], '912': ['Savannah, GA', 'ET'],
  '913': ['Kansas City, KS', 'CT'], '914': ['Westchester, NY', 'ET'], '915': ['El Paso, TX', 'MT'],
  '916': ['Sacramento, CA', 'PT'], '917': ['New York City, NY', 'ET'], '918': ['Tulsa, OK', 'CT'],
  '919': ['Raleigh, NC', 'ET'], '920': ['Green Bay, WI', 'CT'], '925': ['Concord, CA', 'PT'],
  '928': ['Flagstaff, AZ', 'MT'], '929': ['New York City, NY', 'ET'], '936': ['Huntsville, TX', 'CT'],
  '937': ['Dayton, OH', 'ET'], '940': ['Denton, TX', 'CT'], '941': ['Sarasota, FL', 'ET'],
  '947': ['Michigan', 'ET'], '949': ['Irvine, CA', 'PT'], '951': ['Riverside, CA', 'PT'],
  '952': ['Bloomington, MN', 'CT'], '954': ['Fort Lauderdale, FL', 'ET'], '956': ['Laredo, TX', 'CT'],
  '959': ['Connecticut', 'ET'], '970': ['Fort Collins, CO', 'MT'], '971': ['Portland, OR', 'PT'],
  '972': ['Dallas, TX', 'CT'], '973': ['Newark, NJ', 'ET'], '978': ['Lowell, MA', 'ET'],
  '979': ['College Station, TX', 'CT'], '980': ['Charlotte, NC', 'ET'], '984': ['Raleigh, NC', 'ET'],
  '985': ['Houma, LA', 'CT'], '989': ['Saginaw, MI', 'ET'],
  // Canada
  '204': ['Manitoba, CA', 'CT'], '226': ['Ontario (London), CA', 'ET'], '236': ['British Columbia, CA', 'PT'],
  '250': ['British Columbia, CA', 'PT'], '289': ['Ontario (Hamilton), CA', 'ET'], '306': ['Saskatchewan, CA', 'CT'],
  '343': ['Ottawa, CA', 'ET'], '365': ['Ontario, CA', 'ET'], '403': ['Calgary, CA', 'MT'],
  '416': ['Toronto, CA', 'ET'], '418': ['Quebec City, CA', 'ET'], '431': ['Manitoba, CA', 'CT'],
  '437': ['Toronto, CA', 'ET'], '438': ['Montreal, CA', 'ET'], '450': ['Quebec, CA', 'ET'],
  '506': ['New Brunswick, CA', 'AT'], '514': ['Montreal, CA', 'ET'], '519': ['Ontario (Windsor), CA', 'ET'],
  '579': ['Quebec, CA', 'ET'], '581': ['Quebec City, CA', 'ET'], '587': ['Alberta, CA', 'MT'],
  '604': ['Vancouver, CA', 'PT'], '613': ['Ottawa, CA', 'ET'], '639': ['Saskatchewan, CA', 'CT'],
  '647': ['Toronto, CA', 'ET'], '705': ['Ontario (Sudbury), CA', 'ET'], '709': ['Newfoundland, CA', 'NT'],
  '778': ['British Columbia, CA', 'PT'], '780': ['Edmonton, CA', 'MT'], '807': ['Ontario (Thunder Bay), CA', 'ET'],
  '819': ['Quebec, CA', 'ET'], '867': ['Northern Territories, CA', 'MT'], '873': ['Quebec, CA', 'ET'],
  '902': ['Nova Scotia, CA', 'AT'], '905': ['Ontario (Mississauga), CA', 'ET'],
};

const TZ_NAMES = { ET: 'Eastern', CT: 'Central', MT: 'Mountain', PT: 'Pacific', AT: 'Atlantic', NT: 'Newfoundland', AKT: 'Alaska', HT: 'Hawaii' };

const TOLLFREE = new Set(['800', '833', '844', '855', '866', '877', '888']);

function reconPhone(raw) {
  let s = raw.trim().replace(/[^\d+]/g, '');
  if (s.startsWith('00')) s = '+' + s.slice(2);
  const hasPlus = s.startsWith('+');
  const digits = s.replace(/\D/g, '');

  let country = null, cc = null, national = digits;
  if (hasPlus) {
    for (const [code, name] of COUNTRY_CODES) {
      if (digits.startsWith(code)) { cc = code; country = name; national = digits.slice(code.length); break; }
    }
  } else if (digits.length === 10) {
    country = 'US / Canada (assumed — no country code given)'; cc = '1';
  }

  const variants = new Set([cc ? `+${cc}${national}` : digits]);
  if (national.length === 10) {
    const [a, b, c] = [national.slice(0, 3), national.slice(3, 6), national.slice(6)];
    variants.add(`(${a}) ${b}-${c}`);
    variants.add(`${a}-${b}-${c}`);
    variants.add(`${a}.${b}.${c}`);
    variants.add(national);
  } else {
    variants.add(national);
    if (cc) variants.add(`+${cc} ${national}`);
  }
  const vArr = [...variants];
  const dork = vArr.map(v => `"${v}"`).join(' OR ');

  // NANP geolocation: derive real region + timezone from the area code.
  let geo = null, lineType = null;
  if (cc === '1' && national.length === 10) {
    const npa = national.slice(0, 3);
    if (TOLLFREE.has(npa)) { geo = { region: 'Toll-free (not geographic)', tz: null }; lineType = 'toll-free / business'; }
    else if (npa === '900') { geo = { region: 'Premium-rate (not geographic)', tz: null }; lineType = 'premium-rate'; }
    else if (AREA_CODES[npa]) {
      const [region, tz] = AREA_CODES[npa];
      geo = { region, tz: tz ? `${TZ_NAMES[tz] || tz} Time` : null };
      lineType = 'geographic (mobile & landline share codes since number portability)';
    } else {
      geo = { region: `NANP area code ${npa} (unmapped)`, tz: null };
    }
  }

  return {
    input: raw,
    normalized: cc ? `+${cc} ${national}` : digits,
    country: country || 'Unknown (add a +country code for detection)',
    countryCode: cc,
    areaCode: cc === '1' && national.length === 10 ? national.slice(0, 3) : null,
    geo,
    lineType,
    valid: digits.length >= 7 && digits.length <= 15,
    variants: vArr,
    searchLinks: [
      { name: 'Google (all common formats)', url: `https://www.google.com/search?q=${encodeURIComponent(dork)}` },
      { name: 'DuckDuckGo', url: `https://duckduckgo.com/?q=${encodeURIComponent(dork)}` },
      { name: 'Truecaller (caller-ID database)', url: `https://www.truecaller.com/search/${cc || '1'}/${national}` },
      { name: 'Sync.me', url: 'https://sync.me/' },
      { name: 'WhoCallsMe (complaint boards)', url: `https://whocallsme.com/Phone-Number.aspx/${national}` },
    ],
    brokers: [
      { name: 'Whitepages', optOut: 'https://www.whitepages.com/suppression-requests' },
      { name: 'Spokeo', optOut: 'https://www.spokeo.com/optout' },
      { name: 'BeenVerified', optOut: 'https://www.beenverified.com/app/optout/search' },
      { name: 'Intelius', optOut: 'https://suppression.peopleconnect.us/login' },
      { name: 'Radaris', optOut: 'https://radaris.com/page/how-to-remove' },
      { name: 'FastPeopleSearch', optOut: 'https://www.fastpeoplesearch.com/removal' },
      { name: 'TruePeopleSearch', optOut: 'https://www.truepeoplesearch.com/removal' },
      { name: 'MyLife', optOut: 'https://www.mylife.com/ccpa/index.pubview' },
      { name: 'PeopleFinders', optOut: 'https://www.peoplefinders.com/opt-out' },
      { name: 'USSearch', optOut: 'https://www.ussearch.com/opt-out/submit/' },
    ],
    tips: [
      'People-search brokers index phone → name/address. File the opt-outs and re-check quarterly — they re-list.',
      'Your number is tied to WhatsApp/Telegram/Signal profiles — lock down "who can see my phone number" in each.',
      'Reverse lookup works both ways. Consider a VoIP number for signups.',
    ],
  };
}

/* --------------------------------------------------------------- routing */

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon',
};

function json(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1e5) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

const VALID_USERNAME = /^[\w.@-]{1,64}$/;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  try {
    /* -------- SSE: live username sweep -------- */
    if (url.pathname === '/api/username/stream' && req.method === 'GET') {
      const username = (url.searchParams.get('u') || '').trim();
      const mode = url.searchParams.get('mode') === 'full' ? 'full' : 'quick';
      if (!VALID_USERNAME.test(username)) return json(res, 400, { error: 'invalid username' });

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      const send = obj => res.write(`data: ${JSON.stringify(obj)}\n\n`);
      let closed = false;
      req.on('close', () => { closed = true; });

      const units = buildScanUnits(mode);
      send({ type: 'start', total: units.length, mode, sherlock: sherlockMeta });

      const found = [];
      let done = 0, notFound = 0, inconclusive = 0;
      await runPool(units, unit => scanOne(unit, username), 20, result => {
        done++;
        if (result.exists === true) { found.push(result.name); send({ type: 'site', ...result }); }
        else if (result.exists === false) notFound++;
        else { inconclusive++; if (result.source === 'core') send({ type: 'site', ...result }); }
        if (done % 10 === 0 || done === units.length) send({ type: 'progress', done, total: units.length });
      }, () => closed);

      if (!closed) {
        const diff = saveSnapshot('username', username, { found, mode, notFound, inconclusive });
        send({
          type: 'done',
          found: found.length, notFound, inconclusive, total: units.length,
          diff,
          manual: MANUAL_SITES.map(s => ({ name: s.name, url: s.profile(encodeURIComponent(username)) })),
        });
      }
      return res.end();
    }

    /* -------- k-anonymity password range proxy -------- */
    if (url.pathname.startsWith('/api/pwrange/') && req.method === 'GET') {
      const prefix = url.pathname.split('/').pop().toUpperCase();
      if (!/^[0-9A-F]{5}$/.test(prefix)) return json(res, 400, { error: 'prefix must be 5 hex chars' });
      const r = await probe(`https://api.pwnedpasswords.com/range/${prefix}`, {
        wantBody: true, headers: { 'Add-Padding': 'true' }, timeout: 10000,
      });
      if (r.status !== 200) return json(res, 502, { error: `range API returned ${r.status || r.error}` });
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(r.body);
    }

    /* -------- status (boot screen) -------- */
    if (url.pathname === '/api/status' && req.method === 'GET') {
      return json(res, 200, {
        sherlock: sherlockMeta,
        coreSites: CORE_SITES.length,
        manualSites: MANUAL_SITES.length,
        hibp: Boolean(HIBP_KEY),
        calibrations: calibrationCache.size,
        historyEntries: loadHistory().length,
      });
    }

    /* -------- history -------- */
    if (url.pathname === '/api/history' && req.method === 'GET') {
      const history = loadHistory().slice(-40).reverse()
        .map(({ tool, target, ts, summary }) => ({ tool, target, ts, summary }));
      return json(res, 200, history);
    }

    /* -------- JSON POST endpoints -------- */
    if (url.pathname.startsWith('/api/')) {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST only' });
      const body = await readBody(req);

      if (url.pathname === '/api/username') { // non-streaming quick scan (profile tool)
        const u = String(body.username || '').trim();
        if (!VALID_USERNAME.test(u)) return json(res, 400, { error: 'invalid username' });
        const units = buildScanUnits('quick');
        const results = [];
        await runPool(units, unit => scanOne(unit, u), 16, r => results.push(r));
        const found = results.filter(r => r.exists === true).map(r => r.name);
        saveSnapshot('username', u, { found, mode: 'quick' });
        return json(res, 200, {
          username: u, checked: results,
          manual: MANUAL_SITES.map(s => ({ name: s.name, url: s.profile(encodeURIComponent(u)) })),
        });
      }
      if (url.pathname === '/api/email') {
        const e = String(body.email || '').trim();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return json(res, 400, { error: 'invalid email' });
        const result = await reconEmail(e);
        saveSnapshot('email', e, {
          found: [
            ...(result.gravatar ? ['gravatar'] : []),
            ...(result.profile ? ['gravatar-profile'] : []),
            ...(result.breaches || []).map(b => `breach:${b.name}`),
          ],
        });
        return json(res, 200, result);
      }
      if (url.pathname === '/api/phone') {
        const p = String(body.phone || '').trim();
        if (!/^[\d\s()+.-]{5,25}$/.test(p)) return json(res, 400, { error: 'invalid phone number' });
        const result = reconPhone(p);
        result.webMentions = await searchWeb(`"${result.normalized}" OR "${result.variants[1] || result.normalized}"`, 5);
        return json(res, 200, result);
      }
      if (url.pathname === '/api/records') {
        const name = String(body.name || '').trim();
        const city = String(body.city || '').trim();
        if (name.length < 2 || name.length > 80) return json(res, 400, { error: 'name required (2–80 chars)' });
        const [web, records] = await Promise.all([nameRecon(name, city), publicRecords(name, city)]);
        return json(res, 200, { name, city, web, records });
      }
      return json(res, 404, { error: 'unknown endpoint' });
    }

    /* -------- static files -------- */
    let file = url.pathname === '/' ? '/index.html' : url.pathname;
    file = path.normalize(file).replace(/^(\.\.[/\\])+/, '');
    const full = path.join(PUBLIC_DIR, file);
    if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end(); }
    fs.readFile(full, (err, data) => {
      if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('404'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
      res.end(data);
    });
  } catch (err) {
    json(res, 500, { error: err.message });
  }
});

server.listen(PORT, '127.0.0.1', async () => {
  console.log(`
  ███████╗ ██████╗  ██████╗ ████████╗██████╗ ██████╗ ██╗███╗   ██╗████████╗
  ██╔════╝██╔═══██╗██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██║████╗  ██║╚══██╔══╝
  █████╗  ██║   ██║██║   ██║   ██║   ██████╔╝██████╔╝██║██╔██╗ ██║   ██║
  ██╔══╝  ██║   ██║██║   ██║   ██║   ██╔═══╝ ██╔══██╗██║██║╚██╗██║   ██║
  ██║     ╚██████╔╝╚██████╔╝   ██║   ██║     ██║  ██║██║██║ ╚████║   ██║
  ╚═╝      ╚═════╝  ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝

  RECON TOOLBOX v2 // self-audit mode
  → http://localhost:${PORT}
  ${HIBP_KEY ? '✓ HaveIBeenPwned email API enabled' : '○ HIBP email API off (set HIBP_API_KEY to enable; password checks work without it)'}
  Bound to 127.0.0.1 — local only.
`);
  await loadSherlockDB();
  console.log(`  Sherlock DB: ${sherlockMeta.count} sites (${sherlockMeta.source}) + ${CORE_SITES.length} core engines\n`);
});
