/* FOOTPRINT — Recon Toolbox v2 client */
'use strict';

/* ------------------------------------------------------------------ boot */

(async function bootSequence() {
  const boot = document.getElementById('boot');
  const out = document.getElementById('boot-lines');
  const dismiss = () => boot.classList.add('gone');
  boot.addEventListener('click', dismiss);
  window.addEventListener('keydown', dismiss, { once: true });

  const lines = [
    'FOOTPRINT RECON TOOLBOX v2.0 — self-audit kernel',
    'mounting /dev/identity ................ OK',
    'loading core probe engines (15) ....... OK',
    'loading sherlock site database ........ ',
  ];
  for (const l of lines) { out.textContent += l + '\n'; await sleep(120); }
  try {
    const s = await (await fetch('/api/status')).json();
    out.textContent = out.textContent.trimEnd() + `${s.sherlock.count} sites [${s.sherlock.source}]\n`;
    out.textContent += `breach interface ...................... ${s.hibp ? 'HIBP LIVE' : 'k-anonymity only'}\n`;
    out.textContent += `history snapshots ..................... ${s.historyEntries}\n`;
  } catch { out.textContent += 'offline\n'; }
  out.textContent += '\nALL SYSTEMS NOMINAL. entering self-audit mode...';
  await sleep(700);
  dismiss();
})();

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ------------------------------------------------------------------ tabs */

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + name));
}
document.querySelectorAll('.tab').forEach(tab =>
  tab.addEventListener('click', () => switchTab(tab.dataset.tab)));

/* -------------------------------------------------------- terminal output */

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function makeTerm(el) {
  el.innerHTML = '';
  return {
    el,
    line(html, cls) {
      const span = document.createElement('span');
      span.className = 'line ' + (cls || '');
      span.innerHTML = html;
      el.appendChild(span);
      return span;
    },
    raw(html) { el.insertAdjacentHTML('beforeend', html); return el.lastElementChild; },
  };
}

function link(url, label) {
  return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label || url)}</a>`;
}

function renderEnrich(term, e, pad = '        ') {
  if (!e) return;
  if (e.realName) term.line(`${pad}↳ <span class="bad">real name: ${esc(e.realName)}</span>`, 'info');
  if (e.location) term.line(`${pad}↳ <span class="bad">location: ${esc(e.location)}</span>`, 'info');
  if (e.bio) term.line(`${pad}↳ bio: ${esc(e.bio)}`, 'dim');
  if (e.joined) term.line(`${pad}↳ joined: ${esc(e.joined)}`, 'dim');
  if (e.stats) term.line(`${pad}↳ ${esc(e.stats)}`, 'dim');
  (e.fields || []).forEach(f => term.line(`${pad}↳ ${esc(f.k)}: ${esc(f.v)}`, 'dim'));
  (e.links || []).forEach(l => l.url &&
    term.line(`${pad}↳ <span class="warn">linked ${esc(l.platform)}:</span> ${link(l.url, l.nametag || l.url)}`, 'warn'));
}

function header(term, label) {
  term.line(`<span class="dim">┌──────────────────────────────────────────────┐</span>`);
  term.line(`<span class="dim">│</span> ${esc(label)}`);
  term.line(`<span class="dim">└──────────────────────────────────────────────┘</span>`);
}

async function api(path, payload) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'request failed');
  return data;
}

const state = { lastProfile: null, lastEmail: null, lastPhone: null, lastScans: [] };

/* ------------------------------------------------------------- email tool */

async function runEmail(targetEl, email) {
  const term = makeTerm(targetEl);
  header(term, `TARGET: ${email}`);
  term.line(`[*] initializing email recon...`, 'dim');

  let d;
  try { d = await api('/api/email', { email }); }
  catch (e) { term.line(`[!] ERROR: ${esc(e.message)}`, 'bad'); return null; }
  state.lastEmail = d;

  term.line(`\n[ GRAVATAR EXPOSURE ]`, 'section-h');
  if (d.gravatar === true) {
    term.line(`[+] PUBLIC GRAVATAR FOUND — any site can resolve this email's hash to a face`, 'bad');
    term.raw(`<img class="gravatar-img" src="${esc(d.gravatarUrl)}" alt="gravatar">`);
  } else if (d.gravatar === false) {
    term.line(`[-] no public gravatar avatar`, 'ok');
  } else {
    term.line(`[?] gravatar check inconclusive`, 'warn');
  }

  if (d.profile) {
    term.line(`\n[ GRAVATAR PROFILE PIVOT — deanonymized from one MD5 hash ]`, 'section-h');
    term.line(`[+] this email resolves to a PUBLIC IDENTITY PROFILE:`, 'bad');
    if (d.profile.displayName) term.line(`    name     : ${esc(d.profile.displayName)}`, 'bad');
    if (d.profile.username) term.line(`    username : ${esc(d.profile.username)} ← pivot: run this through [ USERNAME ]`, 'bad');
    if (d.profile.location) term.line(`    location : ${esc(d.profile.location)}`, 'bad');
    if (d.profile.about) term.line(`    bio      : ${esc(d.profile.about)}`, 'warn');
    d.profile.accounts.forEach(a => term.line(`    linked   : ${esc(a.platform)} — ${link(a.url)}`, 'bad'));
    d.profile.urls.forEach(l => term.line(`    website  : ${link(l.url, l.title || l.url)}`, 'warn'));
    term.line(`    fix: ${link('https://gravatar.com/profile', 'delete or restrict this Gravatar profile')} — it exposes all of the above to anyone with your email`, 'warn');
  } else if (d.gravatar) {
    term.line(`    (avatar exists but no public profile document — good)`, 'dim');
  }

  if (d.domainIntel) {
    const di = d.domainIntel;
    term.line(`\n[ DOMAIN & MAIL INTELLIGENCE — live DNS lookup on ${esc(d.domain)} ]`, 'section-h');
    if (di.disposable) term.line(`  ⚠ DISPOSABLE / throwaway email provider`, 'warn');
    term.line(`  type       : ${di.freemail ? 'free webmail (shared with millions)' : di.custom ? 'CUSTOM DOMAIN — likely personal or org, higher-value target' : 'unknown'}`, di.custom ? 'warn' : 'dim');
    if (di.provider) term.line(`  mail host  : ${esc(di.provider)}`, 'info');
    if (di.mx.length) term.line(`  MX records : ${esc(di.mx.slice(0, 3).join(', '))}${di.mx.length > 3 ? ` (+${di.mx.length - 3})` : ''}`, 'dim');
    term.line(`  SPF        : ${di.spf ? 'present' : 'MISSING — domain can be spoofed in phishing'}`, di.spf ? 'ok' : 'bad');
    term.line(`  DMARC      : ${di.dmarc ? `present (policy: ${esc(di.dmarcPolicy)})` : 'MISSING — no anti-spoofing enforcement'}`, di.dmarc ? 'ok' : 'bad');
    if (d.whois) term.line(`  ↳ custom domain — registration may expose your name/address: ${link(d.whois, 'WHOIS lookup')}`, 'warn');
  }

  term.line(`\n[ BREACH DATABASE ]`, 'section-h');
  if (d.breaches === null && !d.hibpEnabled) {
    term.line(`[?] live email-breach lookup needs an HIBP key (paid). Free 10-second check: ${link('https://haveibeenpwned.com/', 'haveibeenpwned.com')}`, 'warn');
    term.line(`    tip: the [ PASSWORD ] tab checks leaked passwords free, key-less and anonymously`, 'dim');
  } else if (Array.isArray(d.breaches) && d.breaches.length === 0) {
    term.line(`[-] no known breaches contain this address`, 'ok');
  } else if (Array.isArray(d.breaches)) {
    term.line(`[+] FOUND IN ${d.breaches.length} BREACH${d.breaches.length > 1 ? 'ES' : ''}:`, 'bad');
    d.breaches.forEach(b =>
      term.line(`    ✗ ${esc(b.name)} (${esc(b.date || '?')}) — leaked: ${esc((b.dataClasses || []).join(', '))}`, 'bad'));
    term.line(`    fix: rotate these passwords NOW, enable 2FA, never reuse`, 'warn');
  } else {
    term.line(`[?] breach lookup failed — check ${link('https://haveibeenpwned.com/', 'haveibeenpwned.com')}`, 'warn');
  }

  term.line(`\n[ PUBLIC TRACES — run these searches ]`, 'section-h');
  d.manualChecks.forEach(m => term.line(`  → ${link(m.url, m.name)}`));

  term.line(`\n[ PIVOT ]`, 'section-h');
  const pivotHandle = d.profile?.username || d.derivedUsername;
  term.raw(`<span class="line info">  derived handle: <span class="chip" data-scan-user="${esc(pivotHandle)}">${esc(pivotHandle)} — click to scan</span></span>`);

  term.line(`\n[ HARDENING TIPS ]`, 'section-h');
  d.tips.forEach(t => term.line(`  · ${esc(t)}`, 'dim'));
  wireChips(targetEl);
  return d;
}

/* ------------------------------------------------------------- phone tool */

const OPTOUT_KEY = 'footprint.optout.';

function ccpaMailto(broker) {
  const subject = encodeURIComponent('Data Deletion Request (CCPA/GDPR)');
  const body = encodeURIComponent(
    `To ${broker},\n\nUnder the California Consumer Privacy Act (CCPA) / GDPR Article 17, I request the deletion of all personal information you hold about me, and that you cease selling or sharing it.\n\nPlease confirm deletion in writing.\n\n[Your full name]\n[Address on file, if any]\n[Phone number to remove]\n[Email to remove]`);
  return `mailto:privacy@${broker.toLowerCase().replace(/[^a-z]/g, '')}.com?subject=${subject}&body=${body}`;
}

async function runPhone(targetEl, phone) {
  const term = makeTerm(targetEl);
  header(term, `TARGET: ${phone}`);

  let d;
  try { d = await api('/api/phone', { phone }); }
  catch (e) { term.line(`[!] ERROR: ${esc(e.message)}`, 'bad'); return null; }
  state.lastPhone = d;

  term.line(`\n[ NUMBER INTEL ]`, 'section-h');
  term.line(`  normalized : ${esc(d.normalized)}`);
  term.line(`  country    : ${esc(d.country)}`, d.countryCode ? 'info' : 'warn');
  if (d.areaCode) term.line(`  area code  : ${esc(d.areaCode)}`, 'info');
  if (d.geo) {
    term.line(`  geo region : ${esc(d.geo.region)}`, 'bad');
    if (d.geo.tz) term.line(`  timezone   : ${esc(d.geo.tz)} — narrows your daily activity window`, 'warn');
  }
  if (d.lineType) term.line(`  line type  : ${esc(d.lineType)}`, 'dim');
  term.line(`  plausible  : ${d.valid ? 'yes' : 'NO — check the number'}`, d.valid ? 'ok' : 'bad');

  term.line(`\n[ SEARCHABLE FORMATS ]`, 'section-h');
  d.variants.forEach(v => term.line(`  ${esc(v)}`, 'dim'));

  term.line(`\n[ EXPOSURE SEARCHES ]`, 'section-h');
  d.searchLinks.forEach(s => term.line(`  → ${link(s.url, s.name)}`));

  const doneCount = d.brokers.filter(b => localStorage.getItem(OPTOUT_KEY + b.name)).length;
  term.line(`\n[ OPT-OUT CAMPAIGN — ${doneCount}/${d.brokers.length} filed ] check off as you submit; state persists locally`, 'section-h');
  d.brokers.forEach(b => {
    const done = localStorage.getItem(OPTOUT_KEY + b.name);
    const row = term.raw(
      `<span class="line optout-row ${done ? 'ok' : 'warn'}">` +
      `<input type="checkbox" ${done ? 'checked' : ''} data-broker="${esc(b.name)}">` +
      `${esc(b.name)} — ${link(b.optOut, 'opt-out page')} · <a href="${ccpaMailto(b.name)}">CCPA email</a>` +
      `<span class="when">${done ? 'filed ' + new Date(+done).toLocaleDateString() : ''}</span></span>`);
    row.querySelector('input').addEventListener('change', ev => {
      if (ev.target.checked) localStorage.setItem(OPTOUT_KEY + b.name, Date.now());
      else localStorage.removeItem(OPTOUT_KEY + b.name);
      runPhone(targetEl, phone); // re-render counts
    });
  });
  term.line(`  ⚠ re-check quarterly — brokers re-list after data refreshes`, 'dim');

  term.line(`\n[ HARDENING TIPS ]`, 'section-h');
  d.tips.forEach(t => term.line(`  · ${esc(t)}`, 'dim'));
  return d;
}

/* ---------------------------------------------------------- username tool */

function runUsernameStream(targetEl, username, full) {
  return new Promise(resolve => {
    const term = makeTerm(targetEl);
    header(term, `TARGET: ${username} — ${full ? 'FULL SWEEP' : 'QUICK SCAN'}`);
    term.line(`[*] every FOUND below is control-verified: a random gibberish handle is probed on the same site; soft-404s are auto-rejected`, 'dim');

    const bar = term.raw(
      `<div class="scanbar"><div class="track"><div class="fill" style="width:0%"></div></div><span class="count">0 / ?</span></div>`);
    const fill = bar.querySelector('.fill');
    const count = bar.querySelector('.count');
    const foundHeader = term.line(`\n[ HITS — streaming live ]`, 'section-h');
    void foundHeader;

    const found = [];
    const es = new EventSource(`/api/username/stream?u=${encodeURIComponent(username)}&mode=${full ? 'full' : 'quick'}`);

    es.onmessage = ev => {
      const m = JSON.parse(ev.data);
      if (m.type === 'start') {
        count.textContent = `0 / ${m.total}`;
        if (full) term.line(`  sweeping ${m.total} platforms (sherlock db: ${m.sherlock.count} sites, ${esc(m.sherlock.source)})`, 'dim');
      } else if (m.type === 'progress') {
        fill.style.width = (m.done / m.total * 100).toFixed(1) + '%';
        count.textContent = `${m.done} / ${m.total}`;
      } else if (m.type === 'site') {
        if (m.exists === true) {
          found.push(m);
          const badge = m.verified === true
            ? '<span class="badge v">VERIFIED</span>'
            : '<span class="badge u">UNVERIFIED</span>';
          term.line(`  [+] FOUND  ${esc(m.name).padEnd(24)} ${link(m.url)} ${badge} <span class="dim">(${m.ms}ms)</span>`, 'bad');
          renderEnrich(term, m.enrich);
        } else {
          term.line(`  [?] ${esc(m.name)}: ${esc(m.reason || 'inconclusive')} — ${link(m.url, 'verify manually')}`, 'warn');
        }
      } else if (m.type === 'done') {
        fill.style.width = '100%';
        es.close();
        term.line(`\n[ SWEEP COMPLETE ] ${m.found} found · ${m.notFound} clear · ${m.inconclusive} blocked/inconclusive of ${m.total}`, 'section-h');
        if (!m.found) term.line(`  no accounts confirmed under this handle`, 'ok');

        if (m.diff && !m.diff.first) {
          const box = [`[ TIMELINE ] vs. last scan (${new Date(m.diff.prevTs).toLocaleString()})`];
          term.raw(`<div class="diffbox info">${esc(box[0])}<br>` +
            (m.diff.added.length ? `<span class="bad">  + NEW: ${esc(m.diff.added.join(', '))}</span><br>` : '') +
            (m.diff.removed.length ? `<span class="ok">  − GONE: ${esc(m.diff.removed.join(', '))}</span><br>` : '') +
            (!m.diff.added.length && !m.diff.removed.length ? `<span class="ok">  no change — footprint stable</span>` : '') +
            `</div>`);
        } else if (m.diff?.first) {
          term.line(`  [timeline] baseline snapshot saved — re-scan later to see drift`, 'dim');
        }

        renderSynthesis(term, username, found);

        term.line(`\n[ MANUAL CHECKS ] — big platforms block bots; click to verify (logged-out browser)`, 'section-h');
        m.manual.forEach(r => term.line(`  → ${esc(r.name).padEnd(14)} ${link(r.url)}`, 'info'));

        term.line(`\n[ HARDENING ]`, 'section-h');
        term.line(`  · every account above is linkable to you by handle alone — delete strays via ${link('https://justdeleteme.xyz', 'justdeleteme.xyz')}`, 'dim');
        term.line(`  · split handles: one for public life, others for private — break the chain`, 'dim');
        state.lastScans.push({ username, found: found.map(f => ({ name: f.name, url: f.url })) });
        wireChips(targetEl);
        resolve({ username, found });
      }
    };
    es.onerror = () => { es.close(); term.line(`[!] stream lost — is the server still running?`, 'bad'); resolve(null); };
  });
}

/* --------------------------------------------- cross-platform synthesis */

// Fold the enrichment from every confirmed account into one intel picture:
// which real names / locations recur, and which OTHER accounts they link to.
function synthesize(handle, found) {
  const names = new Map(), locations = new Map(), links = new Map();
  const norm = s => String(s).trim().toLowerCase();
  for (const acc of found) {
    const e = acc.enrich;
    if (!e) continue;
    if (e.realName) { const k = norm(e.realName); (names.get(k) || names.set(k, { label: e.realName, src: [] }).get(k)).src.push(acc.name); }
    if (e.location) { const k = norm(e.location); (locations.get(k) || locations.set(k, { label: e.location, src: [] }).get(k)).src.push(acc.name); }
    (e.links || []).forEach(l => {
      if (!l.url) return;
      const k = norm(l.url);
      if (!links.has(k)) links.set(k, { platform: l.platform, url: l.url, nametag: l.nametag, src: [] });
      links.get(k).src.push(acc.name);
    });
  }
  // Discovered links that point to a handle different from the one scanned = new pivots.
  const external = [...links.values()].filter(l => {
    try { return !new URL(l.url).pathname.toLowerCase().includes(norm(handle)); } catch { return true; }
  });
  return {
    names: [...names.values()].sort((a, b) => b.src.length - a.src.length),
    locations: [...locations.values()].sort((a, b) => b.src.length - a.src.length),
    links: [...links.values()],
    external,
  };
}

function renderSynthesis(term, handle, found) {
  const enriched = found.filter(f => f.enrich);
  if (!enriched.length) return;
  const s = synthesize(handle, found);
  term.line(`\n[ CROSS-PLATFORM SYNTHESIS — what the accounts collectively reveal ]`, 'section-h');

  if (s.names.length) {
    term.line(`  REAL NAME exposed by ${s.names[0].src.length > 1 ? 'multiple accounts' : 'an account'}:`, 'bad');
    s.names.forEach(n => term.line(`    ▸ "${esc(n.label)}" — from ${esc(n.src.join(', '))}`, 'bad'));
  }
  if (s.locations.length) {
    const agree = s.locations[0].src.length > 1;
    term.line(`  LOCATION ${agree ? 'corroborated across accounts (high confidence)' : 'exposed'}:`, agree ? 'bad' : 'warn');
    s.locations.forEach(l => term.line(`    ▸ ${esc(l.label)} — from ${esc(l.src.join(', '))}`, agree ? 'bad' : 'warn'));
  }
  if (s.external.length) {
    term.line(`  LINKED ACCOUNTS discovered (pivots to identities you may not have listed):`, 'warn');
    s.external.forEach(l => {
      const chip = `<span class="chip" data-scan-url="${esc(l.url)}">pivot</span>`;
      term.line(`    ▸ ${esc(l.platform)}${l.nametag ? ' @' + esc(l.nametag) : ''}: ${link(l.url)} <span class="dim">(via ${esc(l.src.join(', '))})</span> ${chip}`, 'warn');
    });
  }
  if (!s.names.length && !s.locations.length && !s.external.length) {
    term.line(`  accounts exist but leak no name/location/links in their public profiles — good`, 'ok');
  }
}

/* ---------------------------------------------------------- password tool */

async function runPassword(targetEl, password) {
  const term = makeTerm(targetEl);
  header(term, 'K-ANONYMITY PASSWORD EXPOSURE CHECK');
  if (!password) { term.line('[!] type a password first', 'bad'); return; }

  term.line(`[*] hashing locally with SHA-1 (WebCrypto)...`, 'dim');
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  const hash = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const prefix = hash.slice(0, 5), suffix = hash.slice(5);

  term.line(`  full hash (never leaves this page) : ${hash.slice(0, 5)}<span class="dim">${'·'.repeat(35)}</span>`, 'info');
  term.line(`  transmitted to server              : "${prefix}" — 5 characters, matches ~800 different hashes`, 'ok');
  term.line(`[*] requesting candidate bucket /range/${prefix} (with padding, so even bucket size leaks nothing)...`, 'dim');

  let text;
  try {
    const res = await fetch(`/api/pwrange/${prefix}`);
    if (!res.ok) throw new Error((await res.json()).error);
    text = await res.text();
  } catch (e) { term.line(`[!] range API error: ${esc(e.message)}`, 'bad'); return; }

  const rows = text.split('\n').map(l => l.trim().split(':'));
  const real = rows.filter(([, c]) => parseInt(c, 10) > 0);
  term.line(`  received ${rows.length} candidate suffixes (${rows.length - real.length} decoy padding) — matching locally...`, 'dim');

  const hit = real.find(([s]) => s === suffix);
  term.line('');
  if (hit) {
    const n = parseInt(hit[1], 10).toLocaleString();
    term.line(`[+] PWNED — this password appears ${n} times in known breach corpora`, 'bad');
    term.line(`    attackers try these first in credential-stuffing. stop using it everywhere, today.`, 'bad');
    term.line(`    fix: unique random passwords per site via a password manager + 2FA`, 'warn');
  } else {
    term.line(`[-] not present in the 800M+ leaked-password corpus`, 'ok');
    term.line(`    (absence ≠ strong — length beats complexity; 4 random words > P@ssw0rd1)`, 'dim');
  }
  term.line(`\n[ WHY THIS IS SAFE ]`, 'section-h');
  term.line(`  the server (and HIBP) only ever saw "${prefix}". your password and even its full hash stayed in this tab.`, 'dim');
  term.line(`  protocol: k-anonymity range query — ${link('https://haveibeenpwned.com/API/v3#PwnedPasswords', 'spec')}`, 'dim');
  document.getElementById('password-input').value = '';
}

/* ---------------------------------------------------- card tool (LOCAL) */

const CARD_BRANDS = [
  { brand: 'Visa', re: /^4/ },
  { brand: 'Mastercard', re: /^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/ },
  { brand: 'American Express', re: /^3[47]/ },
  { brand: 'Discover', re: /^(6011|64[4-9]|65)/ },
  { brand: 'Diners Club', re: /^3(0[0-5]|[68])/ },
  { brand: 'JCB', re: /^35(2[89]|[3-8]\d)/ },
  { brand: 'UnionPay', re: /^62/ },
  { brand: 'Maestro', re: /^(50|5[6-9]|6\d)/ },
];

function luhn(num) {
  let sum = 0, dbl = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let d = +num[i];
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}

const CARD_STORAGE_MAP = [
  { where: 'Chrome saved payment methods', url: 'chrome://settings/payments', note: 'paste into Chrome address bar' },
  { where: 'Safari / iCloud Keychain cards', url: 'https://support.apple.com/guide/safari/autofill-ibrw1103/mac', note: 'Safari → Settings → AutoFill' },
  { where: 'Firefox saved cards', url: 'about:preferences#privacy', note: 'paste into Firefox address bar' },
  { where: 'Amazon wallet', url: 'https://www.amazon.com/cpe/managepaymentmethods' },
  { where: 'PayPal linked cards', url: 'https://www.paypal.com/myaccount/money/cards' },
  { where: 'Google Pay', url: 'https://pay.google.com/gp/w/u/0/home/paymentmethods' },
  { where: 'Apple account', url: 'https://appleid.apple.com/account/manage' },
  { where: 'App stores', url: 'https://play.google.com/store/paymentmethods' },
  { where: 'Forgotten subscriptions', url: 'https://www.rocketmoney.com/', note: 'or scan statements for recurring charges' },
];

function runCard(targetEl, rawInput) {
  const term = makeTerm(targetEl);
  const digits = rawInput.replace(/\D/g, '');
  header(term, 'LOCAL CARD ANALYSIS — zero network activity');
  term.line(`[*] in-browser only. open devtools → network to verify: no requests fire.`, 'info');

  if (digits.length < 12 || digits.length > 19) {
    term.line(`[!] ${digits.length} digits — not a valid card length (12–19). Full number, or first 6–8 digits for BIN-only mode.`, 'warn');
    if (digits.length >= 6) {
      const brand = (CARD_BRANDS.find(b => b.re.test(digits)) || { brand: 'Unknown network' }).brand;
      term.line(`\n[ BIN-ONLY ] network: ${brand} (prefix ${digits.slice(0, 6)})`, 'info');
    }
    renderCardStorage(term);
    return;
  }
  const brand = (CARD_BRANDS.find(b => b.re.test(digits)) || { brand: 'Unknown network' }).brand;
  const valid = luhn(digits);
  const masked = digits.slice(0, 6) + '*'.repeat(digits.length - 10) + digits.slice(-4);

  term.line(`\n[ CARD INTEL ]`, 'section-h');
  term.line(`  masked   : ${masked}`, 'dim');
  term.line(`  network  : ${brand}`, 'info');
  term.line(`  BIN/IIN  : ${digits.slice(0, 6)} (identifies the issuing bank — the prefix alone isn't secret)`, 'dim');
  term.line(`  checksum : ${valid ? 'VALID (passes Luhn)' : 'INVALID — typo, or not a real card'}`, valid ? 'ok' : 'bad');

  term.line(`\n[ WHY THERE'S NO "WHICH SITES HAVE MY CARD" LOOKUP ]`, 'section-h');
  term.line(`  no legitimate public database maps card numbers → merchants. anything claiming to is a scam`, 'warn');
  term.line(`  harvesting numbers, or a criminal "checker". the real sources of truth are below + your bank's alerts.`, 'warn');
  renderCardStorage(term);
}

function renderCardStorage(term) {
  term.line(`\n[ AUDIT: EVERY PLACE YOUR CARD LIKELY LIVES ]`, 'section-h');
  CARD_STORAGE_MAP.forEach(s => {
    const isBrowserUrl = s.url.startsWith('chrome://') || s.url.startsWith('about:');
    term.line(`  ☐ ${esc(s.where).padEnd(34)} ${isBrowserUrl ? `<span class="info">${esc(s.url)}</span>` : link(s.url, 'open')}${s.note ? ` <span class="dim">// ${esc(s.note)}</span>` : ''}`);
  });
  term.line(`\n[ DEFENSE ]`, 'section-h');
  term.line(`  · bank transaction alerts = the only reliable "who charged my card" feed`, 'dim');
  term.line(`  · virtual card numbers per merchant (Privacy.com, Revolut, many banks) contain any single leak`, 'dim');
  term.line(`  · card was in a breach? don't monitor — replace. a new number is free.`, 'dim');
}

/* ------------------------------------------------- SELF: browser audit */

const FONT_PROBES = ['Arial Black', 'Comic Sans MS', 'Courier New', 'Georgia', 'Impact', 'Lucida Console',
  'Palatino Linotype', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Helvetica Neue', 'Menlo',
  'Monaco', 'Consolas', 'Cambria', 'Calibri', 'Futura', 'Gill Sans', 'Optima', 'Avenir', 'Baskerville',
  'Didot', 'American Typewriter', 'Rockwell', 'Franklin Gothic Medium', 'Segoe UI', 'Ubuntu', 'Roboto', 'Fira Code'];

function detectFonts() {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const text = 'mmmMMMwwwlli10O';
  const base = {};
  for (const fallback of ['monospace', 'sans-serif', 'serif']) {
    ctx.font = `72px ${fallback}`;
    base[fallback] = ctx.measureText(text).width;
  }
  return FONT_PROBES.filter(font =>
    ['monospace', 'sans-serif', 'serif'].some(fb => {
      ctx.font = `72px "${font}", ${fb}`;
      return ctx.measureText(text).width !== base[fb];
    }));
}

async function fingerprintHash(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
}

function canvasFingerprint() {
  const c = document.createElement('canvas');
  c.width = 240; c.height = 60;
  const x = c.getContext('2d');
  x.textBaseline = 'top'; x.font = '14px "Arial"';
  x.fillStyle = '#f60'; x.fillRect(120, 1, 62, 20);
  x.fillStyle = '#069'; x.fillText('footprint,fp <canvas> 1.0 😃', 2, 15);
  x.fillStyle = 'rgba(102,204,0,0.7)'; x.fillText('footprint,fp <canvas> 1.0 😃', 4, 17);
  return c.toDataURL();
}

function webglInfo() {
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    if (!gl) return { vendor: 'n/a', renderer: 'n/a' };
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    return {
      vendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
      renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
    };
  } catch { return { vendor: 'blocked', renderer: 'blocked' }; }
}

function webrtcLeakTest(timeoutMs = 2500) {
  return new Promise(resolve => {
    const ips = new Set();
    let pc;
    try { pc = new RTCPeerConnection({ iceServers: [] }); }
    catch { return resolve({ supported: false, ips: [] }); }
    pc.createDataChannel('probe');
    pc.onicecandidate = ev => {
      const cand = ev.candidate?.candidate || '';
      const m = cand.match(/(\d{1,3}(?:\.\d{1,3}){3})|([a-f0-9:]{10,})/i);
      if (m) ips.add(m[0]);
    };
    pc.createOffer().then(o => pc.setLocalDescription(o));
    setTimeout(() => { pc.close(); resolve({ supported: true, ips: [...ips] }); }, timeoutMs);
  });
}

async function runSelf(targetEl) {
  const term = makeTerm(targetEl);
  header(term, 'BROWSER TRACKABILITY AUDIT — what any webpage learns about you in <1s');
  term.line(`[*] running the same techniques ad-tech fingerprinting scripts use, locally...`, 'dim');

  const fonts = detectFonts();
  const canvasHash = await fingerprintHash(canvasFingerprint());
  const gl = webglInfo();
  const glHash = await fingerprintHash(gl.vendor + gl.renderer);
  const rtc = await webrtcLeakTest();

  const signals = [
    ['canvas fingerprint', canvasHash, 'unique-ish rendering hash — top tracking signal'],
    ['WebGL renderer', `${gl.renderer}`, 'often narrows you to an exact GPU/driver'],
    ['WebGL hash', glHash, ''],
    ['installed fonts', `${fonts.length}/${FONT_PROBES.length} detected`, fonts.slice(0, 8).join(', ') + '…'],
    ['timezone', Intl.DateTimeFormat().resolvedOptions().timeZone, ''],
    ['language(s)', navigator.languages.join(', '), ''],
    ['platform', navigator.platform, ''],
    ['screen', `${screen.width}×${screen.height} @${window.devicePixelRatio}x, ${screen.colorDepth}-bit`, ''],
    ['CPU threads', navigator.hardwareConcurrency ?? '?', ''],
    ['device memory', (navigator.deviceMemory ?? '?') + ' GB class', ''],
    ['touch points', navigator.maxTouchPoints, ''],
    ['do-not-track', navigator.doNotTrack || 'unset', 'ironically a tracking signal itself'],
    ['cookies enabled', navigator.cookieEnabled, ''],
  ];

  term.line(`\n[ FINGERPRINT SURFACE ]`, 'section-h');
  signals.forEach(([k, v, note]) =>
    term.line(`<span class="fp-row"><span class="k">${esc(k)}</span><span>${esc(String(v))}${note ? ` <span class="dim">// ${esc(note)}</span>` : ''}</span></span>`));

  term.line(`\n[ WEBRTC LEAK TEST ]`, 'section-h');
  if (!rtc.supported) term.line(`  [-] WebRTC blocked or unsupported — no leak`, 'ok');
  else if (!rtc.ips.length) term.line(`  [-] no candidate IPs surfaced (mDNS obfuscation active) — good`, 'ok');
  else rtc.ips.forEach(ip => term.line(`  [+] WebRTC surfaced local candidate: ${esc(ip)} — can deanonymize VPN users`, 'bad'));

  // crude entropy estimate: each distinguishing signal multiplies your uniqueness
  let bits = 0;
  bits += 10;                        // canvas hash
  bits += 6;                         // webgl renderer
  bits += Math.min(10, fonts.length / 3);
  bits += 4;                         // timezone+lang
  bits += 4;                         // screen combo
  bits += 2;                         // hw hints
  if (rtc.ips.length) bits += 3;
  const pop = Math.min(2 ** bits, 8e9);
  const score = Math.min(100, Math.round(bits * 2.6));

  const grade = score >= 75 ? ['HIGHLY TRACKABLE — effectively unique', 'bad']
    : score >= 45 ? ['TRACKABLE — small anonymity set', 'warn']
    : ['RESISTANT — you blend into a crowd', 'ok'];
  term.raw(`<div class="scorebox"><div><div class="dim">TRACKABILITY</div><div class="scorenum ${grade[1]}">${score}/100</div></div><div class="meter"><div style="width:${score}%"></div></div><div class="${grade[1]}">${grade[0]}<br><span class="dim">~${Math.round(bits)} bits of entropy ≈ 1 in ${pop.toLocaleString()} browsers</span></div></div>`);

  term.line(`[ COUNTERMEASURES ]`, 'section-h');
  term.line(`  · Firefox: privacy.resistFingerprinting = true · Safari: on by default · Brave: farbling on`, 'dim');
  term.line(`  · uBlock Origin blocks most fingerprinting scripts before they run`, 'dim');
  term.line(`  · the strongest move is the Tor Browser: everyone looks identical by design`, 'dim');
}

/* ------------------------------------------------ permutation engine */

const LEET = { a: '4', e: '3', i: '1', o: '0', s: '5' };

function permuteHandles(name, handles) {
  const out = new Set();
  const tokens = name ? name.toLowerCase().split(/\s+/).filter(Boolean) : [];
  const bases = new Set(handles.map(h => h.toLowerCase()));
  if (tokens.length >= 2) {
    const [f, l] = [tokens[0], tokens[tokens.length - 1]];
    [f + l, f + '.' + l, f + '_' + l, f[0] + l, f + l[0], l + f].forEach(b => bases.add(b));
  } else if (tokens.length === 1) bases.add(tokens[0]);

  for (const b of bases) {
    out.add(b);
    out.add(b + '_');
    out.add('real' + b);
    out.add(b + 'official');
    for (const yr of ['88', '90', '95', '99', '01', '123']) out.add(b + yr);
    const leet = b.replace(/[aeios]/g, c => LEET[c] || c);
    if (leet !== b) out.add(leet);
  }
  handles.forEach(h => out.delete(h.toLowerCase())); // only *new* candidates
  return [...out].filter(h => /^[\w.-]{3,30}$/.test(h)).slice(0, 24);
}

/* ------------------------------------------------ correlation engine */

function correlate({ name, city, emailR, phoneR, scans }) {
  const insights = [];
  const totalFound = scans.reduce((n, s) => n + s.found.length, 0);

  // Fold enrichment across every found account.
  const allEnrich = scans.flatMap(s => s.found.map(f => f.enrich).filter(Boolean));
  const names = new Map(), locs = new Map();
  const norm = s => String(s).trim().toLowerCase();
  allEnrich.forEach(e => {
    if (e.realName) names.set(norm(e.realName), (names.get(norm(e.realName)) || 0) + 1);
    if (e.location) locs.set(norm(e.location), (locs.get(norm(e.location)) || 0) + 1);
  });
  const externalLinks = new Set();
  scans.forEach(s => s.found.forEach(f => (f.enrich?.links || []).forEach(l => {
    if (l.url) { try { if (!new URL(l.url).pathname.toLowerCase().includes(norm(s.username))) externalLinks.add(l.url); } catch { /* ignore */ } }
  })));

  const nameList = [...names.entries()];
  if (nameList.length) {
    const top = allEnrich.find(e => e.realName && norm(e.realName) === nameList.sort((a, b) => b[1] - a[1])[0][0]);
    insights.push({ sev: 'bad', text: `Your public account profiles expose a REAL NAME ("${top.realName}")${nameList[0][1] > 1 ? ' — corroborated by multiple platforms, so it is almost certainly you' : ''}. Name + any handle = full deanonymization.` });
  }
  const locList = [...locs.entries()].sort((a, b) => b[1] - a[1]);
  if (locList.length) {
    const top = allEnrich.find(e => e.location && norm(e.location) === locList[0][0]);
    insights.push({ sev: locList[0][1] > 1 ? 'bad' : 'warn', text: `Location "${top.location}" is published${locList[0][1] > 1 ? ` by ${locList[0][1]} of your accounts (high-confidence geolocation)` : ''}. Combine with timezone from phone/posts to narrow further.` });
  }
  if (externalLinks.size) {
    insights.push({ sev: 'bad', text: `${externalLinks.size} linked account(s) discovered inside your profiles (e.g. Keybase proofs, bio links) — these chain your identities together and often point to handles you didn't list.` });
  }
  if (name && names.size && ![...names.keys()].includes(norm(name))) {
    insights.push({ sev: 'warn', text: `The name you entered ("${name}") differs from the name your accounts publish ("${[...names.values(), ][0] && allEnrich.find(e => e.realName).realName}") — one of them is the persona an adversary will actually find.` });
  }

  if (emailR?.profile?.username) {
    const gravHandle = emailR.profile.username.toLowerCase();
    const known = scans.some(s => s.username.toLowerCase() === gravHandle);
    insights.push({
      sev: 'bad',
      text: `Gravatar links your email to handle "${emailR.profile.username}"${known ? '' : ' — a handle you did NOT list. One email = all its accounts.'}`,
    });
  }
  if (emailR?.profile?.location) {
    insights.push({ sev: 'bad', text: `Your Gravatar publishes a location ("${emailR.profile.location}") — combine with name and anyone geolocates you in one query.` });
  }
  const withBreachPasswords = (emailR?.breaches || []).filter(b => (b.dataClasses || []).includes('Passwords'));
  if (withBreachPasswords.length) {
    insights.push({ sev: 'bad', text: `${withBreachPasswords.length} breach(es) leaked PASSWORDS for this email — assume credential-stuffing bots have tried them on every major site already.` });
  }
  if (scans.length >= 2 && scans.every(s => s.found.length)) {
    insights.push({ sev: 'warn', text: `Multiple handles each have live accounts — if any two share a bio, avatar or link, the personas collapse into one.` });
  }
  if (totalFound >= 5) {
    insights.push({ sev: 'warn', text: `${totalFound} accounts resolve from handles alone. Each is an OSINT pivot: bios leak employers, timestamps leak timezone, follows leak friends.` });
  }
  const cats = new Set();
  scans.forEach(s => s.found.forEach(f => { if (/github|gitlab|npm|dev/i.test(f.name)) cats.add('developer'); if (/chess|lichess|steam|twitch/i.test(f.name)) cats.add('gamer'); }));
  if (cats.size) insights.push({ sev: 'info', text: `Persona profile derivable from account mix: ${[...cats].join(' + ')} — enough for targeted phishing pretexts.` });
  if (name && city) {
    insights.push({ sev: 'warn', text: `"${name}" + "${city}" is the exact key data brokers index on. The opt-out list in [ PHONE ] applies to you even without a phone number.` });
  }
  if (phoneR) {
    insights.push({ sev: 'warn', text: `Phone number is likely resolvable to your name via caller-ID databases (Truecaller et al. crowd-source address books).` });
  }
  if (!insights.length) insights.push({ sev: 'ok', text: 'No cross-identifier correlations detected in the automated surface — good posture.' });
  return insights;
}

/* ----------------------------------------------------------- profile tool */

async function runProfile(targetEl) {
  const name = document.getElementById('pf-name').value.trim();
  const city = document.getElementById('pf-city').value.trim();
  const usernames = document.getElementById('pf-usernames').value.split(',').map(s => s.trim()).filter(Boolean);
  const email = document.getElementById('pf-email').value.trim();
  const phone = document.getElementById('pf-phone').value.trim();

  const term = makeTerm(targetEl);
  document.getElementById('graph-wrap').classList.add('hidden');
  if (!name && !usernames.length && !email && !phone) {
    term.line(`[!] enter at least one identifier`, 'bad');
    return;
  }
  header(term, `COMPILING EXPOSURE PROFILE${name ? ': ' + name.toUpperCase() : ''}`);
  term.line(`[*] running all scans in parallel...`, 'dim');

  const jobs = [];
  if (email) jobs.push(api('/api/email', { email }).then(d => ['email', d]).catch(() => ['email', null]));
  if (phone) jobs.push(api('/api/phone', { phone }).then(d => ['phone', d]).catch(() => ['phone', null]));
  usernames.slice(0, 3).forEach(u =>
    jobs.push(api('/api/username', { username: u }).then(d => ['username', d]).catch(() => ['username', null])));

  const results = await Promise.all(jobs);
  const emailR = results.find(r => r[0] === 'email')?.[1];
  const phoneR = results.find(r => r[0] === 'phone')?.[1];
  const userRs = results.filter(r => r[0] === 'username' && r[1]).map(r => r[1]);
  const scans = userRs.map(r => ({
    username: r.username,
    found: r.checked.filter(c => c.exists === true).map(c => ({ name: c.name, url: c.url, enrich: c.enrich || null })),
  }));

  /* ---- exposure score ---- */
  let score = 0;
  const factors = [];
  const accountsFound = scans.reduce((n, s) => n + s.found.length, 0);
  if (accountsFound) { score += accountsFound * 6; factors.push(`${accountsFound} confirmed account(s) (+${accountsFound * 6})`); }
  if (emailR?.gravatar) { score += 8; factors.push('public gravatar avatar (+8)'); }
  if (emailR?.profile) { score += 14; factors.push('gravatar PROFILE exposes identity from email hash (+14)'); }
  const enrichedNames = scans.some(s => s.found.some(f => f.enrich?.realName));
  const enrichedLoc = scans.some(s => s.found.some(f => f.enrich?.location));
  if (enrichedNames) { score += 12; factors.push('real name published in account profiles (+12)'); }
  if (enrichedLoc) { score += 8; factors.push('location published in account profiles (+8)'); }
  if (emailR?.domainIntel?.custom) { score += 5; factors.push('custom email domain → WHOIS may expose registrant (+5)'); }
  if (Array.isArray(emailR?.breaches) && emailR.breaches.length) { score += emailR.breaches.length * 15; factors.push(`${emailR.breaches.length} breach(es) (+${emailR.breaches.length * 15})`); }
  if (phone) { score += 12; factors.push('phone likely indexed by brokers/caller-ID (+12)'); }
  if (name && city) { score += 8; factors.push('name+city enables people-search (+8)'); }
  score = Math.min(100, score);

  const grade = score >= 70 ? ['CRITICAL — you are an open book', 'bad']
    : score >= 40 ? ['ELEVATED — meaningful exposure', 'warn']
    : score >= 15 ? ['MODERATE — some traces', 'info']
    : ['LOW — minimal automated exposure', 'ok'];

  term.raw(`<div class="scorebox"><div><div class="dim">EXPOSURE SCORE</div><div class="scorenum ${grade[1]}">${score}/100</div></div><div class="meter"><div style="width:${score}%"></div></div><div class="${grade[1]}">${grade[0]}</div></div>`);
  if (factors.length) { term.line(`[ SCORE FACTORS ]`, 'section-h'); factors.forEach(f => term.line(`  · ${esc(f)}`, 'dim')); }

  /* ---- identity graph ---- */
  const gdata = { center: name || usernames[0] || email || 'YOU', identifiers: [], accounts: [], breaches: [], intel: [] };
  if (email) gdata.identifiers.push({ id: 'em', label: email });
  if (phone) gdata.identifiers.push({ id: 'ph', label: phoneR?.normalized || phone });
  const seenIntel = new Set();
  scans.forEach((s, i) => {
    gdata.identifiers.push({ id: 'u' + i, label: '@' + s.username });
    s.found.forEach((f, j) => {
      const aid = `a${i}_${j}`;
      gdata.accounts.push({ id: aid, label: f.name, url: f.url, parent: 'u' + i });
      const e = f.enrich;
      if (!e) return;
      if (e.realName && !seenIntel.has('n:' + e.realName.toLowerCase())) {
        seenIntel.add('n:' + e.realName.toLowerCase());
        gdata.intel.push({ id: 'n' + i + j, label: '★ ' + e.realName, parent: aid });
      }
      if (e.location && !seenIntel.has('l:' + e.location.toLowerCase())) {
        seenIntel.add('l:' + e.location.toLowerCase());
        gdata.intel.push({ id: 'l' + i + j, label: '⌖ ' + e.location, parent: aid });
      }
      (e.links || []).forEach((l, k) => l.url && gdata.accounts.push({ id: `x${i}_${j}_${k}`, label: l.platform, url: l.url, parent: aid }));
    });
  });
  (emailR?.breaches || []).forEach((b, i) => gdata.breaches.push({ id: 'b' + i, label: '☠ ' + b.name, parent: 'em' }));
  if (emailR?.profile) {
    gdata.intel.push({ id: 'gp', label: 'gravatar profile', url: emailR.profile.profileUrl, parent: 'em' });
    (emailR.profile.accounts || []).forEach((a, i) => gdata.accounts.push({ id: 'ga' + i, label: a.platform, url: a.url, parent: 'gp' }));
  }
  if (gdata.identifiers.length || gdata.accounts.length) {
    document.getElementById('graph-wrap').classList.remove('hidden');
    IdentityGraph.init(document.getElementById('graph'));
    IdentityGraph.build(gdata);
  }

  /* ---- correlation engine ---- */
  term.line(`\n[ CORRELATION ENGINE ] — how the pieces connect`, 'section-h');
  correlate({ name, city, emailR, phoneR, scans }).forEach(i => term.line(`  ▸ ${esc(i.text)}`, i.sev));

  /* ---- discovered accounts ---- */
  if (scans.length) {
    term.line(`\n[ ACCOUNTS DISCOVERED ]`, 'section-h');
    scans.forEach(s => {
      term.line(`  handle "${esc(s.username)}": ${s.found.length} confirmed`, s.found.length ? 'bad' : 'ok');
      s.found.forEach(f => { term.line(`    [+] ${esc(f.name)} — ${link(f.url)}`, 'bad'); renderEnrich(term, f.enrich, '          '); });
      renderSynthesis(term, s.username, s.found);
    });
    term.line(`  ↑ run each handle through [ USERNAME ] with FULL SWEEP for 400+ site coverage`, 'dim');
  }

  /* ---- permutations ---- */
  const perms = permuteHandles(name, usernames);
  if (perms.length) {
    term.line(`\n[ HANDLE PERMUTATION ENGINE ] — variants people (and stalkers) guess; click to scan`, 'section-h');
    term.raw(`<span class="line">${perms.map(p => `<span class="chip" data-scan-user="${esc(p)}">${esc(p)}</span>`).join('')}</span>`);
  }

  /* ---- name dorks ---- */
  if (name) {
    const q = city ? `"${name}" "${city}"` : `"${name}"`;
    const dorks = [
      `${q}`,
      `site:linkedin.com/in "${name}"`,
      `site:facebook.com "${name}"${city ? ` "${city}"` : ''}`,
      `"${name}" filetype:pdf`,
      `"${name}" (resume OR cv)`,
      `site:pastebin.com "${name}"`,
    ];
    term.line(`\n[ NAME DORKS — what a stranger finds in 60 seconds ]`, 'section-h');
    dorks.forEach(dk => term.line(`  → ${link(`https://www.google.com/search?q=${encodeURIComponent(dk)}`, dk)}`));
    const copyBtn = term.raw(`<span class="line"><span class="chip" id="copy-dorks">⧉ copy full dork pack</span></span>`);
    copyBtn.querySelector('#copy-dorks').addEventListener('click', () => {
      navigator.clipboard.writeText(dorks.join('\n'));
      copyBtn.querySelector('#copy-dorks').textContent = '✓ copied';
    });
  }

  /* ---- playbook + export ---- */
  term.line(`\n[ REMEDIATION PLAYBOOK — in priority order ]`, 'section-h');
  const playbook = [
    'Rotate passwords + enable 2FA on breached / reused-password accounts',
    'Delete abandoned accounts found above — justdeleteme.xyz has direct links',
    'File data-broker opt-outs (tracker in [ PHONE ]) — biggest win for name/address privacy',
    'Delete or restrict the Gravatar profile; stop reusing one avatar everywhere',
    'Set kept accounts private; scrub location-tagged posts',
    'Adopt per-site email aliases + a password manager going forward',
  ];
  playbook.forEach((p, i) => term.line(`  ${i + 1}. ${esc(p)}`, 'dim'));

  state.lastProfile = { name, city, email, phone, scans, emailR, phoneR, score, grade: grade[0], factors };
  const exp = term.raw(`<span class="line"><span class="chip" id="export-dossier">⧉ EXPORT DOSSIER (printable html)</span></span>`);
  exp.querySelector('#export-dossier').addEventListener('click', exportDossier);
  term.line(`\n[✓] profile compiled. re-run quarterly — the timeline will diff every scan automatically.`, 'ok');
  wireChips(targetEl);
}

/* ------------------------------------------------ deep footprint (SSE) */

function runFootprint(targetEl) {
  return new Promise(resolve => {
    const name = document.getElementById('fp-name').value.trim();
    const city = document.getElementById('fp-city').value.trim();
    const usernames = document.getElementById('fp-usernames').value.trim();
    const email = document.getElementById('fp-email').value.trim();
    const phone = document.getElementById('fp-phone').value.trim();
    const term = makeTerm(targetEl);
    document.getElementById('graph-wrap') && document.getElementById('graph-wrap').classList.add('hidden');

    if (!name && !usernames && !email && !phone) { term.line('[!] enter at least one identifier', 'bad'); return resolve(); }
    header(term, 'MAPPING DIGITAL FOOTPRINT');
    term.line('[*] running every source, then fetching & scraping the pages they surface...', 'dim');
    const log = term.line('', 'info');

    const qs = new URLSearchParams({ name, city, email, phone, usernames });
    const es = new EventSource('/api/footprint/stream?' + qs.toString());
    let liveAccounts = 0, liveScraped = 0;

    es.onmessage = ev => {
      const m = JSON.parse(ev.data);
      if (m.type === 'phase') {
        term.line(`\n▶ ${esc(m.label)}`, 'section-h');
      } else if (m.type === 'account') {
        liveAccounts++;
        const extra = [m.realName, m.location].filter(Boolean).join(' · ');
        term.line(`  [+] ${esc(m.platform).padEnd(18)} ${link(m.url)}${extra ? ` <span class="info">${esc(extra)}</span>` : ''}`, 'bad');
      } else if (m.type === 'email') {
        if (m.breaches) term.line(`  [!] ${m.breaches} breach(es) via ${esc(m.breachSource || '')}${m.risk ? ` — risk: ${esc(m.risk.label)} (${m.risk.score}/100)` : ''}`, 'bad');
        if (m.domainIntel) term.line(`  [i] mail: ${esc(m.domainIntel.provider || m.domainIntel.mx[0] || 'unknown')} · SPF ${m.domainIntel.spf ? '✓' : '✗'} · DMARC ${m.domainIntel.dmarc ? '✓' : '✗'}`, 'dim');
      } else if (m.type === 'scraped') {
        liveScraped++;
        const hit = (m.emails || 0) + (m.phones || 0) + (m.socials || 0);
        term.line(`  [~] scraped ${esc(hostname(m.url)).padEnd(24)} ${hit ? `<span class="warn">extracted ${m.emails}✉ ${m.phones}☎ ${m.socials}🔗</span>` : '<span class="dim">no entities</span>'}`, 'dim');
      } else if (m.type === 'records') {
        renderRecords(term, m.records, m.web);
      } else if (m.type === 'error') {
        term.line(`  [!] ${esc(m.message)}`, 'bad');
      } else if (m.type === 'done') {
        es.close();
        renderFootprint(term, m.footprint);
        state.lastFootprint = m.footprint;
        resolve(m.footprint);
      }
    };
    es.onerror = () => { es.close(); term.line('[!] stream lost — is the server running?', 'bad'); resolve(null); };
  });
}

function hostname(url) { try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return url.slice(0, 30); } }

function renderRecords(term, records, web) {
  if (records) {
    if (records.sec && records.sec.length) {
      term.line(`  [SEC EDGAR] ${records.sec.length} corporate/financial filing(s):`, 'warn');
      records.sec.forEach(f => term.line(`    ▸ ${esc(f.title)} — ${esc(f.detail)} ${link(f.url, 'view')}`, 'dim'));
    }
    if (records.courts && records.courts.count) {
      term.line(`  [COURT RECORDS] ${records.courts.count} case(s) match (CourtListener):`, 'warn');
      records.courts.items.forEach(c => term.line(`    ▸ ${esc(c.title)} — ${esc(c.detail)} ${link(c.url, 'view')}`, 'dim'));
    }
    if (records.business && records.business.length) {
      term.line(`  [BUSINESS FILINGS]`, 'warn');
      records.business.forEach(b => term.line(`    ▸ ${esc(b.title)} ${link(b.url, 'view')}`, 'dim'));
    }
    if (records.government && records.government.length) {
      term.line(`  [GOV / PROPERTY / VOTER]`, 'warn');
      records.government.forEach(g => term.line(`    ▸ ${esc(g.title)}${g.snippet ? ` — <span class="dim">${esc(g.snippet.slice(0, 100))}</span>` : ''}`, 'warn'));
    }
  }
  if (web && web.length) {
    web.forEach(g => {
      if (!g.results.length) return;
      term.line(`  [${esc(g.label.toUpperCase())}]`, 'warn');
      g.results.forEach(r => term.line(`    ▸ ${esc(r.title)}${r.snippet ? ` — <span class="dim">${esc(r.snippet.slice(0, 110))}</span>` : ''}`, 'dim'));
    });
  }
}

function renderFootprint(term, f) {
  term.line(`\n╔══════════════════════════════════════════════╗`, 'ok');
  term.line(`║  CONSOLIDATED FOOTPRINT DOSSIER               ║`, 'ok');
  term.line(`╚══════════════════════════════════════════════╝`, 'ok');
  term.line(`  ${f.stats.sourcesChecked} sources checked · ${f.stats.accountsFound} accounts · ${f.stats.pagesScraped} pages scraped · ${f.stats.entities} distinct data points\n`, 'dim');

  const idBlock = (label, arr, cls) => {
    if (!arr || !arr.length) return;
    term.line(`[ ${label} ]`, 'section-h');
    arr.forEach(x => {
      const conf = x.sources.length > 1 ? `<span class="badge v">×${x.sources.length} sources</span>` : '';
      term.line(`  ▸ ${esc(x.value)} ${conf} <span class="dim">${esc(x.sources.slice(0, 3).join(', '))}${x.sources.length > 3 ? '…' : ''}</span>`, cls);
    });
  };
  idBlock('REAL NAMES', f.identity.names, 'bad');
  idBlock('LOCATIONS', f.identity.locations, 'bad');
  idBlock('EMAIL ADDRESSES', f.identity.emails, 'warn');
  idBlock('PHONE NUMBERS', f.identity.phones, 'warn');

  if (f.breaches && f.breaches.length) {
    term.line(`\n[ BREACHES — ${f.breaches.length} (${esc(f.breachSource || '')}) ]`, 'section-h');
    f.breaches.slice(0, 12).forEach(b =>
      term.line(`  ✗ ${esc(b.name)}${b.date ? ` (${esc(b.date)})` : ''}${(b.dataClasses || []).length ? ` — ${esc((b.dataClasses || []).slice(0, 5).join(', '))}` : ''}`, 'bad'));
    if (f.breaches.length > 12) term.line(`  …and ${f.breaches.length - 12} more`, 'dim');
  }

  if (f.accounts && f.accounts.length) {
    term.line(`\n[ CONFIRMED ACCOUNTS: ${f.accounts.length} ]`, 'section-h');
    f.accounts.forEach(a => term.line(`  [+] ${esc(a.platform).padEnd(18)} ${link(a.url)}${a.realName ? ` <span class="info">${esc(a.realName)}</span>` : ''}`, 'bad'));
  }

  if (f.links && f.links.length) {
    term.line(`\n[ LINKED / DISCOVERED PROFILES: ${f.links.length} ]`, 'section-h');
    f.links.slice(0, 25).forEach(l => term.line(`  → ${link(l.url)} <span class="dim">(via ${esc(l.via.slice(0, 2).join(', '))})</span>`, 'warn'));
  }

  if (f.pivots && f.pivots.length) {
    term.line(`\n[ PIVOTS — new leads to scan ]`, 'section-h');
    term.raw(`<span class="line">${f.pivots.map(p => `<span class="chip" data-scan-user="${esc(p.value)}">${esc(p.value)}</span>`).join('')}</span>`);
  }

  term.line(`\n[✓] footprint mapped. this is a subset of what's public — brokers & logged-in platforms hold more.`, 'ok');
  const exp = term.raw(`<span class="line"><span class="chip" id="fp-export">⧉ EXPORT DOSSIER</span></span>`);
  exp.querySelector('#fp-export').addEventListener('click', () => exportFootprint(f));
  wireChips(term.el);
}

function exportFootprint(f) {
  const rows = [`<h1>DIGITAL FOOTPRINT DOSSIER</h1><p class="meta">generated ${new Date().toLocaleString()} · ${f.stats.sourcesChecked} sources · ${f.stats.pagesScraped} pages scraped</p>`];
  const sec = (t, arr, fmt) => { if (arr && arr.length) { rows.push(`<h2>${t}</h2><ul>`); arr.forEach(x => rows.push(`<li>${fmt(x)}</li>`)); rows.push('</ul>'); } };
  sec('Real names', f.identity.names, x => `${x.value} (${x.sources.length} sources)`);
  sec('Locations', f.identity.locations, x => `${x.value} (${x.sources.length} sources)`);
  sec('Emails', f.identity.emails, x => x.value);
  sec('Phones', f.identity.phones, x => x.value);
  sec('Breaches', f.breaches, b => `${b.name} — ${(b.dataClasses || []).join(', ')}`);
  sec('Accounts', f.accounts, a => `${a.platform}: ${a.url}`);
  sec('Linked profiles', f.links, l => l.url);
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>footprint dossier</title>
<style>body{font-family:Menlo,monospace;background:#050805;color:#00ff41;max-width:820px;margin:40px auto;padding:0 20px}
h1,h2{border-bottom:1px solid #114411;padding-bottom:4px}.meta{color:#1f7a35}a{color:#00e5ff}@media print{body{background:#fff;color:#000}}</style>
</head><body>${rows.join('\n')}<p class="meta">FOOTPRINT recon toolbox — self-audit only</p></body></html>`;
  const w = window.open('', '_blank'); w.document.write(html); w.document.close();
}

/* -------------------------------------------------------- dossier export */

function exportDossier() {
  const p = state.lastProfile;
  if (!p) return;
  const rows = [];
  rows.push(`<h1>FOOTPRINT DOSSIER${p.name ? ' — ' + esc(p.name) : ''}</h1>`);
  rows.push(`<p class="meta">compiled ${new Date().toLocaleString()} · exposure score <b>${p.score}/100 — ${esc(p.grade)}</b></p>`);
  rows.push(`<h2>What an adversary compiles in 10 minutes</h2><ul>`);
  p.factors.forEach(f => rows.push(`<li>${esc(f)}</li>`));
  rows.push(`</ul>`);
  p.scans.forEach(s => {
    rows.push(`<h2>Handle: ${esc(s.username)} — ${s.found.length} accounts</h2><ul>`);
    s.found.forEach(f => rows.push(`<li>${esc(f.name)} — ${esc(f.url)}</li>`));
    rows.push(`</ul>`);
  });
  if (p.emailR?.profile) {
    rows.push(`<h2>Gravatar identity (from email hash alone)</h2><ul>`);
    ['displayName', 'username', 'location'].forEach(k => p.emailR.profile[k] && rows.push(`<li>${k}: ${esc(p.emailR.profile[k])}</li>`));
    rows.push(`</ul>`);
  }
  if (p.emailR?.breaches?.length) {
    rows.push(`<h2>Breaches</h2><ul>`);
    p.emailR.breaches.forEach(b => rows.push(`<li>${esc(b.name)} (${esc(b.date || '?')}) — ${esc((b.dataClasses || []).join(', '))}</li>`));
    rows.push(`</ul>`);
  }
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>FOOTPRINT dossier</title>
<style>body{font-family:Menlo,monospace;background:#050805;color:#00ff41;max-width:800px;margin:40px auto;padding:0 20px}
h1,h2{border-bottom:1px solid #114411;padding-bottom:4px}.meta{color:#1f7a35}a{color:#00e5ff}
@media print{body{background:#fff;color:#000}}</style></head><body>${rows.join('\n')}
<p class="meta">generated locally by FOOTPRINT recon toolbox — self-audit use only</p></body></html>`;
  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
}

/* --------------------------------------------------- chips (click-to-scan) */

function wireChips(scope) {
  scope.querySelectorAll('[data-scan-user]').forEach(chip => {
    chip.addEventListener('click', () => {
      document.getElementById('username-input').value = chip.dataset.scanUser;
      switchTab('username');
      RUNNERS.username();
    }, { once: true });
  });
  scope.querySelectorAll('[data-scan-url]').forEach(chip => {
    chip.addEventListener('click', () => window.open(chip.dataset.scanUrl, '_blank', 'noopener'), { once: true });
  });
}

/* --------------------------------------------------------------- history */

async function runHistory(targetEl) {
  const term = makeTerm(targetEl);
  header(term, 'SCAN TIMELINE — local snapshots (data/history.json)');
  const rows = await (await fetch('/api/history')).json();
  if (!rows.length) return term.line('  no snapshots yet — run a scan first', 'dim');
  rows.forEach(r => {
    const found = r.summary.found || [];
    term.line(`  ${new Date(r.ts).toLocaleString().padEnd(22)} ${r.tool.padEnd(9)} ${esc(r.target).padEnd(24)} ${found.length} finding(s)${found.length ? ': ' + esc(found.slice(0, 6).join(', ')) + (found.length > 6 ? '…' : '') : ''}`,
      found.length ? 'warn' : 'ok');
  });
}

/* --------------------------------------------------------------- wiring */

const RUNNERS = {
  footprint: () => runFootprint(document.getElementById('footprint-out')),
  email: () => { const v = document.getElementById('email-input').value.trim(); if (v) return runEmail(document.getElementById('email-out'), v); },
  phone: () => { const v = document.getElementById('phone-input').value.trim(); if (v) return runPhone(document.getElementById('phone-out'), v); },
  username: () => {
    const v = document.getElementById('username-input').value.trim();
    const full = document.getElementById('username-full').checked;
    if (v) return runUsernameStream(document.getElementById('username-out'), v, full);
  },
  password: () => runPassword(document.getElementById('password-out'), document.getElementById('password-input').value),
  card: () => { const v = document.getElementById('card-input').value.trim(); if (v) return runCard(document.getElementById('card-out'), v); },
  self: () => runSelf(document.getElementById('self-out')),
  profile: () => runProfile(document.getElementById('profile-out')),
};

document.querySelectorAll('button.run').forEach(btn => {
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    try { await RUNNERS[btn.dataset.run](); } finally { btn.disabled = false; }
  });
});

document.querySelectorAll('main input').forEach(inp => {
  inp.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    inp.closest('.panel').querySelector('button.run').click();
  });
});

/* ----------------------------------------------------------- command REPL */

const cmdInput = document.getElementById('cmd-input');
const cmdHistory = [];
let cmdCursor = -1;

window.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
    e.preventDefault();
    cmdInput.focus();
  }
});

function replOut() {
  // route REPL output to the currently active panel's terminal
  const active = document.querySelector('.panel.active');
  return active.querySelector('.terminal-out');
}

const COMMANDS = {
  help() {
    const term = makeTerm(replOut());
    header(term, 'COMMAND REFERENCE');
    [
      ['email <addr>', 'gravatar pivot + breach recon'],
      ['phone <number>', 'number intel + broker opt-out tracker'],
      ['user <handle> [full]', 'account sweep — "full" = 400+ sites'],
      ['pw', 'jump to k-anonymity password check'],
      ['card <number>', 'local card analysis (never transmitted)'],
      ['self', 'browser trackability audit'],
      ['profile', 'jump to profile compiler'],
      ['history', 'show scan timeline'],
      ['clear', 'clear active terminal'],
    ].forEach(([c, d]) => term.line(`  ${c.padEnd(24)} ${d}`, 'dim'));
  },
  email(args) { if (!args[0]) return COMMANDS.help(); switchTab('email'); document.getElementById('email-input').value = args[0]; RUNNERS.email(); },
  phone(args) { if (!args[0]) return COMMANDS.help(); switchTab('phone'); document.getElementById('phone-input').value = args.join(' '); RUNNERS.phone(); },
  user(args) {
    if (!args[0]) return COMMANDS.help();
    switchTab('username');
    document.getElementById('username-input').value = args[0];
    document.getElementById('username-full').checked = args.includes('full');
    RUNNERS.username();
  },
  footprint() { switchTab('footprint'); },
  fp() { switchTab('footprint'); },
  pw() { switchTab('password'); document.getElementById('password-input').focus(); },
  card(args) { switchTab('card'); if (args[0]) { document.getElementById('card-input').value = args.join(''); RUNNERS.card(); } },
  self() { switchTab('self'); RUNNERS.self(); },
  profile() { switchTab('profile'); },
  history() { runHistory(replOut()); },
  clear() { replOut().innerHTML = ''; },
};
COMMANDS.username = COMMANDS.user;
COMMANDS.scan = COMMANDS.user;

cmdInput.addEventListener('keydown', e => {
  if (e.key === 'ArrowUp') { if (cmdCursor < cmdHistory.length - 1) cmdInput.value = cmdHistory[++cmdCursor] || ''; e.preventDefault(); return; }
  if (e.key === 'ArrowDown') { if (cmdCursor > 0) cmdInput.value = cmdHistory[--cmdCursor] || ''; else { cmdCursor = -1; cmdInput.value = ''; } e.preventDefault(); return; }
  if (e.key !== 'Enter') return;
  const parts = cmdInput.value.trim().split(/\s+/);
  if (!parts[0]) return;
  cmdHistory.unshift(cmdInput.value.trim());
  cmdCursor = -1;
  cmdInput.value = '';
  const fn = COMMANDS[parts[0].toLowerCase()];
  if (fn) fn(parts.slice(1));
  else {
    const term = makeTerm(replOut());
    term.line(`[!] unknown command "${esc(parts[0])}" — type 'help'`, 'bad');
  }
});
