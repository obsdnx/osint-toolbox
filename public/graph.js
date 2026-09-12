/* FOOTPRINT — identity link graph (vanilla canvas force-directed layout) */
'use strict';

const IdentityGraph = (() => {
  let canvas, ctx, nodes = [], edges = [], raf = null;
  let dragging = null, hovered = null, devicePR = 1;

  const COLORS = {
    identity: '#00ff41', identifier: '#00e5ff', account: '#ff3e3e',
    breach: '#ff9100', intel: '#ffb000',
  };
  const RADII = { identity: 16, identifier: 9, account: 6, breach: 7, intel: 7 };

  function init(el) {
    canvas = el;
    ctx = canvas.getContext('2d');
    devicePR = window.devicePixelRatio || 1;
    canvas.addEventListener('mousedown', onDown);
    canvas.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', () => { dragging = null; canvas.style.cursor = 'grab'; });
    canvas.addEventListener('click', onClick);
  }

  function resize() {
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * devicePR;
    canvas.height = 420 * devicePR;
    ctx.setTransform(devicePR, 0, 0, devicePR, 0, 0);
  }

  // data: { center, identifiers:[{id,label}], accounts:[{id,label,url,parent}], breaches:[...], intel:[...] }
  function build(data) {
    resize();
    const W = canvas.width / devicePR, H = 420;
    nodes = []; edges = [];
    const add = (n, x, y) => { nodes.push({ vx: 0, vy: 0, x, y, ...n }); return n.id; };

    add({ id: '@root', label: data.center || 'YOU', type: 'identity', pin: false }, W / 2, H / 2);

    const groups = [
      ['identifiers', 'identifier'], ['accounts', 'account'],
      ['breaches', 'breach'], ['intel', 'intel'],
    ];
    for (const [key, type] of groups) {
      (data[key] || []).forEach((item, i) => {
        const angle = Math.random() * Math.PI * 2;
        const dist = 80 + Math.random() * 120;
        add({ ...item, type }, W / 2 + Math.cos(angle) * dist, H / 2 + Math.sin(angle) * dist);
        edges.push({ a: item.parent || '@root', b: item.id });
      });
    }
    // drop edges whose endpoints are missing
    const ids = new Set(nodes.map(n => n.id));
    edges = edges.filter(e => ids.has(e.a) && ids.has(e.b));
    if (raf) cancelAnimationFrame(raf);
    let ticks = 0;
    const loop = () => { step(); draw(); if (++ticks < 2400) raf = requestAnimationFrame(loop); };
    loop();
  }

  function byId(id) { return nodes.find(n => n.id === id); }

  function step() {
    const W = canvas.width / devicePR, H = 420;
    // pairwise repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy || 0.01;
        if (d2 > 40000) continue;
        const f = 900 / d2;
        const d = Math.sqrt(d2);
        dx /= d; dy /= d;
        a.vx += dx * f; a.vy += dy * f;
        b.vx -= dx * f; b.vy -= dy * f;
      }
    }
    // springs
    for (const e of edges) {
      const a = byId(e.a), b = byId(e.b);
      if (!a || !b) continue;
      const rest = (a.type === 'identity' || b.type === 'identity') ? 120 : 70;
      let dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const f = (d - rest) * 0.02;
      dx /= d; dy /= d;
      a.vx += dx * f; a.vy += dy * f;
      b.vx -= dx * f; b.vy -= dy * f;
    }
    // gentle centering + integrate
    for (const n of nodes) {
      if (n === dragging) { n.vx = 0; n.vy = 0; continue; }
      n.vx += (W / 2 - n.x) * 0.0015;
      n.vy += (H / 2 - n.y) * 0.0015;
      n.vx *= 0.86; n.vy *= 0.86;
      n.x += n.vx; n.y += n.vy;
      n.x = Math.max(20, Math.min(W - 20, n.x));
      n.y = Math.max(20, Math.min(H - 20, n.y));
    }
  }

  function draw() {
    const W = canvas.width / devicePR, H = 420;
    ctx.clearRect(0, 0, W, H);
    // edges
    ctx.strokeStyle = 'rgba(0,255,65,0.25)';
    ctx.lineWidth = 1;
    for (const e of edges) {
      const a = byId(e.a), b = byId(e.b);
      if (!a || !b) continue;
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    }
    // nodes
    for (const n of nodes) {
      const r = RADII[n.type] || 6;
      const color = COLORS[n.type] || '#00ff41';
      ctx.shadowColor = color; ctx.shadowBlur = n === hovered ? 22 : 10;
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
      ctx.fillStyle = '#020402';
      ctx.beginPath(); ctx.arc(n.x, n.y, Math.max(r - 3, 2), 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = color;
      ctx.font = (n.type === 'identity' ? 'bold 12px' : '10px') + ' Menlo, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(n.label.slice(0, 26), n.x, n.y + r + 12);
    }
  }

  function nodeAt(mx, my) {
    return nodes.find(n => {
      const r = (RADII[n.type] || 6) + 6;
      return (n.x - mx) ** 2 + (n.y - my) ** 2 < r * r;
    });
  }

  function coords(ev) {
    const rect = canvas.getBoundingClientRect();
    return [ev.clientX - rect.left, ev.clientY - rect.top];
  }

  function onDown(ev) { const [x, y] = coords(ev); dragging = nodeAt(x, y) || null; if (dragging) canvas.style.cursor = 'grabbing'; }
  function onMove(ev) {
    const [x, y] = coords(ev);
    if (dragging) { dragging.x = x; dragging.y = y; }
    else { hovered = nodeAt(x, y) || null; canvas.style.cursor = hovered ? 'pointer' : 'grab'; }
  }
  function onClick(ev) {
    const [x, y] = coords(ev);
    const n = nodeAt(x, y);
    if (n && n.url) window.open(n.url, '_blank', 'noopener');
  }

  return { init, build };
})();
