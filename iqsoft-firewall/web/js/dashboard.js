(function () {
  if (!Auth.guard()) return;

  const $ = (id) => document.getElementById(id);

  const MAX_POINTS = 120;          // live traffic points kept (3 seconds each)
  const SPARK_POINTS = 60;
  const POLL_MS = 3000;
  const SLOW_EVERY = 4;            // slow data is read every 4th poll
  const LOG_LIMIT = 1000;
  const EVENT_LIMIT = 500;         // most the IDS and antivirus APIs return per request
  const BUCKETS = 36;

  const RANGES = {
    '1h': { sec: 3600, label: 'Last Hour' },
    '24h': { sec: 86400, label: 'Last 24h' },
    '7d': { sec: 604800, label: 'Last 7 Days' }
  };

  const PROTO_ORDER = ['HTTPS', 'HTTP', 'DNS', 'SSH', 'Other'];
  const PROTO_COLORS = { HTTPS: '#1b7cf5', HTTP: '#6cc0ff', DNS: '#8a5cff', SSH: '#17c9a8', Other: '#a5b1c6' };
  const SPARK_COLORS = { total: '#0a7cf5', allowed: '#12b76a', blocked: '#f0334a', threats: '#f59f00' };

  // World map as dots: 100 columns x 38 rows, 3.6 degrees per dot, top row = 80 N.
  const MAP_COLS = 100, MAP_ROWS = 38, MAP_CELL = 3.6, MAP_TOP = 80;
  const MAP_MASK = [
    '0000000000000000000000011111101111111111111110000000011110000000000000000000011000000000000000000000',
    '0000000000000001111110111111000000111111111110000000000000000000011000000111111111000000110000000000',
    '0000011110000001111111111111111000011111111100000000000011100000010001111111111111111111111111000000',
    '1100111111111111111111111110011110011111110000000000001111111111111111111111111111111111111111111111',
    '0100111111111111111111111110111100011110000011000000111111111111111111111111111111111111111111111111',
    '0000111111111111111111110000111000000100000000000001111011111111111111111111111111111111111110111100',
    '0000001000000111111111111100111110000000000000001100111011111111111111111111111111111111100001100000',
    '0000000000000011111111111111111111100000000000011101111111111111111111111111111111111111110001100000',
    '0000000000000001111111111111111111100000000000000111111111111111111111111111111111111111110000000000',
    '0000000000000001111111111111111110000000000000000111111111111111111111111111111111111111010000000000',
    '0000000000000001111111111111111000000000000000011110011111010111111111111111111111111110010000000000',
    '0000000000000000111111111111100000000000000000011100001111111111011111111111111111111100110000000000',
    '0000000000000000111111111111100000000000000000001111100000011111111111111111111111110111100000000000',
    '0000000000000000011111111111000000000000000000011111111111111111111111111111111111110010000000000000',
    '0000000000000000001111100001000000000000000000111111111111111111111111111111111111110000000000000000',
    '0000000000000000000111100000000000000000000001111111111111111111111011111111111111110000000000000000',
    '0000000000000000000001100100100000000000000001111111111111111111110000111101111110000000000000000000',
    '0000000000000000000000111100000000000000000001111111111111111111110000111000111100010000000000000000',
    '0000000000000000000000000110000000000000000001111111111111111111000000010000011110000000000000000000',
    '0000000000000000000000000011111110000000000000111111111111111111000000010000010100001000000000000000',
    '0000000000000000000000000000111111100000000000011111111111111111000000001000001000101000000000000000',
    '0000000000000000000000000000111111110000000000000000111111111110000000000000011001100000000000000000',
    '0000000000000000000000000001111111111100000000000000111111111100000000000000001011110000000000000000',
    '0000000000000000000000000001111111111111000000000000011111111000000000000000001100010001111000000000',
    '0000000000000000000000000000111111111111000000000000011111111000000000000000000011000000111000000000',
    '0000000000000000000000000000111111111111000000000000011111111000000000000000000000000011010000000000',
    '0000000000000000000000000000011111111110000000000000011111111001000000000000000000001111011000000000',
    '0000000000000000000000000000001111111110000000000000011111110011000000000000000000011111111000000000',
    '0000000000000000000000000000001111111110000000000000001111110011000000000000000001111111111100000000',
    '0000000000000000000000000000001111111000000000000000001111100000000000000000000001111111111110000000',
    '0000000000000000000000000000001111110000000000000000001111100000000000000000000000111111111110000000',
    '0000000000000000000000000000001111110000000000000000000111000000000000000000000000111001111100000000',
    '0000000000000000000000000000011111000000000000000000000000000000000000000000000000000000011100000010',
    '0000000000000000000000000000011110000000000000000000000000000000000000000000000000000000001000000010',
    '0000000000000000000000000000011100000000000000000000000000000000000000000000000000000000000000001100',
    '0000000000000000000000000000011100000000000000000000000000000000000000000000000000000000000000000000',
    '0000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000000000',
    '0000000000000000000000000000001100000000000000000000000000000000000000000000000000000000000000000000'
  ];

  const state = {
    range: '24h',
    query: '',
    expanded: false,
    rules: {},
    rulesOk: false,
    netcfg: null,
    logs: [],
    ids: [],
    av: [],
    events: [],
    feeds: [],
    hist: { rx: [], tx: [], t: [] },
    spark: { total: [], allowed: [], blocked: [], threats: [] },
    buckets: [],
    hover: -1,
    geom: null,
    prevIf: null,
    lastFast: 0,
    threatCount: 0
  };

  /* ---------------- small helpers ---------------- */

  const safe = (p) => p.catch(() => null);
  const num = (n) => Number(n || 0).toLocaleString();
  const asList = (d) => (Array.isArray(d) ? d : (d && (d.entries || d.logs || d.items)) || []);
  const cssVar = (name) => getComputedStyle(document.body).getPropertyValue(name).trim();

  function rate(bps) {
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbps';
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
    return Math.round(bps) + ' bps';
  }

  function axisRate(v) {
    return v === 0 ? '0' : rate(v).replace(/\.0+ /, ' ');
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function icon(name, cls) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'ic ' + (cls || ''));
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(ns, 'use');
    use.setAttribute('href', '#' + name);
    svg.append(use);
    return svg;
  }

  function when(t) {
    return new Date(t > 1e12 ? t : t * 1000);
  }

  function clock(t) {
    return when(t).toTimeString().slice(0, 8);
  }

  function niceMax(v) {
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / p;
    const s = n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10;
    return s * p;
  }

  function store(key, value) {
    try { localStorage.setItem(key, value); } catch (_) {}
  }

  function load(key) {
    try { return localStorage.getItem(key); } catch (_) { return null; }
  }

  function prep(c) {
    const box = c.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    c.width = Math.max(1, Math.round(box.width * dpr));
    c.height = Math.max(1, Math.round(box.height * dpr));
    const g = c.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { g, w: box.width, h: box.height };
  }

  function curve(g, pts) {
    g.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length; i++) {
      const a = pts[i - 1], b = pts[i];
      const mx = (a[0] + b[0]) / 2;
      g.bezierCurveTo(mx, a[1], mx, b[1], b[0], b[1]);
    }
  }

  /* ---------------- theme ---------------- */

  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
  }

  function initTheme() {
    applyTheme(load('iqsoft.theme') === 'dark' ? 'dark' : 'light');
    $('themeBtn').addEventListener('click', () => {
      const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      store('iqsoft.theme', next);
      drawAll();
    });
  }

  /* ---------------- network traffic chart ---------------- */

  function drawChart() {
    const c = $('trafficChart');
    const { g, w, h } = prep(c);
    const left = 66, right = 8, top = 10, bottom = 26;
    const plotW = w - left - right, plotH = h - top - bottom;
    const rx = state.hist.rx, tx = state.hist.tx, ts = state.hist.t;
    const n = rx.length;
    const max = niceMax(Math.max(1e6, ...rx, ...tx) * 1.1);

    state.geom = { left, right, plotW, n };

    g.font = '12px sans-serif';
    g.textBaseline = 'middle';
    g.textAlign = 'left';
    g.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = top + (plotH * i) / 4;
      g.strokeStyle = cssVar('--line');
      g.beginPath(); g.moveTo(left, y); g.lineTo(w - right, y); g.stroke();
      g.fillStyle = cssVar('--muted');
      g.fillText(axisRate(max * (1 - i / 4)), 0, y);
    }

    if (n < 2) {
      g.fillStyle = cssVar('--muted');
      g.textAlign = 'center';
      g.fillText('Collecting live traffic…', left + plotW / 2, top + plotH / 2);
      return;
    }

    const xAt = (i) => left + (plotW * i) / (n - 1);
    const yAt = (v) => top + plotH * (1 - v / max);

    g.textBaseline = 'alphabetic';
    for (let k = 0; k <= 4; k++) {
      const idx = Math.round((k * (n - 1)) / 4);
      g.fillStyle = cssVar('--muted');
      g.textAlign = k === 0 ? 'left' : k === 4 ? 'right' : 'center';
      g.fillText(clock(ts[idx]), xAt(idx), h - 6);
    }

    const plot = (arr, color) => {
      const pts = arr.map((v, i) => [xAt(i), yAt(v)]);
      g.beginPath();
      curve(g, pts);
      g.lineWidth = 2.5;
      g.lineCap = 'round';
      g.strokeStyle = color;
      g.stroke();
      g.lineTo(pts[n - 1][0], top + plotH);
      g.lineTo(pts[0][0], top + plotH);
      g.closePath();
      const grad = g.createLinearGradient(0, top, 0, top + plotH);
      grad.addColorStop(0, color + '66');
      grad.addColorStop(1, color + '08');
      g.fillStyle = grad;
      g.fill();
    };
    plot(tx, '#8a5cff');
    plot(rx, '#0a7cf5');

    const i = state.hover;
    if (i >= 0 && i < n) {
      const x = xAt(i);
      g.save();
      g.setLineDash([4, 4]);
      g.strokeStyle = '#0a7cf5';
      g.lineWidth = 1;
      g.beginPath(); g.moveTo(x, top); g.lineTo(x, top + plotH); g.stroke();
      g.restore();
      [[rx[i], '#0a7cf5'], [tx[i], '#8a5cff']].forEach(([v, col]) => {
        g.beginPath();
        g.arc(x, yAt(v), 5, 0, Math.PI * 2);
        g.fillStyle = cssVar('--tip-bg');
        g.fill();
        g.lineWidth = 2.5;
        g.strokeStyle = col;
        g.stroke();
      });
    }
  }

  function initChartHover() {
    const c = $('trafficChart');
    const tip = $('chartTip');

    c.addEventListener('mousemove', (ev) => {
      const geom = state.geom;
      if (!geom || geom.n < 2) return;
      const box = c.getBoundingClientRect();
      const x = ev.clientX - box.left;
      const idx = Math.round(((x - geom.left) / geom.plotW) * (geom.n - 1));
      const i = Math.max(0, Math.min(geom.n - 1, idx));
      state.hover = i;
      drawChart();

      tip.replaceChildren();
      tip.append(el('b', '', clock(state.hist.t[i])));
      [['lg-blue', 'Download', state.hist.rx[i]], ['lg-violet', 'Upload', state.hist.tx[i]]].forEach(([cls, label, v]) => {
        const row = el('div');
        const dot = el('span', 'lg ' + cls);
        dot.style.display = 'inline-block';
        dot.style.marginRight = '6px';
        row.append(dot, document.createTextNode(label + ' ' + rate(v)));
        tip.append(row);
      });
      tip.hidden = false;
      const px = geom.left + (geom.plotW * i) / (geom.n - 1);
      const tw = tip.offsetWidth;
      const place = px + 14 + tw > box.width ? px - 14 - tw : px + 14;
      tip.style.left = Math.max(0, place) + 'px';
      tip.style.top = '14px';
    });

    c.addEventListener('mouseleave', () => {
      state.hover = -1;
      tip.hidden = true;
      drawChart();
    });
  }

  /* ---------------- sparklines and bars ---------------- */

  function drawSpark(id, data, color) {
    const { g, w, h } = prep($(id));
    const pad = 4;
    g.lineWidth = 2.2;
    g.lineCap = 'round';
    g.strokeStyle = color;
    g.beginPath();
    if (data.length < 2) {
      g.moveTo(0, h - pad - 4);
      g.lineTo(w, h - pad - 4);
      g.globalAlpha = 0.45;
      g.stroke();
      return;
    }
    const min = Math.min(...data), max = Math.max(...data);
    const span = max - min || 1;
    const pts = data.map((v, i) => [
      (w * i) / (data.length - 1),
      max === min ? h / 2 : pad + (h - pad * 2) * (1 - (v - min) / span)
    ]);
    curve(g, pts);
    g.stroke();
  }

  function drawBars() {
    const { g, w, h } = prep($('threatBars'));
    const data = state.buckets.length ? state.buckets : new Array(BUCKETS).fill(0);
    const n = data.length, gap = 2;
    const bw = Math.max(2, (w - gap * (n - 1)) / n);
    const max = Math.max(1, ...data);
    const grad = g.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, '#4aa3ff');
    grad.addColorStop(1, '#0a64d8');
    data.forEach((v, i) => {
      const bh = v > 0 ? Math.max(4, (v / max) * (h - 4)) : 3;
      g.globalAlpha = v > 0 ? 1 : 0.25;
      g.fillStyle = grad;
      const x = i * (bw + gap), y = h - bh;
      g.beginPath();
      if (g.roundRect) g.roundRect(x, y, bw, bh, Math.min(2, bw / 2)); else g.rect(x, y, bw, bh);
      g.fill();
    });
    g.globalAlpha = 1;
  }

  function drawSparks() {
    drawSpark('spTotal', state.spark.total, SPARK_COLORS.total);
    drawSpark('spAllowed', state.spark.allowed, SPARK_COLORS.allowed);
    drawSpark('spBlocked', state.spark.blocked, SPARK_COLORS.blocked);
    drawSpark('spThreats', state.spark.threats, SPARK_COLORS.threats);
  }

  /* ---------------- threat map ---------------- */

  function drawMap(points) {
    const c = $('mapCanvas');
    c.style.height = Math.round((c.parentElement.clientWidth * MAP_ROWS) / MAP_COLS) + 'px';
    const { g, w, h } = prep(c);
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    const sp = Math.min(w / MAP_COLS, h / MAP_ROWS);
    const ox = (w - sp * MAP_COLS) / 2, oy = (h - sp * MAP_ROWS) / 2;

    g.fillStyle = dark ? 'rgba(130, 170, 235, 0.55)' : 'rgba(10, 124, 245, 0.38)';
    MAP_MASK.forEach((row, y) => {
      for (let x = 0; x < row.length; x++) {
        if (row[x] === '1') {
          g.beginPath();
          g.arc(ox + (x + 0.5) * sp, oy + (y + 0.5) * sp, sp * 0.32, 0, Math.PI * 2);
          g.fill();
        }
      }
    });

    points.forEach((p) => {
      const x = ox + ((p.lon + 180) / (MAP_COLS * MAP_CELL)) * sp * MAP_COLS;
      const y = oy + ((MAP_TOP - p.lat) / (MAP_ROWS * MAP_CELL)) * sp * MAP_ROWS;
      const glow = g.createRadialGradient(x, y, 0, x, y, sp * 5);
      glow.addColorStop(0, 'rgba(240, 51, 74, 0.85)');
      glow.addColorStop(1, 'rgba(240, 51, 74, 0)');
      g.fillStyle = glow;
      g.beginPath(); g.arc(x, y, sp * 5, 0, Math.PI * 2); g.fill();
      g.fillStyle = '#f0334a';
      g.beginPath(); g.arc(x, y, sp * 0.9, 0, Math.PI * 2); g.fill();
    });

    $('mapEmpty').hidden = points.length > 0;
  }

  function drawAll() {
    drawChart();
    drawSparks();
    drawBars();
    drawMap([]);
  }

  /* ---------------- stat cards ---------------- */

  function pushSpark(key, value) {
    const a = state.spark[key];
    a.push(value);
    if (a.length > SPARK_POINTS) a.shift();
  }

  function trendText(key) {
    const a = state.spark[key];
    if (a.length < 2) return '–';
    const first = a[0], cur = a[a.length - 1];
    if (first === 0) return cur > 0 ? '↑ new' : '↑ 0.0%';
    const pct = ((cur - first) / first) * 100;
    return (pct >= 0 ? '↑ +' : '↓ ') + Math.abs(pct).toFixed(1) + '%';
  }

  function setStat(key, valueId, trendId, value) {
    $(valueId).textContent = num(value);
    pushSpark(key, value);
    $(trendId).textContent = trendText(key);
  }

  /* ---------------- gauges ---------------- */

  function setGauge(arcId, pctId, pct) {
    const arc = $(arcId);
    if (pct == null || isNaN(pct)) {
      arc.setAttribute('stroke-dasharray', '0 100');
      $(pctId).textContent = '–';
      return;
    }
    const p = Math.max(0, Math.min(100, Number(pct)));
    arc.setAttribute('stroke-dasharray', (p * 0.75).toFixed(1) + ' 100');
    $(pctId).textContent = Math.round(p) + '%';
  }

  /* ---------------- interfaces ---------------- */

  function updateInterfaces(list, dt) {
    const rates = {};
    list.forEach((i) => {
      let r = 0, t = 0;
      const p = state.prevIf && state.prevIf[i.name];
      if (p && dt > 0) {
        r = Math.max(0, ((i.rx_bytes - p.rx) * 8) / dt);
        t = Math.max(0, ((i.tx_bytes - p.tx) * 8) / dt);
      }
      rates[i.name] = { r, t, down: String(i.state).toLowerCase() === 'down' };
    });
    state.prevIf = {};
    list.forEach((i) => { state.prevIf[i.name] = { rx: i.rx_bytes, tx: i.tx_bytes }; });
    return rates;
  }

  function renderInterfaces(rates) {
    const ul = $('ifList');
    ul.replaceChildren();
    const wan = state.netcfg && state.netcfg.wan_interface;
    const lan = state.netcfg && state.netcfg.lan_interface;
    const names = Object.keys(rates).filter((n) => n !== 'lo');

    const rank = (n) => (n === wan ? 0 : n === lan ? 1 : rates[n].down ? 3 : 2);
    names.sort((a, b) => rank(a) - rank(b) || (rates[b].r + rates[b].t) - (rates[a].r + rates[a].t));

    const shown = names.slice(0, 5);
    shown.forEach((n) => {
      const v = rates[n];
      const li = el('li');
      const label = el('b', '', n === wan ? 'WAN' : n === lan ? 'LAN' : n);
      li.append(el('span', 'dot ' + (v.down ? 'bad' : 'ok')), label);
      if (n === wan || n === lan) {
        const sub = el('span', '', '(' + n + ')');
        sub.style.color = 'var(--muted)';
        sub.style.fontSize = '13px';
        li.append(sub);
      }
      const rr = el('span', 'rates');
      rr.append(el('span', 'up', '↑ ' + rate(v.t).replace(' ', '')), el('span', 'down', '↓ ' + rate(v.r).replace(' ', '')));
      li.append(rr);
      ul.append(li);
    });
    if (names.length > shown.length) {
      const more = el('li');
      more.append(el('span', 'empty', '+' + (names.length - shown.length) + ' more interfaces'));
      ul.append(more);
    }
    if (!names.length) {
      const li = el('li');
      li.append(el('span', 'empty', 'No interfaces found'));
      ul.append(li);
    }

    // Download / upload: use the WAN port when it is known, otherwise add all ports together.
    if (wan && rates[wan]) return { rx: rates[wan].r, tx: rates[wan].t };
    let rx = 0, tx = 0;
    names.forEach((n) => { rx += rates[n].r; tx += rates[n].t; });
    return { rx, tx };
  }

  /* ---------------- protocols ---------------- */

  function classify(c) {
    const p = String(c.protocol).toLowerCase();
    const d = c.dport;
    if (d === 443) return 'HTTPS';
    if (d === 80 && p === 'tcp') return 'HTTP';
    if (d === 53) return 'DNS';
    if (d === 22 && p === 'tcp') return 'SSH';
    return 'Other';
  }

  function renderProtocols(conns, total) {
    const counts = {};
    PROTO_ORDER.forEach((k) => { counts[k] = 0; });
    conns.forEach((c) => { counts[classify(c)]++; });
    const sum = conns.length || 1;
    const arcs = $('donutArcs'), legend = $('protoLegend');
    arcs.replaceChildren();
    legend.replaceChildren();

    let offset = 0;
    PROTO_ORDER.forEach((k) => {
      const pct = (counts[k] / sum) * 100;
      if (pct > 0) {
        const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        c.setAttribute('cx', 21); c.setAttribute('cy', 21); c.setAttribute('r', 15.9155);
        c.setAttribute('fill', 'none');
        c.setAttribute('stroke', PROTO_COLORS[k]);
        c.setAttribute('stroke-width', 5);
        c.setAttribute('stroke-dasharray', pct.toFixed(2) + ' ' + (100 - pct).toFixed(2));
        c.setAttribute('stroke-dashoffset', (-offset).toFixed(2));
        arcs.append(c);
        offset += pct;
      }
      const li = el('li');
      const sw = el('span', 'lg');
      sw.style.background = PROTO_COLORS[k];
      li.append(sw, el('span', '', k), el('em', '', conns.length ? pct.toFixed(1) + '%' : '–'));
      legend.append(li);
    });
    $('donutTotal').textContent = num(total);
  }

  /* ---------------- security events: firewall + IDS + antivirus ---------------- */

  const secs = (t) => { t = Number(t) || 0; return t > 1e12 ? t / 1000 : t; };

  function ruleOf(l) { return state.rules[l.rule_id]; }

  function fwBlock(l) {
    const r = ruleOf(l);
    const a = r ? String(r.action).toLowerCase() : '';
    return a === 'drop' || a === 'reject';
  }

  function fwName(l) {
    const r = ruleOf(l);
    return r && r.name ? r.name : 'Rule ' + l.rule_id;
  }

  // One list for everything that can show up as a security event, newest first.
  function buildEvents() {
    const out = [];
    state.logs.forEach((l) => {
      const block = fwBlock(l);
      out.push({
        kind: 'fw', time: secs(l.time), src: l.src, dst: l.dst, sport: l.sport, dport: l.dport,
        protocol: l.protocol, block, threat: block, name: fwName(l), rule_id: l.rule_id
      });
    });
    state.ids.forEach((e) => {
      out.push({
        kind: 'ids', time: secs(e.ts), src: e.src_ip, dst: e.dest_ip, sport: e.src_port, dport: e.dest_port,
        protocol: e.proto, block: String(e.action).toLowerCase() === 'blocked', threat: true,
        name: e.signature || 'IDS alert'
      });
    });
    state.av.forEach((e) => {
      out.push({
        kind: 'av', time: secs(e.ts), src: e.client_ip, dst: e.host, sport: null, dport: null,
        protocol: 'http', block: String(e.action).toLowerCase().includes('block'), threat: true,
        name: e.signature || 'Malware'
      });
    });
    out.sort((a, b) => b.time - a.time);
    state.events = out;
  }

  function shortName(s) {
    s = String(s);
    return s.length > 15 ? s.slice(0, 14) + '…' : s;
  }

  function target(l) {
    return l.dst + (l.dport ? ':' + l.dport : '');
  }

  function inRange(l, back) {
    const now = Date.now() / 1000;
    const sec = RANGES[state.range].sec;
    return l.time >= now - sec * (back + 1) && l.time < now - sec * back + (back === 0 ? 60 : 0);
  }

  function matches(l) {
    const q = state.query;
    if (!q) return true;
    const kind = l.kind === 'ids' ? 'ids intrusion' : l.kind === 'av' ? 'antivirus malware virus' : 'firewall';
    return [l.src, l.dst, l.dport, l.sport, l.protocol, l.name, l.rule_id, kind]
      .some((v) => v != null && String(v).toLowerCase().includes(q));
  }

  function verb(l) {
    if (l.kind === 'fw') return l.block ? 'Blocked' : 'Allowed';
    return l.block ? 'Blocked' : 'Detected';
  }

  function message(l) {
    if (l.kind === 'ids') return verb(l) + ' intrusion “' + l.name + '” from ' + l.src + ' to ' + target(l);
    if (l.kind === 'av') return verb(l) + ' malware ' + l.name + ' for ' + l.src + ' (' + l.dst + ')';
    return verb(l) + ' ' + String(l.protocol).toUpperCase() + ' from ' + l.src + ' to ' + target(l);
  }

  function tagText(l) {
    return l.kind === 'ids' ? 'IDS' : l.kind === 'av' ? 'Antivirus' : shortName(l.name);
  }

  function tagClass(l) {
    if (l.block) return 'tag-red';
    return l.kind === 'fw' ? 'tag-blue' : 'tag-orange';
  }

  function renderThreats() {
    const now = Date.now() / 1000;
    const sec = RANGES[state.range].sec;
    $('threatRange').textContent = RANGES[state.range].label;

    const threats = state.events.filter((l) => l.threat && inRange(l, 0));
    $('threatCount').textContent = num(threats.length);

    // Compare with the same length of time just before this one.
    const prev = state.events.filter((l) => l.threat && inRange(l, 1)).length;
    // The trend is only trusted when every source reached back far enough.
    const sources = [[state.logs, LOG_LIMIT, 'time'], [state.ids, EVENT_LIMIT, 'ts'], [state.av, EVENT_LIMIT, 'ts']];
    const complete = sources.every(([list, limit, key]) =>
      list.length < limit || Math.min(...list.map((x) => secs(x[key]))) <= now - sec * 2);
    const pill = $('threatTrend');
    if (!complete) {
      pill.textContent = '–';
    } else if (prev === 0) {
      pill.textContent = threats.length ? '↑ new' : '0%';
    } else {
      const pct = ((threats.length - prev) / prev) * 100;
      pill.textContent = (pct >= 0 ? '↑ +' : '↓ ') + Math.abs(pct).toFixed(1) + '%';
    }
    const up = pill.textContent.startsWith('↑') || pill.textContent === '–';
    pill.style.color = up ? '' : '#12a05b';
    pill.style.background = up ? '' : 'rgba(18, 160, 91, 0.14)';

    // Bars: events per time slot across the chosen range.
    const buckets = new Array(BUCKETS).fill(0);
    threats.forEach((l) => {
      const age = now - l.time;
      const idx = BUCKETS - 1 - Math.min(BUCKETS - 1, Math.floor((age / sec) * BUCKETS));
      buckets[Math.max(0, idx)]++;
    });
    state.buckets = buckets;
    drawBars();

    $('stThreats').textContent = num(threats.length);
    state.threatCount = threats.length;
    return threats;
  }

  function renderTopBlocked(threats) {
    const bySrc = {};
    threats.filter(matches).forEach((l) => {
      const s = bySrc[l.src] || (bySrc[l.src] = { n: 0, ports: new Set(), name: l.name, kind: l.kind });
      s.n++;
      if (l.dport) s.ports.add(l.dport);
    });
    const top = Object.entries(bySrc).sort((a, b) => b[1].n - a[1].n).slice(0, 5);
    const tb = $('topSrc');
    tb.replaceChildren();
    if (!top.length) {
      const tr = el('tr');
      const td = el('td', 'empty', state.query ? 'No matches' : 'No threats logged');
      td.colSpan = 3;
      tr.append(td);
      tb.append(tr);
      return;
    }
    top.forEach(([ip, s]) => {
      const scan = s.ports.size >= 5;
      const label = scan ? 'Port Scan' : s.kind === 'av' ? 'Malware' : shortName(s.name);
      const tr = el('tr');
      const tdTag = el('td');
      const tag = el('span', 'tag ' + (scan ? 'tag-orange' : 'tag-red'), label);
      tag.title = s.name;
      tdTag.append(tag);
      tr.append(el('td', '', ip), el('td', '', num(s.n)), tdTag);
      tb.append(tr);
    });
  }

  function renderEvents() {
    const ev = $('events');
    ev.replaceChildren();
    const list = state.events.filter((l) => inRange(l, 0)).filter(matches)
      .slice(0, state.expanded ? 30 : 6);

    $('viewAllEvents').firstChild.textContent = state.expanded ? 'Show Less' : 'View All';

    if (!list.length) {
      const li = el('li');
      li.append(el('span', 'empty', state.query ? 'No matching events.' : 'No events logged. Turn on logging for a rule to see traffic here.'));
      ev.append(li);
      return;
    }
    list.forEach((l) => {
      const li = el('li');
      const t = el('span', 't', clock(l.time));
      t.title = when(l.time).toLocaleString();
      const ic = icon(l.block ? 'i-ban' : l.kind === 'fw' ? 'i-shield-check' : 'i-alert', 'ev-ic');
      if (!l.block) ic.style.color = l.kind === 'fw' ? '#12a05b' : '#f59f00';
      const tag = el('span', 'tag ' + tagClass(l), tagText(l));
      tag.title = l.name;
      li.append(t, ic, el('span', 'msg', message(l)), tag);
      ev.append(li);
    });
  }

  function renderLogPanels() {
    buildEvents();
    const threats = renderThreats();
    renderTopBlocked(threats);
    renderEvents();
    renderBell();
  }

  /* ---------------- notifications ---------------- */

  function renderBell() {
    const items = [];
    state.events.filter((l) => l.threat).slice(0, 6).forEach((l) => {
      items.push({
        t: l.time,
        text: message(l),
        sub: (l.kind === 'fw' ? l.name : tagText(l)) + ' · ' + clock(l.time)
      });
    });
    state.feeds.filter((f) => f.last_error).forEach((f) => {
      items.push({
        t: f.last_attempt || 0,
        text: 'Threat feed "' + f.name + '" failed to update',
        sub: String(f.last_error)
      });
    });
    items.sort((a, b) => b.t - a.t);
    const shown = items.slice(0, 8);

    const ul = $('bellList');
    ul.replaceChildren();
    if (!shown.length) {
      ul.append(el('li', 'empty', 'No notifications'));
    }
    shown.forEach((it) => {
      const li = el('li', '', it.text);
      li.append(el('small', '', it.sub));
      ul.append(li);
    });

    const seen = Number(load('iqsoft.bellSeen')) || 0;
    $('bellDot').hidden = !shown.some((it) => it.t > seen);
  }

  function initBell() {
    if (!load('iqsoft.bellSeen')) store('iqsoft.bellSeen', String(Math.floor(Date.now() / 1000)));
    const panel = $('bellPanel');
    $('bellBtn').addEventListener('click', (ev) => {
      ev.stopPropagation();
      panel.hidden = !panel.hidden;
      if (!panel.hidden) {
        store('iqsoft.bellSeen', String(Math.floor(Date.now() / 1000)));
        $('bellDot').hidden = true;
      }
    });
    panel.addEventListener('click', (ev) => ev.stopPropagation());
    document.addEventListener('click', () => { panel.hidden = true; });
    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') panel.hidden = true; });
  }

  /* ---------------- data loading ---------------- */

  let busyFast = false, busySlow = false;

  async function fast() {
    if (busyFast) return;
    busyFast = true;
    try {
      const now = Date.now();
      const [ifs, sys] = await Promise.all([
        safe(api('/api/monitor/interfaces')),
        safe(api('/api/monitor/system'))
      ]);

      $('liveDot').className = 'dot ' + (ifs ? 'ok' : 'bad');
      $('liveText').textContent = ifs ? 'Live' : 'API error';

      if (ifs) {
        const dt = state.lastFast ? (now - state.lastFast) / 1000 : 0;
        state.lastFast = now;
        const rates = updateInterfaces(ifs, dt);
        const sum = renderInterfaces(rates);
        if (dt > 0) {
          state.hist.rx.push(sum.rx);
          state.hist.tx.push(sum.tx);
          state.hist.t.push(now);
          if (state.hist.rx.length > MAX_POINTS) {
            state.hist.rx.shift(); state.hist.tx.shift(); state.hist.t.shift();
          }
          $('lgRx').textContent = rate(sum.rx);
          $('lgTx').textContent = rate(sum.tx);
          drawChart();
        }
      }

      if (sys) {
        setGauge('gaugeCpuArc', 'gaugeCpuPct', sys.cpu_percent);
        setGauge('gaugeRamArc', 'gaugeRamPct', sys.memory_percent);
        setGauge('gaugeDiskArc', 'gaugeDiskPct', sys.disk_percent);
      }
    } finally {
      busyFast = false;
    }
  }

  async function slow() {
    if (busySlow) return;
    busySlow = true;
    try {
      const [conns, counters, logs, rules, feeds, net, idsEv, avEv] = await Promise.all([
        safe(api('/api/monitor/connections?limit=' + LOG_LIMIT)),
        safe(api('/api/monitor/rule-counters')),
        safe(api('/api/monitor/logs?limit=' + LOG_LIMIT)),
        safe(api('/api/rules')),
        safe(api('/api/threatfeeds')),
        state.netcfg ? Promise.resolve(state.netcfg) : safe(api('/api/network')),
        safe(api('/api/ids/events?limit=' + EVENT_LIMIT)),
        safe(api('/api/av/events?limit=' + EVENT_LIMIT))
      ]);

      if (net) state.netcfg = net;

      if (rules) {
        state.rules = {};
        asList(rules).forEach((r) => { state.rules[r.id] = r; });
        state.rulesOk = true;
      }
      if (feeds) state.feeds = asList(feeds);

      if (conns) {
        const list = conns.connections || [];
        setStat('total', 'stTotal', 'stTotalTrend', conns.total || 0);
        renderProtocols(list, conns.total || 0);
      }

      if (counters && state.rulesOk) {
        let allowed = 0, blocked = 0;
        asList(counters).forEach((c) => {
          const r = state.rules[c.rule_id];
          const a = r ? String(r.action).toLowerCase() : '';
          if (a === 'accept') allowed += c.packets || 0;
          else if (a === 'drop' || a === 'reject') blocked += c.packets || 0;
        });
        setStat('allowed', 'stAllowed', 'stAllowedTrend', allowed);
        setStat('blocked', 'stBlocked', 'stBlockedTrend', blocked);
      }

      if (logs) state.logs = asList(logs);
      if (idsEv) state.ids = asList(idsEv);
      if (avEv) state.av = asList(avEv);

      renderLogPanels();
      pushSpark('threats', state.threatCount || 0);
      $('stThreatsTrend').textContent = trendText('threats');
      drawSparks();
    } finally {
      busySlow = false;
      document.body.classList.remove('loading');
    }
  }

  let tick = 0;
  function loop() {
    fast();
    if (tick % SLOW_EVERY === 0) slow();
    tick++;
  }

  /* ---------------- controls ---------------- */

  function initControls() {
    $('logoutBtn').addEventListener('click', logout);

    const sel = $('rangeSelect');
    const saved = load('iqsoft.range');
    if (saved && RANGES[saved]) state.range = saved;
    sel.value = state.range;
    sel.addEventListener('change', () => {
      state.range = sel.value;
      store('iqsoft.range', state.range);
      state.spark.threats = [];
      renderLogPanels();
      $('stThreatsTrend').textContent = '–';
      drawSparks();
    });

    let timer = null;
    $('globalSearch').addEventListener('input', (ev) => {
      clearTimeout(timer);
      const v = ev.target.value.trim().toLowerCase();
      timer = setTimeout(() => {
        state.query = v;
        renderLogPanels();
      }, 150);
    });

    $('viewAllEvents').addEventListener('click', (ev) => {
      ev.preventDefault();
      state.expanded = !state.expanded;
      renderEvents();
    });

    $('refreshBtn').addEventListener('click', async () => {
      const b = $('refreshBtn');
      b.classList.add('spin');
      await Promise.all([fast(), slow()]);
      b.classList.remove('spin');
    });

    // Short explanations when the mouse rests on a card.
    $('stTotal').parentElement.title = 'Connections currently tracked by the firewall';
    $('stAllowed').parentElement.title = 'Packets accepted by firewall rules since the last commit';
    $('stBlocked').parentElement.title = 'Packets dropped or rejected by firewall rules since the last commit';
    $('stThreats').parentElement.title = 'Firewall drops, IDS alerts and antivirus detections in the chosen time range';
    ['stTotalTrend', 'stAllowedTrend', 'stBlockedTrend', 'stThreatsTrend'].forEach((id) => {
      $(id).title = 'Change since this page was opened (last few minutes)';
    });

    let rz = null;
    window.addEventListener('resize', () => {
      clearTimeout(rz);
      rz = setTimeout(drawAll, 120);
    });
  }

  /* ---------------- product version ---------------- */

  async function loadVersion() {
    try {
      const res = await fetch('/health');
      const h = await res.json();
      if (h && h.version) $('appVersion').textContent = 'v' + h.version;
    } catch (_) {}
  }

  /* ---------------- logged-in user ---------------- */

  async function loadUser() {
    try {
      const me = await api('/api/auth/me');
      if (!me || !me.username) return;
      const role = String(me.role || '');
      document.querySelector('.user-text b').textContent = me.username;
      document.querySelector('.user-text span').textContent =
        role.charAt(0).toUpperCase() + role.slice(1);
      document.querySelector('.avatar').textContent = me.username.charAt(0).toUpperCase();
    } catch (_) {}
  }

  /* ---------------- page chrome: full screen, mobile menu ---------------- */

  function initChrome() {
    const fsBtn = $('fullscreenBtn');
    if (document.fullscreenEnabled) {
      fsBtn.addEventListener('click', () => {
        if (document.fullscreenElement) document.exitFullscreen();
        else document.documentElement.requestFullscreen().catch(() => {});
      });
      document.addEventListener('fullscreenchange', () => {
        const on = !!document.fullscreenElement;
        fsBtn.setAttribute('aria-label', on ? 'Exit full screen' : 'Enter full screen');
        fsBtn.title = on ? 'Exit full screen' : 'Full screen';
        setTimeout(drawAll, 150);
      });
    } else {
      fsBtn.hidden = true;
    }

    const closeNav = () => document.body.classList.remove('nav-open');
    $('menuBtn').addEventListener('click', () => document.body.classList.toggle('nav-open'));
    $('navScrim').addEventListener('click', closeNav);
    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeNav(); });

    // Pages that do not exist yet say so instead of jumping to the top of the page.
    document.querySelectorAll('.nav-item').forEach((a) => {
      if (a.getAttribute('href') === '#') {
        a.title = 'Coming soon';
        a.addEventListener('click', (ev) => ev.preventDefault());
      } else {
        a.addEventListener('click', closeNav);
      }
    });
  }

  initTheme();
  initControls();
  initChrome();
  initBell();
  loadUser();
  loadVersion();
  initChartHover();
  drawAll();
  loop();
  setInterval(loop, POLL_MS);
})();
