(function () {
  if (!Auth.guard()) return;

  // A role without dashboard rights is sent to the first page it may open.
  if (Access.me() && !Access.canView('dashboard')) {
    const target = Access.landing();
    if (target) {
      location.replace(target);
    } else {
      Auth.clear();
      location.replace('/html/login.html');
    }
    return;
  }

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
    threatCount: 0,
    geo: {},
    geoAt: 0,
    geoBusy: false,
    geoDatasets: null,
    mapPoints: []
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

  // Where a country's dot goes on the map: [latitude, longitude] of its middle.
  const COUNTRY_POS = {
    AD:[42.5,1.5],AE:[24,54],AF:[33.9,67.7],AG:[17.1,-61.8],AL:[41.2,20.2],AM:[40.1,45],AO:[-11.2,17.9],AR:[-38.4,-63.6],
    AT:[47.5,14.6],AU:[-25.3,133.8],AZ:[40.1,47.6],BA:[43.9,17.7],BB:[13.2,-59.5],BD:[23.7,90.4],BE:[50.5,4.5],BF:[12.2,-1.6],
    BG:[42.7,25.5],BH:[26,50.6],BI:[-3.4,29.9],BJ:[9.3,2.3],BN:[4.5,114.7],BO:[-16.3,-63.6],BR:[-14.2,-51.9],BS:[25,-77.4],
    BT:[27.5,90.4],BW:[-22.3,24.7],BY:[53.7,27.9],BZ:[17.2,-88.5],CA:[56.1,-106.3],CD:[-4,21.8],CF:[6.6,20.9],CG:[-0.2,15.8],
    CH:[46.8,8.2],CI:[7.5,-5.5],CL:[-35.7,-71.5],CM:[7.4,12.4],CN:[35.9,104.2],CO:[4.6,-74.3],CR:[9.7,-83.8],CU:[21.5,-77.8],
    CY:[35.1,33.4],CZ:[49.8,15.5],DE:[51.2,10.5],DJ:[11.8,42.6],DK:[56.3,9.5],DO:[18.7,-70.2],DZ:[28,1.7],EC:[-1.8,-78.2],
    EE:[58.6,25],EG:[26.8,30.8],ER:[15.2,39.8],ES:[40.5,-3.7],ET:[9.1,40.5],FI:[61.9,25.7],FJ:[-17.7,178.1],FR:[46.2,2.2],
    GA:[-0.8,11.6],GB:[55.4,-3.4],GE:[42.3,43.4],GH:[7.9,-1],GM:[13.4,-15.3],GN:[9.9,-9.7],GQ:[1.7,10.3],GR:[39.1,21.8],
    GT:[15.8,-90.2],GW:[11.8,-15.2],GY:[4.9,-58.9],HK:[22.3,114.2],HN:[15.2,-86.2],HR:[45.1,15.2],HT:[18.97,-72.3],HU:[47.2,19.5],
    ID:[-0.8,113.9],IE:[53.4,-8.2],IL:[31,34.9],IN:[20.6,78.96],IQ:[33.2,43.7],IR:[32.4,53.7],IS:[64.96,-19],IT:[41.9,12.6],
    JM:[18.1,-77.3],JO:[30.6,36.2],JP:[36.2,138.3],KE:[-0.02,37.9],KG:[41.2,74.8],KH:[12.6,104.99],KP:[40.3,127.5],KR:[35.9,127.8],
    KW:[29.3,47.5],KZ:[48,66.9],LA:[19.9,102.5],LB:[33.9,35.9],LI:[47.2,9.6],LK:[7.9,80.8],LR:[6.4,-9.4],LS:[-29.6,28.2],
    LT:[55.2,23.9],LU:[49.8,6.1],LV:[56.9,24.6],LY:[26.3,17.2],MA:[31.8,-7.1],MC:[43.7,7.4],MD:[47.4,28.4],ME:[42.7,19.4],
    MG:[-18.8,46.9],MK:[41.6,21.7],ML:[17.6,-4],MM:[21.9,95.96],MN:[46.9,103.8],MO:[22.2,113.5],MR:[21,-10.9],MT:[35.9,14.4],
    MU:[-20.3,57.6],MV:[3.2,73.2],MW:[-13.3,34.3],MX:[23.6,-102.6],MY:[4.2,102],MZ:[-18.7,35.5],NA:[-22.96,18.5],NE:[17.6,8.1],
    NG:[9.1,8.7],NI:[12.9,-85.2],NL:[52.1,5.3],NO:[60.5,8.5],NP:[28.4,84.1],NZ:[-40.9,174.9],OM:[21.5,55.9],PA:[8.5,-80.8],
    PE:[-9.2,-75],PG:[-6.3,143.96],PH:[12.9,121.8],PK:[30.4,69.3],PL:[51.9,19.1],PR:[18.2,-66.6],PS:[31.95,35.2],PT:[39.4,-8.2],
    PY:[-23.4,-58.4],QA:[25.4,51.2],RO:[45.9,24.97],RS:[44,21],RU:[61.5,105.3],RW:[-1.9,29.9],SA:[23.9,45.1],SD:[12.9,30.2],
    SE:[60.1,18.6],SG:[1.35,103.8],SI:[46.2,14.995],SK:[48.7,19.7],SL:[8.5,-11.8],SN:[14.5,-14.5],SO:[5.2,46.2],SR:[3.9,-56],
    SS:[6.9,31.3],SV:[13.8,-88.9],SY:[34.8,39],SZ:[-26.5,31.5],TD:[15.5,18.7],TG:[8.6,0.8],TH:[15.9,100.99],TJ:[38.9,71.3],
    TL:[-8.9,125.7],TM:[38.97,59.6],TN:[33.9,9.5],TR:[38.96,35.2],TT:[10.7,-61.2],TW:[23.7,121],TZ:[-6.4,34.9],UA:[48.4,31.2],
    UG:[1.4,32.3],US:[37.1,-95.7],UY:[-32.5,-55.8],UZ:[41.4,64.6],VE:[6.4,-66.6],VN:[14.1,108.3],YE:[15.6,48.5],ZA:[-30.6,22.9],
    ZM:[-13.1,27.8],ZW:[-19,29.2]
  };

  /* ---------------- interactive world map ---------------- */

  const MAP_H_DEG = MAP_ROWS * MAP_CELL;          // degrees from top to bottom edge
  const MAP_BOTTOM = MAP_TOP - MAP_H_DEG;
  const MAP_MID_LAT = (MAP_TOP + MAP_BOTTOM) / 2;
  const MAP_MIN_Z = 1, MAP_MAX_Z = 10;
  const LAND_THRESHOLD = 0.42;

  const mapV = {
    ready: false, canvas: null, wrap: null, tip: null, top: null, layer: null, field: null,
    w: 0, h: 0, dpr: 1, dark: null,
    z: 1, cx: 0, cy: MAP_MID_LAT, tz: 1, tcx: 0, tcy: MAP_MID_LAT,
    dirty: true, sizeDirty: true, running: false, drag: null, hover: null, names: null
  };

  /* The coarse land mask is smoothed once so coasts look round instead of blocky. */
  function buildLandField() {
    const S = 4, W = MAP_COLS * S, H = MAP_ROWS * S;
    let a = new Float32Array(W * H);
    for (let y = 0; y < H; y++) {
      const row = MAP_MASK[Math.floor(y / S)] || '';
      for (let x = 0; x < W; x++) a[y * W + x] = row[Math.floor(x / S)] === '1' ? 1 : 0;
    }
    for (let pass = 0; pass < 2; pass++) {
      const b = new Float32Array(W * H);
      for (let y = 0; y < H; y++) {
        for (let x = 0; x < W; x++) {
          let sum = 0;
          for (let dy = -1; dy <= 1; dy++) {
            const yy = Math.min(H - 1, Math.max(0, y + dy));
            for (let dx = -1; dx <= 1; dx++) {
              sum += a[yy * W + Math.min(W - 1, Math.max(0, x + dx))];
            }
          }
          b[y * W + x] = sum / 9;
        }
      }
      a = b;
    }
    return { W, H, S, a };
  }

  function landAt(lon, lat) {
    const f = mapV.field;
    const fx = ((lon + 180) / MAP_CELL) * f.S - 0.5;
    const fy = ((MAP_TOP - lat) / MAP_CELL) * f.S - 0.5;
    if (fy < -0.5 || fy > f.H - 0.5) return 0;
    const x0 = Math.floor(fx), y0 = Math.floor(fy);
    const tx = fx - x0, ty = fy - y0;
    const at = (x, y) => f.a[Math.min(f.H - 1, Math.max(0, y)) * f.W + Math.min(f.W - 1, Math.max(0, x))];
    return (at(x0, y0) * (1 - tx) + at(x0 + 1, y0) * tx) * (1 - ty) +
           (at(x0, y0 + 1) * (1 - tx) + at(x0 + 1, y0 + 1) * tx) * ty;
  }

  function mapScale(z) {
    return Math.min(mapV.w / 360, mapV.h / MAP_H_DEG) * z;
  }

  function mapClamp(z, cx, cy) {
    const s = mapScale(z), hw = mapV.w / (2 * s), hh = mapV.h / (2 * s);
    cx = hw >= 180 ? 0 : Math.max(-180 + hw, Math.min(180 - hw, cx));
    cy = hh >= MAP_H_DEG / 2 ? MAP_MID_LAT : Math.max(MAP_BOTTOM + hh, Math.min(MAP_TOP - hh, cy));
    return [cx, cy];
  }

  function mapXY(lon, lat) {
    const s = mapScale(mapV.z);
    return [mapV.w / 2 + (lon - mapV.cx) * s, mapV.h / 2 + (mapV.cy - lat) * s];
  }

  function mapName(cc) {
    try {
      if (!mapV.names) mapV.names = new Intl.DisplayNames(['en'], { type: 'region' });
      return mapV.names.of(cc) || cc;
    } catch (e) { return cc; }
  }

  function mapSize() {
    const c = mapV.canvas;
    const r = c.getBoundingClientRect();
    if (r.width < 10 || r.height < 10) return false;
    const dpr = window.devicePixelRatio || 1;
    if (mapV.sizeDirty || Math.abs(r.width - mapV.w) > 0.5 || Math.abs(r.height - mapV.h) > 0.5 || dpr !== mapV.dpr) {
      mapV.w = r.width; mapV.h = r.height; mapV.dpr = dpr;
      c.width = Math.round(r.width * dpr);
      c.height = Math.round(r.height * dpr);
      const k = mapClamp(mapV.z, mapV.cx, mapV.cy);
      mapV.cx = k[0]; mapV.cy = k[1];
      const t = mapClamp(mapV.tz, mapV.tcx, mapV.tcy);
      mapV.tcx = t[0]; mapV.tcy = t[1];
      mapV.sizeDirty = false;
      mapV.dirty = true;
    }
    return true;
  }

  /* Ocean, grid lines and land dots. Redrawn only when the view changes. */
  function mapLayer() {
    const { w, h, dpr } = mapV;
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    const L = mapV.layer || (mapV.layer = document.createElement('canvas'));
    L.width = Math.round(w * dpr);
    L.height = Math.round(h * dpr);
    const g = L.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    mapV.dark = dark;

    const a = mapXY(-180, MAP_TOP), b = mapXY(180, MAP_BOTTOM);
    const ox = Math.max(0, a[0]), oy = Math.max(0, a[1]);
    const ow = Math.min(w, b[0]) - ox, oh = Math.min(h, b[1]) - oy;

    const sea = g.createLinearGradient(0, oy, 0, oy + oh);
    sea.addColorStop(0, dark ? 'rgba(70, 120, 210, 0.20)' : 'rgba(10, 124, 245, 0.09)');
    sea.addColorStop(1, dark ? 'rgba(40, 80, 160, 0.06)' : 'rgba(10, 124, 245, 0.02)');
    g.fillStyle = sea;
    g.fillRect(ox, oy, ow, oh);

    g.save();
    g.beginPath();
    g.rect(ox, oy, ow, oh);
    g.clip();

    // faint graticule every 30 degrees
    g.strokeStyle = dark ? 'rgba(150, 180, 230, 0.10)' : 'rgba(10, 80, 160, 0.09)';
    g.lineWidth = 1;
    g.beginPath();
    for (let lon = -150; lon <= 150; lon += 30) {
      const x = Math.round(mapXY(lon, 0)[0]) + 0.5;
      g.moveTo(x, oy); g.lineTo(x, oy + oh);
    }
    for (let lat = -30; lat <= 60; lat += 30) {
      const y = Math.round(mapXY(0, lat)[1]) + 0.5;
      g.moveTo(ox, y); g.lineTo(ox + ow, y);
    }
    g.stroke();

    // land: dots get denser as you zoom in
    const s = mapScale(mapV.z);
    const k = Math.max(0, Math.round(Math.log2((MAP_CELL * s) / 6.5)));
    const step = MAP_CELL / Math.pow(2, k);
    const sp = step * s, r = sp * 0.34;
    const lonMin = mapV.cx - w / (2 * s), lonMax = mapV.cx + w / (2 * s);
    const latMax = mapV.cy + h / (2 * s), latMin = mapV.cy - h / (2 * s);
    const i0 = Math.floor((Math.max(lonMin, -180) + 180) / step) - 1;
    const i1 = Math.ceil((Math.min(lonMax, 180) + 180) / step) + 1;
    const j0 = Math.floor((MAP_TOP - Math.min(latMax, MAP_TOP)) / step) - 1;
    const j1 = Math.ceil((MAP_TOP - Math.max(latMin, MAP_BOTTOM)) / step) + 1;

    g.fillStyle = dark ? 'rgba(140, 178, 240, 0.62)' : 'rgba(10, 112, 230, 0.46)';
    g.beginPath();
    for (let j = j0; j <= j1; j++) {
      const lat = MAP_TOP - (j + 0.5) * step;
      for (let i = i0; i <= i1; i++) {
        const lon = -180 + (i + 0.5) * step;
        if (landAt(lon, lat) < LAND_THRESHOLD) continue;
        const p = mapXY(lon, lat);
        g.moveTo(p[0] + r, p[1]);
        g.arc(p[0], p[1], r, 0, Math.PI * 2);
      }
    }
    g.fill();
    g.restore();

    g.strokeStyle = dark ? 'rgba(150, 180, 230, 0.22)' : 'rgba(10, 100, 200, 0.18)';
    g.strokeRect(ox + 0.5, oy + 0.5, ow - 1, oh - 1);
    mapV.dirty = false;
  }

  function mapHue(p) {
    const t = Math.min(1, Math.log2(1 + p.n) / 6);
    return { t, color: 'hsl(' + Math.round(34 * (1 - t)) + ', 95%, 56%)', hue: Math.round(34 * (1 - t)) };
  }

  function mapRender(now) {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (dark !== mapV.dark) mapV.dirty = true;
    if (mapV.dirty) mapLayer();

    const c = mapV.canvas, { w, h, dpr } = mapV;
    const g = c.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, h);
    g.drawImage(mapV.layer, 0, 0, w, h);

    const pts = (state.mapPoints || []).slice(0, 80);
    const zoomBoost = 1 + Math.min(0.9, (mapV.z - 1) * 0.12);
    g.font = '600 11px system-ui, -apple-system, "Segoe UI", sans-serif';
    g.textBaseline = 'middle';

    // draw the busiest last so it sits on top
    for (let n = pts.length - 1; n >= 0; n--) {
      const p = pts[n];
      const xy = mapXY(p.lon, p.lat);
      if (xy[0] < -40 || xy[0] > w + 40 || xy[1] < -40 || xy[1] > h + 40) continue;
      const m = mapHue(p);
      const core = (3 + 3.5 * m.t) * zoomBoost;
      const seed = ((p.cc.charCodeAt(0) * 31 + p.cc.charCodeAt(1) * 7) % 100) / 100;

      const glow = g.createRadialGradient(xy[0], xy[1], 0, xy[0], xy[1], core * 4.5);
      glow.addColorStop(0, 'hsla(' + m.hue + ', 95%, 56%, 0.55)');
      glow.addColorStop(1, 'hsla(' + m.hue + ', 95%, 56%, 0)');
      g.fillStyle = glow;
      g.beginPath(); g.arc(xy[0], xy[1], core * 4.5, 0, Math.PI * 2); g.fill();

      for (let ph = 0; ph < 2; ph++) {
        const t = ((now / 2200) + ph * 0.5 + seed) % 1;
        g.strokeStyle = 'hsla(' + m.hue + ', 95%, 56%, ' + (0.6 * (1 - t)).toFixed(3) + ')';
        g.lineWidth = 1.6;
        g.beginPath(); g.arc(xy[0], xy[1], core + t * (14 + 16 * m.t) * zoomBoost, 0, Math.PI * 2); g.stroke();
      }

      g.fillStyle = m.color;
      g.beginPath(); g.arc(xy[0], xy[1], core, 0, Math.PI * 2); g.fill();
      g.strokeStyle = 'rgba(255, 255, 255, 0.92)';
      g.lineWidth = 1.2;
      g.stroke();

      if (mapV.z >= 2.4 || mapV.hover === p) {
        const text = p.cc + ' · ' + p.n;
        const tw = g.measureText(text).width;
        const lx = xy[0] + core + 6, ly = xy[1] - core - 5;
        g.fillStyle = dark ? 'rgba(14, 24, 44, 0.82)' : 'rgba(255, 255, 255, 0.9)';
        g.fillRect(lx - 4, ly - 8, tw + 8, 16);
        g.fillStyle = dark ? '#e8eef9' : '#101c2e';
        g.fillText(text, lx, ly);
      }
    }
  }

  function mapFrame(now) {
    mapV.running = false;
    if (!mapV.canvas || !mapV.canvas.isConnected) return;
    if (!mapSize()) return;

    let moving = false;
    const dz = mapV.tz - mapV.z, dx = mapV.tcx - mapV.cx, dy = mapV.tcy - mapV.cy;
    if (Math.abs(dz) > 0.002 || Math.abs(dx) > 0.02 || Math.abs(dy) > 0.02) {
      mapV.z += dz * 0.28; mapV.cx += dx * 0.28; mapV.cy += dy * 0.28;
      moving = true;
      mapV.dirty = true;
    } else if (dz || dx || dy) {
      mapV.z = mapV.tz; mapV.cx = mapV.tcx; mapV.cy = mapV.tcy;
      mapV.dirty = true;
    }

    mapRender(now);
    if ((moving || (state.mapPoints && state.mapPoints.length)) && !document.hidden) mapKick();
  }

  function mapKick() {
    if (mapV.running) return;
    mapV.running = true;
    requestAnimationFrame(mapFrame);
  }

  function mapZoomAt(px, py, factor) {
    const nz = Math.max(MAP_MIN_Z, Math.min(MAP_MAX_Z, mapV.tz * factor));
    const s0 = mapScale(mapV.tz), s1 = mapScale(nz);
    const lon = mapV.tcx + (px - mapV.w / 2) / s0;
    const lat = mapV.tcy - (py - mapV.h / 2) / s0;
    const k = mapClamp(nz, lon - (px - mapV.w / 2) / s1, lat + (py - mapV.h / 2) / s1);
    mapV.tz = nz; mapV.tcx = k[0]; mapV.tcy = k[1];
    mapKick();
  }

  function mapReset() {
    mapV.tz = 1; mapV.tcx = 0; mapV.tcy = MAP_MID_LAT;
    mapKick();
  }

  function mapFull(on) {
    const wrap = mapV.wrap;
    const next = on === undefined ? !wrap.classList.contains('full') : on;
    // The card has a blur effect, which would trap a fixed layer inside it,
    // so the map moves to the page body while it is full screen.
    if (next && !mapV.holder) {
      mapV.holder = document.createComment('map');
      wrap.parentElement.insertBefore(mapV.holder, wrap);
      document.body.appendChild(wrap);
    } else if (!next && mapV.holder) {
      mapV.holder.parentElement.insertBefore(wrap, mapV.holder);
      mapV.holder.remove();
      mapV.holder = null;
    }
    wrap.classList.toggle('full', next);
    document.body.classList.toggle('map-full', next);
    mapV.fullBtn.textContent = next ? '✕' : '⤢';
    mapV.fullBtn.title = mapV.fullBtn.ariaLabel = next ? 'Close full screen' : 'Full screen';
    mapV.sizeDirty = true;
    mapReset();
  }

  function mapHit(px, py) {
    let best = null, bd = 18 * 18;
    (state.mapPoints || []).forEach((p) => {
      const xy = mapXY(p.lon, p.lat);
      const d = (xy[0] - px) * (xy[0] - px) + (xy[1] - py) * (xy[1] - py);
      if (d < bd) { bd = d; best = p; }
    });
    return best;
  }

  function mapTip(p, px, py) {
    const tip = mapV.tip;
    if (!p) { tip.hidden = true; return; }
    tip.replaceChildren();
    tip.append(el('b', '', mapName(p.cc)));
    tip.append(el('span', '', p.n + (p.n === 1 ? ' event' : ' events')));
    const parts = [];
    if (p.fw) parts.push(p.fw + ' blocked traffic');
    if (p.ids) parts.push(p.ids + ' IDS');
    if (parts.length) tip.append(el('small', '', parts.join(' · ')));
    tip.hidden = false;
    const left = Math.min(mapV.w - tip.offsetWidth - 6, px + 14);
    const top = Math.max(6, py - tip.offsetHeight - 10);
    tip.style.left = Math.max(6, left) + 'px';
    tip.style.top = top + 'px';
  }

  function mapInit() {
    if (mapV.ready) return;
    const c = $('mapCanvas');
    if (!c) return;
    mapV.ready = true;
    mapV.canvas = c;
    mapV.wrap = c.parentElement;
    mapV.field = buildLandField();

    const ctl = el('div', 'map-ctl');
    const mk = (txt, title, fn) => {
      const b = el('button', '', txt);
      b.type = 'button'; b.title = title; b.setAttribute('aria-label', title);
      b.addEventListener('click', fn);
      ctl.append(b);
      return b;
    };
    mk('+', 'Zoom in', () => mapZoomAt(mapV.w / 2, mapV.h / 2, 1.7));
    mk('−', 'Zoom out', () => mapZoomAt(mapV.w / 2, mapV.h / 2, 1 / 1.7));
    mk('⟲', 'Reset view', mapReset);
    mapV.fullBtn = mk('⤢', 'Full screen', () => mapFull());
    mapV.wrap.append(ctl);

    mapV.tip = el('div', 'map-tip');
    mapV.tip.hidden = true;
    mapV.wrap.append(mapV.tip);

    mapV.top = el('div', 'map-top');
    mapV.wrap.append(mapV.top);

    c.addEventListener('wheel', (ev) => {
      ev.preventDefault();
      const r = c.getBoundingClientRect();
      mapZoomAt(ev.clientX - r.left, ev.clientY - r.top, ev.deltaY < 0 ? 1.25 : 1 / 1.25);
    }, { passive: false });

    c.addEventListener('dblclick', (ev) => {
      const r = c.getBoundingClientRect();
      mapZoomAt(ev.clientX - r.left, ev.clientY - r.top, 2);
    });

    c.addEventListener('pointerdown', (ev) => {
      mapV.drag = { x: ev.clientX, y: ev.clientY };
      c.setPointerCapture(ev.pointerId);
      c.classList.add('grab');
      mapTip(null);
    });

    c.addEventListener('pointermove', (ev) => {
      const r = c.getBoundingClientRect();
      const px = ev.clientX - r.left, py = ev.clientY - r.top;
      if (mapV.drag) {
        const s = mapScale(mapV.z);
        const k = mapClamp(mapV.z,
          mapV.cx - (ev.clientX - mapV.drag.x) / s,
          mapV.cy + (ev.clientY - mapV.drag.y) / s);
        mapV.drag.x = ev.clientX; mapV.drag.y = ev.clientY;
        mapV.cx = mapV.tcx = k[0]; mapV.cy = mapV.tcy = k[1];
        mapV.tz = mapV.z;
        mapV.dirty = true;
        mapKick();
        return;
      }
      const p = mapHit(px, py);
      if (p !== mapV.hover) { mapV.hover = p; mapKick(); }
      c.style.cursor = p ? 'pointer' : 'grab';
      mapTip(p, px, py);
    });

    const endDrag = () => { mapV.drag = null; c.classList.remove('grab'); };
    c.addEventListener('pointerup', endDrag);
    c.addEventListener('pointercancel', endDrag);
    c.addEventListener('pointerleave', () => { mapV.hover = null; mapTip(null); mapKick(); });

    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape' && mapV.wrap.classList.contains('full')) mapFull(false);
    });
    document.addEventListener('visibilitychange', () => { if (!document.hidden) mapKick(); });

    if (window.ResizeObserver) {
      new ResizeObserver(() => { mapV.sizeDirty = true; mapKick(); }).observe(mapV.wrap);
    }
  }

  function mapUi() {
    const pts = state.mapPoints || [];
    $('mapEmpty').textContent = state.geoDatasets === 0
      ? 'Import country lists on the GeoIP page to place threats on the map'
      : 'No located threats yet';
    $('mapEmpty').hidden = pts.length > 0;

    mapV.top.replaceChildren();
    pts.slice(0, 3).forEach((p) => {
      const chip = el('span', 'map-chip');
      const dot = el('i');
      dot.style.background = mapHue(p).color;
      chip.append(dot, document.createTextNode(mapName(p.cc) + ' ' + p.n));
      mapV.top.append(chip);
    });
  }

  function drawMap() {
    mapInit();
    if (!mapV.ready) return;
    mapV.sizeDirty = true;
    mapV.dirty = true;
    mapUi();
    mapKick();
  }

  /* Work out which country each blocked / IDS source address belongs to and
     put one dot per country on the map. Lookups are cached for a while. */
  async function updateMap() {
    if (state.geoBusy) return;
    state.geoBusy = true;
    try {
      const now = Date.now() / 1000;
      const sec = RANGES[state.range].sec;
      const ev = state.events.filter((l) =>
        (l.kind === 'ids' || (l.kind === 'fw' && l.block)) && l.time >= now - sec);

      if (Date.now() - state.geoAt > 300000) { state.geo = {}; state.geoAt = Date.now(); }

      const need = new Set();
      ev.forEach((l) => [l.src, l.dst].forEach((ip) => {
        if (ip && !(String(ip) in state.geo)) need.add(String(ip));
      }));

      if (need.size || state.geoDatasets === null) {
        const list = Array.from(need).slice(0, 500);
        const r = await api('/api/geoip/locate', { method: 'POST', body: { ips: list } });
        list.forEach((ip) => { state.geo[ip] = (r.countries && r.countries[ip]) || null; });
        state.geoDatasets = r.datasets;
      }

      const byCountry = {};
      ev.forEach((l) => {
        const cc = state.geo[String(l.src)] || state.geo[String(l.dst)];
        if (!cc || !COUNTRY_POS[cc]) return;
        const e = byCountry[cc] || (byCountry[cc] = { n: 0, fw: 0, ids: 0 });
        e.n++;
        if (l.kind === 'ids') e.ids++; else e.fw++;
      });
      state.mapPoints = Object.keys(byCountry).map((cc) => ({
        lat: COUNTRY_POS[cc][0], lon: COUNTRY_POS[cc][1], cc,
        n: byCountry[cc].n, fw: byCountry[cc].fw, ids: byCountry[cc].ids
      })).sort((a, b) => b.n - a.n);
      drawMap();
    } catch (e) {
      // The map is optional: keep the dashboard working if the lookup fails.
    } finally {
      state.geoBusy = false;
    }
  }

  function drawAll() {
    drawChart();
    drawSparks();
    drawBars();
    drawMap();
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
      updateMap();
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
      updateMap();
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

  /* Hides the menu entries this role may not open. */
  function filterMenu() {
    document.querySelectorAll('.sidebar .nav-item').forEach((link) => {
      const page = Access.PAGES.find((p) => p[2] === link.getAttribute('href'));
      if (page && !Access.canView(page[0])) link.hidden = true;
    });
  }

  async function loadUser() {
    try {
      const me = await Access.refresh();
      if (!me || !me.username) return;
      document.querySelector('.user-text b').textContent = me.username;
      document.querySelector('.user-text span').textContent = Access.roleLabel(me.role);
      document.querySelector('.avatar').textContent = me.username.charAt(0).toUpperCase();
      filterMenu();

      if (!Access.canView('dashboard')) {
        const target = Access.landing();
        if (target) location.replace(target);
      }
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
  filterMenu();
  initChrome();
  initBell();
  loadUser();
  loadVersion();
  initChartHover();
  drawAll();
  loop();
  setInterval(loop, POLL_MS);
})();
