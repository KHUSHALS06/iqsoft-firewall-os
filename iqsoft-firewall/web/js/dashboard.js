(function () {
  if (!Auth.guard()) return;

  const $ = (id) => document.getElementById(id);
  const MAX_POINTS = 60;
  const COLORS = { tcp: '#0a7cf5', udp: '#7cc4ff', icmp: '#8a5cff', other: '#9aa9bd' };
  const hist = { rx: [], tx: [] };
  let prev = null;
  let tick = 0;

  $('logoutBtn').addEventListener('click', logout);

  const safe = (p) => p.catch(() => null);
  const num = (n) => Number(n || 0).toLocaleString();
  const asList = (d) => (Array.isArray(d) ? d : (d && (d.entries || d.logs || d.items)) || []);

  function rate(bps) {
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbps';
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
    return Math.round(bps) + ' bps';
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function clock(t) {
    const d = new Date(t > 1e12 ? t : t * 1000);
    return d.toTimeString().slice(0, 8);
  }

  function drawChart() {
    const c = $('trafficChart');
    const box = c.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    c.width = box.width * dpr;
    c.height = box.height * dpr;
    const g = c.getContext('2d');
    g.scale(dpr, dpr);
    const w = box.width, h = box.height, left = 64, bottom = 8, top = 8;
    const max = Math.max(1e6, ...hist.rx, ...hist.tx) * 1.15;

    g.font = '12px sans-serif';
    g.fillStyle = '#5b6b82';
    g.strokeStyle = '#e3eaf3';
    for (let i = 0; i <= 4; i++) {
      const y = top + ((h - top - bottom) * i) / 4;
      g.beginPath(); g.moveTo(left, y); g.lineTo(w, y); g.stroke();
      g.fillText(rate(max * (1 - i / 4)), 0, y + 4);
    }

    const plot = (arr, color) => {
      if (arr.length < 2) return;
      const pts = arr.map((v, i) => [
        left + ((w - left - 4) * (i + MAX_POINTS - arr.length)) / (MAX_POINTS - 1),
        top + (h - top - bottom) * (1 - v / max)
      ]);
      g.beginPath();
      pts.forEach((p, i) => (i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1])));
      g.strokeStyle = color; g.lineWidth = 2.500; g.stroke();
      g.lineTo(pts[pts.length - 1][0], h - bottom);
      g.lineTo(pts[0][0], h - bottom);
      const grad = g.createLinearGradient(0, top, 0, h);
      grad.addColorStop(0, color + '55'); grad.addColorStop(1, color + '05');
      g.fillStyle = grad; g.fill();
    };
    plot(hist.tx, '#8a5cff');
    plot(hist.rx, '#0a7cf5');
  }

  function renderInterfaces(list, dt) {
    const ul = $('ifList');
    ul.replaceChildren();
    let rx = 0, tx = 0;
    list.filter((i) => i.name !== 'lo').forEach((i) => {
      let r = 0, t = 0;
      if (prev && prev[i.name] && dt > 0) {
        r = Math.max(0, ((i.rx_bytes - prev[i.name].rx) * 8) / dt);
        t = Math.max(0, ((i.tx_bytes - prev[i.name].tx) * 8) / dt);
      }
      rx += r; tx += t;
      const li = el('li');
      const dot = el('span', 'dot ' + (String(i.state).toLowerCase() === 'down' ? 'bad' : 'ok'));
      const rates = el('span', 'rates');
      rates.append(el('span', '', '↓ ' + rate(r)), el('span', '', '↑ ' + rate(t)));
      li.append(dot, el('b', '', i.name), rates);
      ul.append(li);
    });
    prev = {};
    list.forEach((i) => { prev[i.name] = { rx: i.rx_bytes, tx: i.tx_bytes }; });
    return { rx, tx };
  }

  async function fast() {
    const now = Date.now();
    const [ifs, usage] = await Promise.all([
      safe(api('/api/monitor/interfaces')),
      safe(api('/api/monitor/conntrack-usage'))
    ]);
    $('liveDot').className = 'dot ' + (ifs ? 'ok' : 'bad');
    $('liveText').textContent = ifs ? 'Live' : 'API error';

    if (ifs) {
      const dt = fast.last ? (now - fast.last) / 1000 : 0;
      fast.last = now;
      const sum = renderInterfaces(ifs, dt);
      if (dt > 0) {
        hist.rx.push(sum.rx); hist.tx.push(sum.tx);
        if (hist.rx.length > MAX_POINTS) { hist.rx.shift(); hist.tx.shift(); }
        $('lgRx').textContent = rate(sum.rx);
        $('lgTx').textContent = rate(sum.tx);
        drawChart();
      }
    }

    if (usage && usage.count != null) {
      const pct = usage.max ? Math.min(100, (usage.count / usage.max) * 100) : 0;
      $('ringArc').setAttribute('stroke-dasharray', pct.toFixed(1) + ' ' + (100 - pct).toFixed(1));
      $('ringPct').textContent = pct.toFixed(1) + '%';
      $('ringText').textContent = num(usage.count) + ' of ' + num(usage.max) + ' entries';
    }
  }

  function renderProtocols(conns) {
    const counts = { tcp: 0, udp: 0, icmp: 0, other: 0 };
    conns.forEach((c) => {
      const p = String(c.protocol).toLowerCase();
      counts[p in counts ? p : 'other']++;
    });
    const total = conns.length || 1;
    const arcs = $('donutArcs'), legend = $('protoLegend');
    arcs.replaceChildren(); legend.replaceChildren();
    let offset = 25;
    Object.keys(counts).forEach((k) => {
      const pct = (counts[k] / total) * 100;
      if (pct > 0) {
        const ns = 'http://www.w3.org/2000/svg';
        const c = document.createElementNS(ns, 'circle');
        c.setAttribute('cx', 21); c.setAttribute('cy', 21); c.setAttribute('r', 15.9155);
        c.setAttribute('fill', 'none'); c.setAttribute('stroke', COLORS[k]); c.setAttribute('stroke-width', 5);
        c.setAttribute('stroke-dasharray', pct + ' ' + (100 - pct));
        c.setAttribute('stroke-dashoffset', offset);
        arcs.append(c);
        offset -= pct;
      }
      const li = el('li');
      const sw = el('span', 'lg'); sw.style.background = COLORS[k];
      li.append(sw, el('span', '', k.toUpperCase()), el('em', '', conns.length ? pct.toFixed(1) + '%' : '–'));
      legend.append(li);
    });
    $('donutTotal').textContent = num(conns.length);
  }

  function renderLogs(logs) {
    const bySrc = {};
    logs.forEach((l) => {
      const s = bySrc[l.src] || (bySrc[l.src] = { n: 0, last: '' });
      s.n++;
      s.last = String(l.protocol).toUpperCase() + (l.dport ? ':' + l.dport : '');
    });
    const tb = $('topSrc');
    tb.replaceChildren();
    const top = Object.entries(bySrc).sort((a, b) => b[1].n - a[1].n).slice(0, 5);
    if (!top.length) {
      const tr = el('tr'); const td = el('td', 'empty', 'No logged traffic yet'); td.colSpan = 3;
      tr.append(td); tb.append(tr);
    }
    top.forEach(([ip, s]) => {
      const tr = el('tr');
      tr.append(el('td', '', ip), el('td', '', num(s.n)), el('td', '', s.last));
      tb.append(tr);
    });

    const ev = $('events');
    ev.replaceChildren();
    const recent = logs.slice().sort((a, b) => b.time - a.time).slice(0, 6);
    if (!recent.length) ev.append(el('li', 'empty', 'No events logged. Enable logging on a rule to see traffic here.'));
    recent.forEach((l) => {
      const li = el('li');
      const target = l.dst + (l.dport ? ':' + l.dport : '');
      li.append(el('span', 't', clock(l.time)), el('span', 'msg', l.src + ' → ' + target + ' (' + String(l.protocol).toUpperCase() + ')'), el('span', 'badge', 'Rule ' + l.rule_id));
      ev.append(li);
    });
  }

  async function slow() {
    const [conns, counters, logs] = await Promise.all([
      safe(api('/api/monitor/connections?limit=1000')),
      safe(api('/api/monitor/rule-counters')),
      safe(api('/api/monitor/logs?limit=200'))
    ]);

    if (conns) {
      const list = conns.connections || [];
      $('stTotal').textContent = num(conns.total);
      $('stEst').textContent = num(list.filter((c) => String(c.state).toUpperCase() === 'ESTABLISHED').length);
      renderProtocols(list);
    }
    if (counters) {
      $('stHits').textContent = num(asList(counters).reduce((s, c) => s + (c.packets || 0), 0));
    }
    if (logs) {
      const list = asList(logs);
      $('stLogs').textContent = num(list.length);
      renderLogs(list);
    }
  }

  function loop() {
    fast();
    if (tick % 4 === 0) slow();
    tick++;
  }

  window.addEventListener('resize', drawChart);
  loop();
  setInterval(loop, 3000);
})();
