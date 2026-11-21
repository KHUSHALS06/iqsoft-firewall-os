(function () {
  'use strict';

  const { h, icon, clear, busy, every, tabs, live, errorText, num } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'monitoring',
    title: 'Monitoring',
    subtitle: 'System health, traffic, connections and rule counters',
    content: $('page')
  });
  if (!frame) return;

  const state = {
    prev: null,
    rules: new Map(),
    connFilter: '',
    connProto: '',
    connLimit: '200',
    tab: 'overview'
  };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' }, icon('i-refresh'));
  frame.tools.append(btnRefresh);

  const badge = (text, kind) => h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  const list = (v) => (Array.isArray(v) ? v : []);
  const has = (v) => v !== null && v !== undefined;

  function fmtBytes(n) {
    let v = Number(n) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + ' ' + u[i];
  }

  function fmtRate(bytesPerSec) {
    if (!has(bytesPerSec)) return '–';
    let v = bytesPerSec * 8;
    const u = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    let i = 0;
    while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
    return (i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i];
  }

  function fmtUptime(sec) {
    if (!has(sec)) return '–';
    const d = Math.floor(sec / 86400);
    const hr = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + 'd ' + hr + 'h ' + m + 'm';
    if (hr > 0) return hr + 'h ' + m + 'm';
    return m + 'm';
  }

  function fmtDuration(sec) {
    const s = Number(sec) || 0;
    if (s >= 86400) return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h';
    if (s >= 3600) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
    if (s >= 60) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    return s + 's';
  }

  const pct = (v) => (has(v) ? v.toFixed(1) + '%' : '–');

  function emptyRow(body, cols, text) {
    body.append(h('tr', null, h('td', { class: 'empty-row', colspan: cols, text })));
  }

  function apiMessage(e) {
    if (e && e.data && typeof e.data === 'object') {
      if (e.data.message) return e.data.message;
      if (e.data.error) return e.data.error;
    }
    return errorText(e);
  }

  function showNotice(box, kind, text) {
    clear(box);
    if (text) box.append(h('div', { class: 'notice ' + kind }, text));
  }

  function meter(value, warnAt, badAt) {
    const wrap = h('div', { class: 'nowrap' });
    const p = h('progress', { max: 100, value: Math.min(100, Math.max(0, value || 0)) });
    const kind = value >= badAt ? 'bad' : value >= warnAt ? 'warn' : 'ok';
    wrap.append(p, ' ', badge(pct(value), kind));
    return wrap;
  }

  /* ---------------- overview ---------------- */

  async function loadSystem() {
    const s = await api('/api/monitor/system');
    $('stCpu').textContent = pct(s.cpu_percent);
    $('stMem').textContent = pct(s.memory_percent);
    $('stMemSub').textContent = has(s.memory_used_bytes) ? fmtBytes(s.memory_used_bytes) + ' of ' + fmtBytes(s.memory_total_bytes) : '–';
    $('stDisk').textContent = pct(s.disk_percent);
    $('stDiskSub').textContent = has(s.disk_used_bytes) ? fmtBytes(s.disk_used_bytes) + ' of ' + fmtBytes(s.disk_total_bytes) : '–';
    $('stUptime').textContent = fmtUptime(s.uptime_seconds);
  }

  async function loadConntrackUsage() {
    const u = await api('/api/monitor/conntrack-usage');
    const box = clear($('ctBox'));
    if (!has(u.count) || !has(u.max) || !u.max) {
      box.append(h('p', { class: 'card-sub', text: 'Connection tracking numbers are not available on this system.' }));
      return;
    }
    const p = (u.count / u.max) * 100;
    box.append(h('div', { class: 'btn-row' },
      meter(p, 70, 90),
      h('span', { class: 'mono', text: num(u.count) + ' of ' + num(u.max) + ' entries in use' })));
  }

  function renderInterfaces(list_, rates) {
    const body = clear($('ifBody'));
    if (!list_.length) return emptyRow(body, 7, 'No interfaces found.');
    list_.forEach((i) => {
      const r = rates.get(i.name) || {};
      body.append(h('tr', null,
        h('td', null, h('b', { text: i.name })),
        h('td', null, badge(i.state, i.state === 'up' ? 'ok' : i.state === 'down' ? 'bad' : 'plain')),
        h('td', { class: 'mono nowrap', text: fmtRate(r.rx) }),
        h('td', { class: 'mono nowrap', text: fmtRate(r.tx) }),
        h('td', { class: 'mono nowrap', text: fmtBytes(i.rx_bytes) }),
        h('td', { class: 'mono nowrap', text: fmtBytes(i.tx_bytes) }),
        h('td', { class: 'mono nowrap', text: num(i.rx_errors + i.tx_errors) + ' / ' + num(i.rx_dropped + i.tx_dropped) })));
    });
  }

  async function loadInterfaces() {
    const now = Date.now();
    const data = list(await api('/api/monitor/interfaces'));
    const rates = new Map();

    if (state.prev && now > state.prev.at) {
      const secs = (now - state.prev.at) / 1000;
      data.forEach((i) => {
        const before = state.prev.map.get(i.name);
        if (!before) return;
        const rx = i.rx_bytes - before.rx_bytes;
        const tx = i.tx_bytes - before.tx_bytes;
        if (rx < 0 || tx < 0) return;
        rates.set(i.name, { rx: rx / secs, tx: tx / secs });
      });
    }

    state.prev = { at: now, map: new Map(data.map((i) => [i.name, i])) };
    renderInterfaces(data, rates);
  }

  async function loadOverview() {
    const jobs = await Promise.allSettled([loadSystem(), loadConntrackUsage(), loadInterfaces()]);
    const failed = jobs.find((j) => j.status === 'rejected');
    if (failed) {
      live(false, 'Connection lost');
      throw failed.reason;
    }
    live(true, 'Live');
  }

  /* ---------------- connections ---------------- */

  const connTools = $('connTools');
  const connFilterInput = h('input', { class: 'in grow', type: 'search', placeholder: 'Filter by address, port or state', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Filter connections' });
  const connProtoSelect = h('select', { class: 'in', 'aria-label': 'Protocol' },
    [['', 'All protocols'], ['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP']].map(([v, t]) => h('option', { value: v, text: t })));
  const connLimitSelect = h('select', { class: 'in', 'aria-label': 'How many to read' },
    [['100', 'Read 100'], ['200', 'Read 200'], ['500', 'Read 500'], ['1000', 'Read 1000']].map(([v, t]) => h('option', { value: v, text: t, selected: v === state.connLimit })));
  connTools.append(connFilterInput, h('span', { class: 'select-wrap' }, connProtoSelect), h('span', { class: 'select-wrap' }, connLimitSelect));

  let connData = { total: 0, shown: 0, connections: [] };

  function endpoint(addr, port) {
    return port !== null && port !== undefined ? addr + ':' + port : addr;
  }

  function natText(c) {
    const origSrc = endpoint(c.src, c.sport);
    const origDst = endpoint(c.dst, c.dport);
    const replySrc = endpoint(c.reply_src, c.reply_sport);
    const replyDst = endpoint(c.reply_dst, c.reply_dport);
    if (replySrc === origDst && replyDst === origSrc) return null;
    return replyDst !== origSrc ? replyDst : replySrc;
  }

  function renderConnections() {
    const body = clear($('connBody'));
    const q = state.connFilter.toLowerCase();

    const rows = connData.connections.filter((c) => {
      if (state.connProto && c.protocol !== state.connProto) return false;
      if (!q) return true;
      const text = [c.protocol, c.state, endpoint(c.src, c.sport), endpoint(c.dst, c.dport), c.reply_src, c.reply_dst].join(' ').toLowerCase();
      return text.includes(q);
    });

    $('countConn').textContent = num(connData.total);
    $('connSub').textContent = 'Showing ' + num(rows.length) + ' of ' + num(connData.shown) + ' read (' + num(connData.total) + ' tracked in total).';

    if (!rows.length) return emptyRow(body, 8, connData.connections.length ? 'No connections match the filter.' : 'No tracked connections.');

    const anyBytes = connData.connections.some((c) => has(c.bytes_out));
    showNotice($('connNotice'), 'warn', anyBytes ? '' : 'Byte counters are off. Enable them with: sysctl -w net.netfilter.nf_conntrack_acct=1');

    rows.forEach((c) => {
      const nat = natText(c);
      const flags = h('div', { class: 'btn-row' });
      if (c.assured) flags.append(badge('Assured', 'ok'));
      if (c.unreplied) flags.append(badge('Unreplied', 'warn'));
      if (nat) flags.append(badge('NAT', 'info'));

      body.append(h('tr', null,
        h('td', null, badge(String(c.protocol).toUpperCase(), 'plain')),
        h('td', null, c.state ? badge(c.state, c.state === 'ESTABLISHED' ? 'ok' : 'plain') : '–'),
        h('td', { class: 'mono nowrap', text: endpoint(c.src, c.sport) }),
        h('td', { class: 'mono nowrap', text: endpoint(c.dst, c.dport) }),
        h('td', { class: 'mono nowrap', text: nat || '–' }),
        h('td', { class: 'mono nowrap', text: has(c.bytes_out) ? fmtBytes(c.bytes_out) + ' / ' + fmtBytes(c.bytes_in) : '–' }),
        h('td', { class: 'mono nowrap', text: fmtDuration(c.timeout_seconds) }),
        h('td', null, flags)));
    });
  }

  async function loadConnections() {
    try {
      connData = await api('/api/monitor/connections?limit=' + encodeURIComponent(state.connLimit));
      connData.connections = list(connData.connections);
      showNotice($('connNotice'), 'warn', '');
      renderConnections();
      live(true, 'Live');
    } catch (e) {
      connData = { total: 0, shown: 0, connections: [] };
      clear($('connBody'));
      emptyRow($('connBody'), 8, 'Connections could not be read.');
      showNotice($('connNotice'), 'bad', apiMessage(e));
      if (!e || e.status !== 503) live(false, 'Connection lost');
    }
  }

  connFilterInput.addEventListener('input', () => { state.connFilter = connFilterInput.value.trim(); renderConnections(); });
  connProtoSelect.addEventListener('change', () => { state.connProto = connProtoSelect.value; renderConnections(); });
  connLimitSelect.addEventListener('change', () => { state.connLimit = connLimitSelect.value; loadConnections(); });

  /* ---------------- rule counters ---------------- */

  async function loadRuleNames() {
    try {
      const data = await api('/api/rules');
      const rows = Array.isArray(data) ? data : list(data && data.rules);
      state.rules = new Map(rows.filter((r) => has(r.id)).map((r) => [r.id, r]));
    } catch (_) {}
  }

  async function loadCounters() {
    const body = clear($('cntBody'));
    try {
      await loadRuleNames();
      const rows = list(await api('/api/monitor/rule-counters'));
      showNotice($('cntNotice'), 'warn', '');
      $('countCnt').textContent = num(rows.length);

      if (!rows.length) return emptyRow(body, 5, 'No rule counters yet. Apply firewall rules first.');

      const top = rows.reduce((m, r) => Math.max(m, r.packets), 0);

      rows.forEach((r) => {
        const rule = state.rules.get(r.rule_id);
        const action = rule ? String(rule.action || '') : '';
        const kind = action === 'accept' ? 'ok' : action === 'drop' || action === 'reject' ? 'bad' : 'plain';
        body.append(h('tr', { class: rule && rule.enabled === false ? 'is-off' : '' },
          h('td', null, h('b', { text: rule ? rule.name : 'Rule #' + r.rule_id }), h('div', { class: 'sub', text: 'ID ' + r.rule_id })),
          h('td', { class: 'mono', text: r.chain }),
          h('td', null, action ? badge(action, kind) : '–'),
          h('td', { class: 'mono nowrap' }, num(r.packets), top > 0 && r.packets === top ? [' ', badge('busiest', 'info')] : null),
          h('td', { class: 'mono nowrap', text: fmtBytes(r.bytes) })));
      });
      live(true, 'Live');
    } catch (e) {
      $('countCnt').textContent = '0';
      emptyRow(body, 5, 'Rule counters could not be read.');
      showNotice($('cntNotice'), 'bad', apiMessage(e));
      if (!e || e.status !== 503) live(false, 'Connection lost');
    }
  }

  /* ---------------- wiring ---------------- */

  function reload() {
    if (state.tab === 'connections') return loadConnections();
    if (state.tab === 'counters') return loadCounters();
    return loadOverview();
  }

  tabs($('page'), 'monitoring', (name) => {
    state.tab = name;
    if (name === 'connections') loadConnections();
    else if (name === 'counters') loadCounters();
    else loadOverview().catch(() => {});
  });

  btnRefresh.addEventListener('click', () => busy(btnRefresh, async () => { await reload(); }));

  every(reload, 5000);
})();
