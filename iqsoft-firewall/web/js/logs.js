(function () {
  'use strict';

  const { h, icon, clear, busy, every, tabs, live, errorText, num, fmtTime } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'logs',
    title: 'Logs',
    subtitle: 'Firewall traffic log and administrator audit trail',
    content: $('page')
  });
  if (!frame) return;

  const AUDIT_PAGE = 50;

  const AUDIT_ACTIONS = [
    ['', 'All events'],
    ['auth.login', 'Sign in'],
    ['auth.logout', 'Sign out'],
    ['auth.password_change', 'Password change'],
    ['auth.access_denied', 'Access denied'],
    ['rule.create', 'Rule created'],
    ['rule.update', 'Rule changed'],
    ['rule.delete', 'Rule deleted'],
    ['firewall.commit', 'Rules applied'],
    ['firewall.commit_confirm', 'Apply confirmed'],
    ['firewall.rollback', 'Rolled back']
    ['system.backup', 'Backup downloaded'],
    ['system.restore', 'Restore staged'],
    ['system.restore_cancel', 'Restore cancelled'],
    ['system.reboot', 'Reboot'],
    ['system.shutdown', 'Shut down']	  
  ];

  const AUDIT_LABELS = new Map(AUDIT_ACTIONS.filter((a) => a[0]).map((a) => [a[0], a[1]]));

  const RANGES = [
    ['0', 'Any time'],
    ['3600', 'Last hour'],
    ['86400', 'Last 24 hours'],
    ['604800', 'Last 7 days'],
    ['2592000', 'Last 30 days']
  ];

  const state = {
    tab: 'traffic',
    rules: new Map(),
    traffic: [],
    trafficRule: '',
    trafficLimit: '200',
    trafficText: '',
    auditOffset: 0,
    auditTotal: 0,
    auditUser: '',
    auditAction: '',
    auditResult: '',
    auditRange: '0'
  };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' }, icon('i-refresh'));
  frame.tools.append(btnRefresh);

  const badge = (text, kind) => h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  const list = (v) => (Array.isArray(v) ? v : []);
  const has = (v) => v !== null && v !== undefined && v !== '';

  function selectBox(label, options, value, onChange) {
    const el = h('select', { class: 'in', 'aria-label': label },
      options.map(([v, t]) => h('option', { value: v, text: t, selected: v === value })));
    el.addEventListener('change', () => onChange(el.value));
    return { el, node: h('span', { class: 'select-wrap' }, el) };
  }

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

  function endpoint(addr, port) {
    if (!addr) return '–';
    return has(port) ? addr + ':' + port : addr;
  }

  /* ---------------- firewall log ---------------- */

  const trafficText = h('input', { class: 'in grow', type: 'search', placeholder: 'Filter by address, port or protocol', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Filter log' });
  const ruleBox = selectBox('Rule', [['', 'All rules']], '', (v) => { state.trafficRule = v; loadTraffic(); });
  const limitBox = selectBox('How many to read', [['100', 'Read 100'], ['200', 'Read 200'], ['500', 'Read 500'], ['1000', 'Read 1000']], state.trafficLimit,
    (v) => { state.trafficLimit = v; loadTraffic(); });
  $('trafficTools').append(trafficText, ruleBox.node, limitBox.node);

  function fillRuleSelect() {
    const rules = Array.from(state.rules.values()).sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }));
    const keep = state.trafficRule;
    clear(ruleBox.el);
    ruleBox.el.append(h('option', { value: '', text: 'All rules' }));
    rules.forEach((r) => ruleBox.el.append(h('option', { value: String(r.id), text: r.name, selected: String(r.id) === keep })));
    ruleBox.el.value = keep;
  }

  async function loadRules() {
    try {
      const data = await api('/api/rules');
      const rows = Array.isArray(data) ? data : list(data && data.rules);
      state.rules = new Map(rows.filter((r) => has(r.id)).map((r) => [r.id, r]));
      fillRuleSelect();
    } catch (_) {}
  }

  function renderTraffic() {
    const body = clear($('trafficBody'));
    const q = state.trafficText.toLowerCase();

    const rows = state.traffic.filter((e) => {
      if (!q) return true;
      const text = [e.src, e.dst, e.sport, e.dport, e.protocol, e.in_interface, e.out_interface].join(' ').toLowerCase();
      return text.includes(q);
    });

    $('countTraffic').textContent = num(state.traffic.length);
    $('trafficSub').textContent = 'Packets matched by rules that have logging turned on, newest first. Showing ' + num(rows.length) + ' of ' + num(state.traffic.length) + ' read.';

    if (!rows.length) {
      return emptyRow(body, 9, state.traffic.length ? 'No entries match the filter.' : 'No log entries. Turn on logging for a rule and apply the firewall.');
    }

    rows.forEach((e) => {
      const rule = state.rules.get(e.rule_id);
      const action = rule ? String(rule.action || '') : '';
      const kind = action === 'accept' ? 'ok' : action === 'drop' || action === 'reject' ? 'bad' : 'plain';
      const flags = h('div', { class: 'btn-row' });
      list(e.tcp_flags).forEach((f) => flags.append(badge(f, f === 'SYN' ? 'info' : f === 'RST' ? 'warn' : 'plain')));

      body.append(h('tr', null,
        h('td', { class: 'mono nowrap', text: fmtTime(e.time) }),
        h('td', null, h('b', { text: rule ? rule.name : 'Rule #' + e.rule_id })),
        h('td', null, action ? badge(action, kind) : '–'),
        h('td', null, badge(e.protocol || '–', 'plain')),
        h('td', { class: 'mono nowrap', text: endpoint(e.src, e.sport) }),
        h('td', { class: 'mono nowrap', text: endpoint(e.dst, e.dport) }),
        h('td', { class: 'mono nowrap', text: (e.in_interface || '–') + ' → ' + (e.out_interface || '–') }),
        h('td', { class: 'mono nowrap', text: has(e.length) ? num(e.length) + ' B' : '–' }),
        h('td', null, flags)));
    });
  }

  async function loadTraffic() {
    try {
      let url = '/api/monitor/logs?limit=' + encodeURIComponent(state.trafficLimit);
      if (state.trafficRule) url += '&rule_id=' + encodeURIComponent(state.trafficRule);
      state.traffic = list(await api(url));
      showNotice($('trafficNotice'), 'warn', '');
      renderTraffic();
      live(true, 'Live');
    } catch (e) {
      state.traffic = [];
      $('countTraffic').textContent = '0';
      clear($('trafficBody'));
      emptyRow($('trafficBody'), 9, 'The firewall log could not be read.');
      showNotice($('trafficNotice'), 'bad', apiMessage(e));
      if (!e || e.status !== 503) live(false, 'Connection lost');
    }
  }

  trafficText.addEventListener('input', () => { state.trafficText = trafficText.value.trim(); renderTraffic(); });

  /* ---------------- audit trail ---------------- */

  const auditUser = h('input', { class: 'in grow', type: 'search', placeholder: 'User name', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Filter by user' });
  const auditActionBox = selectBox('Event', AUDIT_ACTIONS, '', (v) => { state.auditAction = v; state.auditOffset = 0; loadAudit(); });
  const auditResultBox = selectBox('Result', [['', 'Any result'], ['true', 'Succeeded'], ['false', 'Failed']], '', (v) => { state.auditResult = v; state.auditOffset = 0; loadAudit(); });
  const auditRangeBox = selectBox('Time range', RANGES, '0', (v) => { state.auditRange = v; state.auditOffset = 0; loadAudit(); });
  $('auditTools').append(auditUser, auditActionBox.node, auditResultBox.node, auditRangeBox.node);

  const btnPrev = h('button', { class: 'btn sm', type: 'button' }, 'Newer');
  const btnNext = h('button', { class: 'btn sm', type: 'button' }, 'Older');
  const pageText = h('span', { class: 'card-sub' });
  $('auditPager').append(btnPrev, btnNext, h('span', { class: 'grow' }), pageText);

  function renderAudit(entries) {
    const body = clear($('auditBody'));
    $('countAudit').textContent = num(state.auditTotal);

    if (!entries.length) {
      emptyRow(body, 7, 'No audit events match.');
    }

    entries.forEach((e) => {
      body.append(h('tr', null,
        h('td', { class: 'mono nowrap', text: fmtTime(e.created_at) }),
        h('td', null, has(e.username) ? h('b', { text: e.username }) : '–'),
        h('td', null, h('b', { text: AUDIT_LABELS.get(e.action) || e.action }), h('div', { class: 'sub mono', text: e.action })),
        h('td', { class: 'mono', text: has(e.target) ? e.target : '–' }),
        h('td', { text: has(e.detail) ? e.detail : '–' }),
        h('td', null, badge(e.success ? 'Succeeded' : 'Failed', e.success ? 'ok' : 'bad')),
        h('td', { class: 'mono nowrap', text: has(e.source_ip) ? e.source_ip : '–' })));
    });

    const from = entries.length ? state.auditOffset + 1 : 0;
    const to = state.auditOffset + entries.length;
    pageText.textContent = num(from) + '–' + num(to) + ' of ' + num(state.auditTotal);
    btnPrev.disabled = state.auditOffset <= 0;
    btnNext.disabled = to >= state.auditTotal;
  }

  async function loadAudit() {
    const params = new URLSearchParams();
    params.set('limit', String(AUDIT_PAGE));
    params.set('offset', String(state.auditOffset));
    if (state.auditUser) params.set('username', state.auditUser);
    if (state.auditAction) params.set('action', state.auditAction);
    if (state.auditResult) params.set('success', state.auditResult);
    if (state.auditRange !== '0') params.set('since', String(Math.floor(Date.now() / 1000) - Number(state.auditRange)));

    try {
      const data = await api('/api/audit?' + params.toString());
      state.auditTotal = Number(data.total) || 0;
      showNotice($('auditNotice'), 'warn', '');

      const entries = list(data.entries);
      if (!entries.length && state.auditOffset > 0 && state.auditTotal > 0) {
        state.auditOffset = Math.max(0, Math.floor((state.auditTotal - 1) / AUDIT_PAGE) * AUDIT_PAGE);
        return loadAudit();
      }

      renderAudit(entries);
      live(true, 'Live');
    } catch (e) {
      state.auditTotal = 0;
      renderAudit([]);
      if (e && e.status === 403) {
        showNotice($('auditNotice'), 'warn', 'Only administrators can read the audit trail.');
      } else {
        showNotice($('auditNotice'), 'bad', apiMessage(e));
        live(false, 'Connection lost');
      }
    }
  }

  let userTimer = null;
  auditUser.addEventListener('input', () => {
    clearTimeout(userTimer);
    userTimer = setTimeout(() => {
      state.auditUser = auditUser.value.trim();
      state.auditOffset = 0;
      loadAudit();
    }, 350);
  });

  btnPrev.addEventListener('click', () => { state.auditOffset = Math.max(0, state.auditOffset - AUDIT_PAGE); loadAudit(); });
  btnNext.addEventListener('click', () => { state.auditOffset += AUDIT_PAGE; loadAudit(); });

  /* ---------------- wiring ---------------- */

  function reload() {
    if (state.tab === 'audit') return state.auditOffset === 0 ? loadAudit() : Promise.resolve();
    return loadTraffic();
  }

  tabs($('page'), 'logs', (name) => {
    state.tab = name;
    if (name === 'audit') loadAudit();
    else loadTraffic();
  });

  btnRefresh.addEventListener('click', () => busy(btnRefresh, async () => {
    if (state.tab === 'audit') await loadAudit();
    else await loadTraffic();
  }));

  loadRules();
  every(reload, 10000);
})();
