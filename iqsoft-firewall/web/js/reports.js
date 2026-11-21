(function () {
  'use strict';

  const { h, icon, clear, busy, live, errorText, num, fmtTime } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'reports',
    title: 'Reports',
    subtitle: 'Threats, traffic and administrator activity over a chosen period',
    content: $('page')
  });
  if (!frame) return;

  const PAGE = 500;
  const MAX_PAGES = 4;
  const FW_READ = 1000;
  const TOP = 10;

  const PERIODS = [
    ['86400', 'Last 24 hours'],
    ['604800', 'Last 7 days'],
    ['2592000', 'Last 30 days']
  ];

  const EVENT_LABELS = {
    'auth.login': 'Sign in',
    'auth.logout': 'Sign out',
    'auth.password_change': 'Password change',
    'auth.access_denied': 'Access denied',
    'rule.create': 'Rule created',
    'rule.update': 'Rule changed',
    'rule.delete': 'Rule deleted',
    'firewall.commit': 'Rules applied',
    'firewall.commit_confirm': 'Apply confirmed',
    'firewall.rollback': 'Rolled back',
    'system.backup': 'Backup downloaded',
    'system.restore': 'Restore staged',
    'system.restore_cancel': 'Restore cancelled',
    'system.reboot': 'Reboot',
    'system.shutdown': 'Shut down'
  };

  const state = { period: '86400', rules: new Map(), exportRows: [], generated: 0, running: false };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Rebuild report', title: 'Rebuild report' }, icon('i-refresh'));
  frame.tools.append(btnRefresh);

  const periodSelect = h('select', { class: 'in', 'aria-label': 'Report period' },
    PERIODS.map(([v, t]) => h('option', { value: v, text: t, selected: v === state.period })));
  const btnCsv = h('button', { class: 'btn', type: 'button' }, icon('i-file'), 'Download CSV');
  $('reportTools').append(h('span', { class: 'select-wrap' }, periodSelect), h('span', { class: 'grow' }), btnCsv);

  const list = (v) => (Array.isArray(v) ? v : []);
  const has = (v) => v !== null && v !== undefined && v !== '';
  const badge = (text, kind) => h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  const tsSec = (t) => (t > 1e12 ? Math.floor(t / 1000) : Number(t) || 0);
  const sinceSec = () => Math.floor(Date.now() / 1000) - Number(state.period);

  function apiMessage(e) {
    if (e && e.data && typeof e.data === 'object') {
      if (e.data.message) return e.data.message;
      if (e.data.error) return e.data.error;
    }
    return errorText(e);
  }

  function showNotice(id, kind, text) {
    const box = clear($(id));
    if (text) box.append(h('div', { class: 'notice ' + kind }, text));
  }

  function endpoint(addr, port) {
    if (!addr) return '–';
    return has(port) ? addr + ':' + port : addr;
  }

  function top(items, keyFn, labelFn) {
    const map = new Map();
    items.forEach((item) => {
      const key = keyFn(item);
      if (!has(key)) return;
      const entry = map.get(key) || { key, count: 0, item };
      entry.count += 1;
      map.set(key, entry);
    });
    return Array.from(map.values())
      .sort((a, b) => b.count - a.count || String(a.key).localeCompare(String(b.key)))
      .slice(0, TOP)
      .map((e) => ({ label: labelFn ? labelFn(e.item, e.key) : String(e.key), count: e.count }));
  }

  function rankCard(section, title, rows, total, head) {
    state.exportRows.push(...rows.map((r) => [section, title, r.label, r.count]));

    const body = h('tbody');
    if (!rows.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 3, text: 'Nothing in this period.' })));
    }
    rows.forEach((r) => {
      const share = total > 0 ? (r.count / total) * 100 : 0;
      body.append(h('tr', null,
        h('td', { class: 'mono', text: r.label }),
        h('td', { class: 'mono nowrap', text: num(r.count) }),
        h('td', { class: 'nowrap' }, h('progress', { max: 100, value: Math.round(share) }), ' ', badge(share.toFixed(0) + '%', 'plain'))));
    });

    return h('div', { class: 'card' },
      h('div', { class: 'card-h' }, h('h3', { text: title })),
      h('div', { class: 'tbl-wrap' },
        h('table', { class: 'dtable' },
          h('thead', null, h('tr', null, h('th', { text: head }), h('th', { text: 'Count' }), h('th', { text: 'Share' }))),
          body)));
  }

  function fillRow(id, cards) {
    const row = clear($(id));
    cards.forEach((c) => row.append(c));
  }

  function statCard(kind, iconName, value, label, sub) {
    return h('div', { class: 'card stat s-' + kind },
      h('div', { class: 's-ico' }, icon(iconName)),
      h('div', { class: 's-body' },
        h('b', { text: value }),
        h('span', { text: label }),
        h('em', { class: 'trend', text: sub || '' })));
  }

  async function fetchPaged(path, pick, tsOf) {
    const since = sinceSec();
    const items = [];
    let capped = false;

    for (let page = 0; page < MAX_PAGES; page++) {
      const data = await api(path + (path.includes('?') ? '&' : '?') + 'limit=' + PAGE + '&offset=' + (page * PAGE));
      const rows = pick(data);
      let reachedOlder = false;

      rows.forEach((r) => {
        if (tsOf(r) >= since) items.push(r);
        else reachedOlder = true;
      });

      if (reachedOlder || rows.length < PAGE) break;
      if (page === MAX_PAGES - 1) capped = true;
    }

    return { items, capped };
  }

  const pickEvents = (data) => (Array.isArray(data) ? data : list(data && data.events));

  function capNote(capped, what) {
    return capped ? ' Only the newest ' + num(PAGE * MAX_PAGES) + ' ' + what + ' were read, so older ones in this period are not counted.' : '';
  }

  async function buildIds(summary) {
    const { items, capped } = await fetchPaged('/api/ids/events', pickEvents, (e) => tsSec(e.ts));
    const blocked = items.filter((e) => e.action === 'blocked');
    const alerted = items.filter((e) => e.action !== 'blocked');

    $('idsSub').textContent = num(items.length) + ' events in this period: ' + num(blocked.length) + ' blocked, ' + num(alerted.length) + ' alerted.' + capNote(capped, 'events');

    fillRow('idsRow1', [
      rankCard('Intrusion detection', 'Top signatures', top(items, (e) => e.sid, (e) => e.signature + ' (SID ' + e.sid + ')'), items.length, 'Signature'),
      rankCard('Intrusion detection', 'Top source addresses', top(items, (e) => e.src_ip), items.length, 'Source')
    ]);
    fillRow('idsRow2', [
      rankCard('Intrusion detection', 'Top categories', top(items, (e) => e.category || 'Uncategorised'), items.length, 'Category'),
      rankCard('Intrusion detection', 'Top targeted ports', top(items.filter((e) => has(e.dest_port)), (e) => (e.proto || '') + '/' + e.dest_port), items.length, 'Protocol / port')
    ]);

    return { blocked: blocked.length, alerted: alerted.length, total: items.length };
  }

  async function buildAv() {
    const { items, capped } = await fetchPaged('/api/av/events', pickEvents, (e) => tsSec(e.ts));
    const blocked = items.filter((e) => e.action === 'blocked');

    $('avSub').textContent = num(items.length) + ' scan events in this period, ' + num(blocked.length) + ' blocked.' + capNote(capped, 'events');

    fillRow('avRow1', [
      rankCard('Antivirus', 'Outcome', top(items, (e) => e.action), items.length, 'Action'),
      rankCard('Antivirus', 'Top threats', top(items.filter((e) => has(e.signature)), (e) => e.signature), items.length, 'Signature')
    ]);
    fillRow('avRow2', [
      rankCard('Antivirus', 'Top clients', top(items, (e) => e.client_ip), items.length, 'Client'),
      rankCard('Antivirus', 'Top hosts', top(items, (e) => e.host), items.length, 'Host')
    ]);

    return { blocked: blocked.length, total: items.length };
  }

  async function buildFirewall() {
    const since = sinceSec();
    const all = list(await api('/api/monitor/logs?limit=' + FW_READ));
    const items = all.filter((e) => e.time >= since);
    const capped = all.length >= FW_READ && items.length === all.length;

    const denied = items.filter((e) => {
      const rule = state.rules.get(e.rule_id);
      return rule && (rule.action === 'drop' || rule.action === 'reject');
    });

    $('fwSub').textContent = num(items.length) + ' logged packets in this period, ' + num(denied.length) + ' matched a drop or reject rule.' +
      (capped ? ' Only the newest ' + num(FW_READ) + ' log lines were read, so older packets in this period are not counted.' : '') +
      ' Only rules with logging turned on appear here.';

    const ruleName = (e) => {
      const rule = state.rules.get(e.rule_id);
      return rule ? rule.name : 'Rule #' + e.rule_id;
    };

    fillRow('fwRow1', [
      rankCard('Firewall traffic', 'Top rules by log hits', top(items, (e) => e.rule_id, ruleName), items.length, 'Rule'),
      rankCard('Firewall traffic', 'Top sources of denied traffic', top(denied, (e) => e.src), denied.length, 'Source')
    ]);
    fillRow('fwRow2', [
      rankCard('Firewall traffic', 'Top destination ports of denied traffic', top(denied.filter((e) => has(e.dport)), (e) => (e.protocol || '') + '/' + e.dport), denied.length, 'Protocol / port'),
      rankCard('Firewall traffic', 'Top destinations of denied traffic', top(denied, (e) => e.dst), denied.length, 'Destination')
    ]);

    return { total: items.length, denied: denied.length };
  }

  async function buildAudit() {
    const since = sinceSec();
    const entries = [];
    let total = 0;
    let capped = false;

    for (let page = 0; page < MAX_PAGES; page++) {
      const data = await api('/api/audit?since=' + since + '&limit=' + PAGE + '&offset=' + (page * PAGE));
      total = Number(data.total) || 0;
      const rows = list(data.entries);
      entries.push(...rows);
      if (rows.length < PAGE || entries.length >= total) break;
      if (page === MAX_PAGES - 1) capped = true;
    }

    const failed = entries.filter((e) => !e.success);
    const failedLogins = failed.filter((e) => e.action === 'auth.login');

    $('auditSub').textContent = num(total) + ' events in this period, ' + num(failed.length) + ' failed.' + capNote(capped, 'events');

    const label = (e) => EVENT_LABELS[e.action] || e.action;

    fillRow('auditRow1', [
      rankCard('Administrator activity', 'Events by type', top(entries, (e) => e.action, (e) => label(e)), entries.length, 'Event'),
      rankCard('Administrator activity', 'Failed sign-ins by address', top(failedLogins.filter((e) => has(e.source_ip)), (e) => e.source_ip), failedLogins.length, 'Source address')
    ]);

    const body = clear($('auditFailBody'));
    failed.slice(0, 15).forEach((e) => {
      body.append(h('tr', null,
        h('td', { class: 'mono nowrap', text: fmtTime(e.created_at) }),
        h('td', null, has(e.username) ? h('b', { text: e.username }) : '–'),
        h('td', { text: label(e) }),
        h('td', { text: has(e.detail) ? e.detail : '–' }),
        h('td', { class: 'mono nowrap', text: has(e.source_ip) ? e.source_ip : '–' })));
    });
    $('auditFailCard').hidden = failed.length === 0;

    return { total, failed: failed.length };
  }

  function sectionFail(section, noticeId, subId, rowIds, e) {
    $(subId).textContent = 'This section could not be built.';
    rowIds.forEach((id) => clear($(id)));
    const text = e && e.status === 403 ? 'Only administrators can read this section.' : apiMessage(e);
    showNotice(noticeId, e && (e.status === 403 || e.status === 503) ? 'warn' : 'bad', text);
    return null;
  }

  async function loadRules() {
    try {
      const data = await api('/api/rules');
      const rows = Array.isArray(data) ? data : list(data && data.rules);
      state.rules = new Map(rows.filter((r) => has(r.id)).map((r) => [r.id, r]));
    } catch (_) {}
  }

  async function build() {
    if (state.running) return;
    state.running = true;
    state.exportRows = [];

    ['idsNotice', 'avNotice', 'fwNotice', 'auditNotice'].forEach((id) => showNotice(id, 'warn', ''));
    ['idsSub', 'avSub', 'fwSub', 'auditSub'].forEach((id) => { $(id).textContent = 'Loading…'; });

    try {
      await loadRules();

      const results = await Promise.all([
        buildIds().catch((e) => sectionFail('ids', 'idsNotice', 'idsSub', ['idsRow1', 'idsRow2'], e)),
        buildAv().catch((e) => sectionFail('av', 'avNotice', 'avSub', ['avRow1', 'avRow2'], e)),
        buildFirewall().catch((e) => sectionFail('fw', 'fwNotice', 'fwSub', ['fwRow1', 'fwRow2'], e)),
        buildAudit().catch((e) => { $('auditFailCard').hidden = true; return sectionFail('audit', 'auditNotice', 'auditSub', ['auditRow1'], e); })
      ]);

      const [ids, av, fw, audit] = results;

      const stats = clear($('statsBox'));
      stats.append(
        statCard('red', 'i-ban', ids || av ? num((ids ? ids.blocked : 0) + (av ? av.blocked : 0)) : '–', 'Threats blocked', 'Intrusion and antivirus'),
        statCard('amber', 'i-alert', ids ? num(ids.alerted) : '–', 'Intrusion alerts', 'Detected, not blocked'),
        statCard('blue', 'i-shield', fw ? num(fw.denied) : '–', 'Denied packets logged', fw ? num(fw.total) + ' logged in total' : ''),
        statCard('green', 'i-key', audit ? num(audit.failed) : '–', 'Failed admin actions', audit ? num(audit.total) + ' events in total' : ''));

      state.generated = Math.floor(Date.now() / 1000);
      $('reportSub').textContent = 'Built ' + fmtTime(state.generated) + ' from the firewall log, intrusion detection, antivirus and audit events stored on this firewall.';
      live(true, 'Live');
    } finally {
      state.running = false;
    }
  }

  function csvCell(value) {
    let text = String(value === null || value === undefined ? '' : value);
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
  }

  function stamp() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes());
  }

  btnCsv.addEventListener('click', () => {
    if (!state.exportRows.length) { Shell.toast('The report has no rows to export yet.', 'info'); return; }

    const label = (PERIODS.find((p) => p[0] === state.period) || [])[1] || '';
    const lines = [['Section', 'Table', 'Item', 'Count'].map(csvCell).join(',')];
    state.exportRows.forEach((r) => lines.push(r.map(csvCell).join(',')));
    lines.push(['Period', label, '', ''].map(csvCell).join(','));

    const blob = new Blob([lines.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = h('a', { href: url, download: 'iqsoft-report-' + stamp() + '.csv' });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  });

  async function run() {
    try {
      await build();
    } catch (e) {
      live(false, 'Connection lost');
      Shell.toast(apiMessage(e), 'bad');
    }
  }

  periodSelect.addEventListener('change', () => { state.period = periodSelect.value; run(); });
  btnRefresh.addEventListener('click', () => busy(btnRefresh, run));

  run();
})();
