(function () {
  'use strict';

  const { h, icon, clear, toast, confirmBox, openModal, busy, every, tabs, live, fmtTime, ago, num, errorText } = Shell;

  const $ = (id) => document.getElementById(id);
  const PAGE_SIZE = 50;
  const POLL_MS = 5000;

  const frame = Shell.mount({
    active: 'antivirus',
    title: 'Antivirus',
    subtitle: 'Checks downloads for viruses and malware',
    content: $('page')
  });
  if (!frame) return;

  const state = {
    status: null,
    settings: null,
    loadedJson: '',
    tab: 'overview',
    evOffset: 0,
    evHasNext: false,
    wasPending: false,
    pendingBox: null,
    pendingCounter: null
  };

  const btnApply = h('button', { class: 'btn primary', type: 'button', title: 'Put the saved settings into effect on the firewall' },
    icon('i-play'), 'Apply');
  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' },
    icon('i-refresh'));
  frame.tools.append(btnApply, btnRefresh);

  async function lock(buttons, work) {
    const list = buttons.filter(Boolean);
    list.forEach((b) => { b.disabled = true; b.classList.add('busy'); });
    try {
      return await work();
    } finally {
      list.forEach((b) => { b.disabled = false; b.classList.remove('busy'); });
    }
  }

  function kv(dl, rows) {
    clear(dl);
    rows.forEach(([label, value]) => {
      dl.append(h('dt', { text: label }), h('dd', null, value));
    });
  }

  function badge(text, kind) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  }

  function bytes(n) {
    const v = Number(n) || 0;
    if (v >= 1073741824) return (v / 1073741824).toFixed(1) + ' GB';
    if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
    if (v >= 1024) return (v / 1024).toFixed(1) + ' KB';
    return v + ' B';
  }

  function setError(id, message) {
    const box = $(id);
    box.textContent = message || '';
    box.hidden = !message;
  }

  function markInvalid(id, on) {
    $(id).classList.toggle('invalid', !!on);
  }

  const MODE_HELP = {
    block: 'Infected files are stopped and replaced by a block message.',
    monitor: 'Infected files are recorded but still delivered. Use this to test before blocking.'
  };

  const FAIL_HELP = {
    open: 'If the virus engine stops, downloads keep working but are not scanned.',
    closed: 'If the virus engine stops, web downloads are blocked until it is back.'
  };

  const ENGINES = { hash: 'Known threat list', url: 'Website check' };
  const engineName = (e) => ENGINES[e] || 'Virus scan';

  const RESULTS = {
    blocked: ['Blocked', 'bad'],
    monitored: ['Detected only', 'warn'],
    error: ['Scan error', 'info']
  };

  function flag(on, yes, no, enabled) {
    return on ? badge(yes, 'ok') : badge(no, enabled ? 'bad' : '');
  }

  function protection(st) {
    if (!st.enabled) return badge('Off', '');
    if (!st.healthy) return badge('Needs attention', 'warn');
    return state.settings && state.settings.mode === 'monitor'
      ? badge('Detecting only', 'info')
      : badge('Protecting', 'ok');
  }

  function renderNotices(st) {
    const box = clear($('notice'));
    const items = [];

    if (!st.enabled && st.redirect_active) {
      items.push(['warn', 'Antivirus is off but web traffic still goes to the scanner', 'Press Apply to update the firewall.']);
    } else if (!st.enabled) {
      items.push(['', 'Antivirus is switched off', 'Turn it on in Settings, then press Apply.']);
    }

    if (st.enabled) {
      (st.problems || []).forEach((p) => items.push(['warn', p, '']));
    }

    items.forEach(([kind, title, text]) => {
      box.append(h('div', { class: 'notice' + (kind ? ' ' + kind : '') },
        icon(kind === 'warn' || kind === 'bad' ? 'i-alert' : 'i-info'),
        h('div', null, h('b', { text: title }), text ? ' ' + text : '')));
    });
  }

  function renderEngine(st) {
    const on = st.enabled;

    const engineOk = st.engine_reachable && st.engine_detects_test_file;

    kv($('engStatus'), [
      ['Protection', protection(st)],
      ['Mode', state.settings ? (state.settings.mode === 'monitor' ? 'Detect only' : 'Block infected files') : '–'],
      ['Web scanner', st.proxy_listening ? badge('Running', 'ok') : badge('Stopped', on ? 'bad' : '')],
      ['Virus engine', engineOk ? badge('Ready', 'ok') : badge(on ? 'Not ready' : 'Idle', on ? 'bad' : '')],
      ['Web protection', flag(st.redirect_active, 'Active', 'Not active', false)]
    ]);
  }

  function renderCounters(st) {
    kv($('countersInfo'), [
      ['Files scanned', num(st.files_scanned)],
      ['Infected files blocked', num(st.files_blocked)],
      ['Scan errors', num(st.scan_errors)]
    ]);
  }

  async function refreshStatus() {
    const st = await api('/api/av/status');
    state.status = st;
    renderNotices(st);
    renderEngine(st);
    renderCounters(st);
  }

  async function refreshSummary() {
    const s = await api('/api/av/summary');
    $('stTotal').textContent = num(s.total_events);
    $('stBlocked').textContent = num(s.blocked_24h);
    $('stMonitored').textContent = num(s.monitored_24h);
    $('stErrors').textContent = num(s.errors_24h);
  }

  async function loadRecent() {
    const list = await api('/api/av/events?limit=5');
    const body = clear($('recentBody'));

    if (!list.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 5, text: 'No threats found yet.' })));
      return;
    }

    list.forEach((e) => {
      const result = RESULTS[e.action] || [e.action, ''];
      body.append(h('tr', null,
        h('td', { class: 'nowrap', text: fmtTime(e.ts) }),
        h('td', { class: 'mono nowrap', text: e.client_ip }),
        h('td', { class: 'wide', title: e.url, text: e.host }),
        h('td', { text: e.signature || '–' }),
        h('td', null, badge(result[0], result[1]))));
    });
  }

  function readForm() {
    return {
      enabled: $('sEnabled').checked,
      mode: $('sMode').value,
      max_scan_mb: Number($('sMaxScan').value),
      over_size_action: $('sOverSize').value,
      fail_mode: $('sFailMode').value,
      scan_archives: $('sArchives').checked,
      block_encrypted_archives: $('sEncrypted').checked,
      scanner_socket: $('sSocket').value.trim(),
      proxy_port: Number($('sPort').value)
    };
  }

  function fillForm(s) {
    $('sEnabled').checked = !!s.enabled;
    $('sMode').value = s.mode;
    $('sMaxScan').value = s.max_scan_mb;
    $('sOverSize').value = s.over_size_action;
    $('sFailMode').value = s.fail_mode;
    $('sArchives').checked = !!s.scan_archives;
    $('sEncrypted').checked = !!s.block_encrypted_archives;
    $('sSocket').value = s.scanner_socket || '';
    $('sPort').value = s.proxy_port;
  }

  function syncHelp() {
    $('sModeHelp').textContent = MODE_HELP[$('sMode').value] || '';
    $('sFailHelp').textContent = FAIL_HELP[$('sFailMode').value] || '';
  }

  function isDirty() {
    return state.loadedJson !== '' && JSON.stringify(readForm()) !== state.loadedJson;
  }

  function updateDirty() {
    $('settingsState').textContent = isDirty() ? 'You have unsaved changes.' : '';
  }

  async function loadSettings() {
    const s = await api('/api/av/settings');
    state.settings = s;
    fillForm(s);
    syncHelp();
    state.loadedJson = JSON.stringify(readForm());
    updateDirty();
  }

  function whole(id, label, min, max) {
    const raw = $(id).value.trim();
    const value = Number(raw);
    if (raw === '' || !Number.isInteger(value) || value < min || value > max) {
      markInvalid(id, true);
      return label + ' must be a whole number from ' + min + ' to ' + max + '.';
    }
    return '';
  }

  function checkForm() {
    ['sMaxScan', 'sPort', 'sSocket'].forEach((id) => markInvalid(id, false));

    let message = whole('sMaxScan', 'The largest file to scan', 1, 512);
    message = message || whole('sPort', 'The scanner port', 1024, 65535);

    const socket = $('sSocket').value.trim();
    if (!message && (!socket.startsWith('/') || /\s/.test(socket) || socket.split('/').includes('..') || socket.length > 200)) {
      markInvalid('sSocket', true);
      message = 'The scanner connection path must be a full path starting with /, without spaces.';
    }

    if ($('sPort').classList.contains('invalid') || $('sSocket').classList.contains('invalid')) {
      const adv = document.querySelector('.adv');
      if (adv) adv.open = true;
    }

    setError('settingsError', message);
    return !message;
  }

  async function saveSettings() {
    if (!checkForm()) return null;

    const before = state.settings;
    const form = readForm();

    try {
      await api('/api/av/settings', { method: 'PUT', body: form });
    } catch (e) {
      setError('settingsError', errorText(e));
      return null;
    }

    await loadSettings();
    await refreshStatus().catch(() => {});

    return {
      needsApply: !before || before.enabled !== form.enabled || before.proxy_port !== form.proxy_port
    };
  }

  function timerSelect() {
    return h('select', { class: 'in' },
      [[60, '60 seconds (recommended)'], [30, '30 seconds'], [120, '2 minutes'], [300, '5 minutes'], [0, 'Off – keep permanently']]
        .map(([v, t]) => h('option', { value: v, text: t })));
  }

  function openApply() {
    const timer = timerSelect();

    const body = h('div', null,
      h('p', { class: 'card-sub', text: 'This puts your saved settings into effect. If you choose an automatic undo time, the previous settings return by themselves unless you confirm that everything still works.' }),
      h('label', { class: 'fld' },
        h('span', { text: 'Automatic undo' }),
        h('span', { class: 'select-wrap' }, timer),
        h('small', { text: 'Recommended when you are managing this device remotely.' })));

    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const go = h('button', { class: 'btn primary', type: 'button' }, icon('i-play'), 'Activate now');

    const modal = openModal({ title: 'Activate changes', body, footer: [cancel, go] });

    cancel.addEventListener('click', modal.close);
    go.addEventListener('click', async () => {
      modal.setError('');
      const seconds = Number(timer.value);

      try {
        const res = await busy(go, () => api('/api/commit' + (seconds > 0 ? '?confirm_within=' + seconds : ''), { method: 'POST' }));
        modal.close();
        toast((res && res.message) || 'Firewall configuration applied.', 'ok');
      } catch (e) {
        modal.setError(errorText(e));
        return;
      }

      await Promise.allSettled([refreshPending(), refreshStatus()]);
    });
  }

  async function applyNow() {
    if (isDirty()) {
      const go = await confirmBox(
        'Some settings on the Settings tab are not saved. Apply only uses what is already saved.\n\nContinue anyway?',
        { ok: 'Continue', title: 'Unsaved changes' }
      );
      if (!go) return;
    }

    openApply();
  }

  async function confirmPending(button) {
    try {
      const res = await busy(button, () => api('/api/commit/confirm', { method: 'POST' }));
      toast((res && res.message) || 'Change confirmed.', 'ok');
    } catch (e) {
      toast(errorText(e), 'bad');
    }

    await refreshPending();
  }

  async function rollbackPending() {
    const ok = await confirmBox('Go back to the previous firewall ruleset?',
      { ok: 'Roll back', danger: true, title: 'Roll back' });
    if (!ok) return;

    try {
      const res = await api('/api/rollback', { method: 'POST' });
      toast((res && res.message) || 'Rolled back to the previous rules.', 'ok');
    } catch (e) {
      toast(errorText(e), 'bad');
    }

    await Promise.allSettled([refreshPending(), refreshStatus()]);
  }

  function renderPending(status) {
    const box = $('pending');

    if (!status || !status.pending) {
      if (state.pendingBox) {
        clear(box);
        state.pendingBox = null;
        state.pendingCounter = null;
      }

      if (state.wasPending) {
        toast('The confirmation time ran out or the change was rolled back. The firewall is using the previous rules.', 'info', 9000);
      }

      state.wasPending = false;
      return;
    }

    state.wasPending = true;

    if (!state.pendingBox) {
      state.pendingCounter = h('b', { text: '' });

      const keep = h('button', { class: 'btn primary sm', type: 'button' }, icon('i-check'), 'Keep these rules');
      const undo = h('button', { class: 'btn danger sm', type: 'button' }, icon('i-undo'), 'Roll back now');
      keep.addEventListener('click', () => confirmPending(keep));
      undo.addEventListener('click', rollbackPending);

      state.pendingBox = h('div', { class: 'notice warn' },
        icon('i-alert'),
        h('div', null,
          h('b', { text: 'New firewall rules are waiting for your confirmation.' }), ' ',
          'If you can still use the firewall, keep them. Otherwise they are rolled back automatically in ', state.pendingCounter, '.',
          h('div', { class: 'btn-row' }, keep, undo)));

      clear(box).append(state.pendingBox);
    }

    state.pendingCounter.textContent = Number(status.seconds_left) + ' s';
  }

  async function refreshPending() {
    renderPending(await api('/api/commit/status'));
  }

  const KIND_TEXT = {
    domain: { label: 'Domain', placeholder: 'updates.example.com', help: 'Use a full name such as example.com. Subdomains are included.' },
    cidr: { label: 'Network or IP address', placeholder: '10.0.0.0/24', help: 'An IP address or a network such as 10.0.0.0/24.' }
  };

  function syncKind() {
    const t = KIND_TEXT[$('exKind').value];
    $('exValueLabel').textContent = t.label;
    $('exValue').placeholder = t.placeholder;
    $('exHelp').textContent = t.help;
  }

  async function loadExceptions() {
    const list = await api('/api/av/exceptions');
    $('tabCountExceptions').textContent = String(list.length);

    const body = clear($('exBody'));

    if (!list.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 4, text: 'No exceptions. Every download is scanned.' })));
      return;
    }

    list.forEach((item) => {
      body.append(h('tr', null,
        h('td', null, badge(item.kind === 'cidr' ? 'Network' : 'Website', 'info')),
        h('td', { class: 'mono nowrap', text: item.value }),
        h('td', { class: 'wide', text: item.comment || '' }),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteException(item) },
            icon('i-trash'), 'Remove'))));
    });
  }

  async function deleteException(item) {
    const ok = await confirmBox('Scan downloads for ' + item.value + ' again?',
      { ok: 'Remove', danger: true, title: 'Remove exception' });
    if (!ok) return;

    try {
      await api('/api/av/exceptions/' + encodeURIComponent(item.id), { method: 'DELETE' });
      toast('Exception removed.', 'ok');
      await loadExceptions();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  async function addException(ev) {
    ev.preventDefault();
    setError('exError', '');
    markInvalid('exValue', false);

    const value = $('exValue').value.trim();
    if (!value) {
      markInvalid('exValue', true);
      setError('exError', 'Enter a domain, IP address or network.');
      return;
    }

    const comment = $('exComment').value.trim();

    try {
      await lock([$('btnAddException')], () => api('/api/av/exceptions', {
        method: 'POST',
        body: { kind: $('exKind').value, value, comment: comment || null }
      }));
    } catch (e) {
      setError('exError', errorText(e));
      return;
    }

    $('exValue').value = '';
    $('exComment').value = '';
    toast('Exception added. The scanner applies it within a few seconds.', 'ok');
    await loadExceptions();
  }

  function eventRow(e) {
    const result = RESULTS[e.action] || [e.action, ''];

    return h('tr', null,
      h('td', { class: 'nowrap', text: fmtTime(e.ts) }),
      h('td', { class: 'mono nowrap', text: e.client_ip }),
      h('td', { class: 'wide', title: e.url },
        e.host,
        h('span', { class: 'sub', text: e.file_name || e.url })),
      h('td', { class: 'nowrap', text: bytes(e.size_bytes) }),
      h('td', { class: 'nowrap', text: engineName(e.engine) }),
      h('td', { text: e.signature || '–' }),
      h('td', null, badge(result[0], result[1])));
  }

  function eventQuery() {
    const q = new URLSearchParams();
    q.set('limit', String(PAGE_SIZE + 1));
    q.set('offset', String(state.evOffset));

    const action = $('evAction').value;
    if (action) q.set('action', action);

    return q.toString();
  }

  async function loadEvents() {
    let list;
    try {
      list = await api('/api/av/events?' + eventQuery());
    } catch (e) {
      toast(errorText(e), 'bad');
      return;
    }

    state.evHasNext = list.length > PAGE_SIZE;
    const shown = list.slice(0, PAGE_SIZE);

    const body = clear($('evBody'));

    if (!shown.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 7, text: state.evOffset > 0 ? 'No more detections.' : 'No detections match.' })));
    } else {
      shown.forEach((e) => body.append(eventRow(e)));
    }

    $('evInfo').textContent = shown.length ? 'Showing ' + (state.evOffset + 1) + ' to ' + (state.evOffset + shown.length) : '';
    $('evPrev').disabled = state.evOffset === 0;
    $('evNext').disabled = !state.evHasNext;
  }

  async function clearEvents() {
    const ok = await confirmBox('Delete every stored antivirus detection? This cannot be undone.',
      { ok: 'Delete all', danger: true, title: 'Clear detections' });
    if (!ok) return;

    try {
      const r = await api('/api/av/events', { method: 'DELETE' });
      toast((r && r.deleted !== undefined ? num(r.deleted) : 'All') + ' detections deleted.', 'ok');
      state.evOffset = 0;
      await Promise.all([loadEvents(), refreshSummary(), loadRecent()]);
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  async function refresh() {
    try {
      await Promise.all([refreshStatus(), refreshSummary(), loadRecent(), refreshPending()]);

      const dialogOpen = !!document.querySelector('.modal-back');
      if (state.tab === 'events' && state.evOffset === 0 && !dialogOpen) await loadEvents();

      live(true, 'Live');
    } catch (e) {
      live(false, 'Connection lost');
    }
  }

  const tabCtl = tabs($('page'), 'av', (name) => {
    state.tab = name;
    if (name === 'events') loadEvents();
    if (name === 'exceptions') loadExceptions().catch(() => {});
  });

  $('sMode').addEventListener('change', () => { syncHelp(); updateDirty(); });
  $('sFailMode').addEventListener('change', () => { syncHelp(); updateDirty(); });
  $('settingsForm').addEventListener('input', (ev) => {
    if (ev.target.classList) ev.target.classList.remove('invalid');
    updateDirty();
  });
  $('settingsForm').addEventListener('change', updateDirty);

  $('settingsForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const result = await lock([$('btnSaveSettings')], saveSettings);
    if (!result) return;
    toast(result.needsApply
      ? 'Settings saved. Press Apply so the firewall redirects web traffic to the scanner.'
      : 'Settings saved. The scanner uses them within a few seconds.', 'ok');
  });

  $('btnSaveApply').addEventListener('click', async () => {
    const result = await lock([$('btnSaveApply')], saveSettings);
    if (result) openApply();
  });

  btnApply.addEventListener('click', applyNow);

  btnRefresh.addEventListener('click', async () => {
    btnRefresh.classList.add('spin');
    await refresh();
    if (state.tab === 'exceptions') await loadExceptions().catch(() => {});
    btnRefresh.classList.remove('spin');
  });

  $('exKind').addEventListener('change', syncKind);
  $('exForm').addEventListener('submit', addException);
  $('exValue').addEventListener('input', () => $('exValue').classList.remove('invalid'));

  $('evAction').addEventListener('change', () => { state.evOffset = 0; loadEvents(); });
  $('btnEvRefresh').addEventListener('click', loadEvents);
  $('btnEvClear').addEventListener('click', clearEvents);
  $('evPrev').addEventListener('click', () => { state.evOffset = Math.max(0, state.evOffset - PAGE_SIZE); loadEvents(); });
  $('evNext').addEventListener('click', () => { if (state.evHasNext) { state.evOffset += PAGE_SIZE; loadEvents(); } });

  syncKind();
  loadSettings().then(refreshStatus).catch((e) => toast(errorText(e), 'bad'));
  loadExceptions().catch(() => {});
  every(refresh, POLL_MS);
})();
