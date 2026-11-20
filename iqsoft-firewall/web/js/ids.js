(function () {
  'use strict';

  const { h, icon, clear, toast, confirmBox, every, tabs, live, fmtTime, ago, num, errorText } = Shell;

  const $ = (id) => document.getElementById(id);
  const PAGE_SIZE = 50;
  const POLL_MS = 5000;

  const frame = Shell.mount({
    active: 'ids',
    title: 'Intrusion Detection',
    subtitle: 'Detect and block network attacks',
    content: $('page')
  });
  if (!frame) return;

  const state = {
    status: null,          // last /api/ids/status
    loadedJson: '',        // settings as last read from the server, to spot unsaved changes
    tab: 'overview',
    evOffset: 0,
    evHasNext: false
  };

  /* ---------------- header buttons ---------------- */

  const btnApply = h('button', { class: 'btn primary', type: 'button', title: 'Put the saved settings into effect' },
    icon('i-play'), 'Apply');
  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' },
    icon('i-refresh'));
  frame.tools.append(btnApply, btnRefresh);

  /* ---------------- small helpers ---------------- */

  /* Disables the buttons and shows a spinner on them while the work runs. */
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
    if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
    if (v >= 1024) return (v / 1024).toFixed(1) + ' KB';
    return v + ' B';
  }

  function endpoint(ip, port) {
    if (port === null || port === undefined) return ip;
    return (String(ip).includes(':') ? '[' + ip + ']' : ip) + ':' + port;
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
    ids: 'Suricata watches a copy of the traffic and records attacks. Nothing is blocked.',
    ips: 'Forwarded traffic passes through Suricata, and traffic that matches a drop rule is blocked.'
  };

  /* ---------------- status (engine, signatures, notices) ---------------- */

  function engineBadge(st) {
    const s = st.suricata;
    if (!s.installed) return badge('Not installed', 'bad');
    if (s.ready) return badge('Running', 'ok');
    if (s.running) return badge('Starting', 'warn');
    if (s.unit_installed) return badge('Stopped', st.enabled ? 'warn' : '');
    return badge('Not set up', '');
  }

  function renderNotices(st) {
    const box = clear($('notice'));
    const s = st.suricata;
    const items = [];

    if (st.enabled && !s.installed) {
      items.push(['bad', 'Suricata is not installed', 'Install it on the firewall with "apt install suricata", then press Apply.']);
    } else if (st.enabled && !s.running) {
      items.push(['warn', 'Suricata is not running', 'Intrusion detection is switched on but the engine is stopped. Press Apply to start it.']);
    } else if (st.enabled && s.running && !s.ready) {
      items.push(['', 'Suricata is starting', 'It is loading its signatures. This can take a minute.']);
    } else if (!st.enabled && s.running) {
      items.push(['warn', 'Intrusion detection is switched off, but Suricata is still running', 'Press Apply to stop it.']);
    }

    if (st.enabled && st.mode === 'ips' && s.installed && !s.ready) {
      items.push(['warn', 'Blocking is not active', 'Until Suricata is ready, forwarded traffic is not being inspected.']);
    }

    if (st.enabled && st.rules.rule_count === 0 && s.installed) {
      items.push(['warn', 'No signatures yet', 'Suricata has nothing to look for. They download automatically within a few minutes, or press "Update rules now" on the Overview tab.']);
    }

    items.forEach(([kind, title, text]) => {
      box.append(h('div', { class: 'notice' + (kind ? ' ' + kind : '') },
        icon(kind === 'bad' || kind === 'warn' ? 'i-alert' : 'i-info'),
        h('div', null, h('b', { text: title }), ' ', text)));
    });
  }

  function renderEngine(st) {
    const s = st.suricata;

    kv($('engStatus'), [
      ['Engine', engineBadge(st)],
      ['Version', s.version || '–'],
      ['Switched on', st.enabled ? badge('Yes', 'ok') : badge('No', '')],
      ['Mode', st.mode === 'ips' ? 'Detect and block (IPS)' : 'Detect only (IDS)'],
      ['Protection', st.enabled && s.ready
        ? (st.mode === 'ips' ? badge('Blocking attacks', 'ok') : badge('Watching traffic', 'info'))
        : badge('Not active', '')],
      ['Service installed', s.unit_installed ? 'Yes' : 'No']
    ]);
  }

  function renderRules(st) {
    const r = st.rules;

    kv($('rulesInfo'), [
      ['Signatures', r.exists ? num(r.rule_count) : 'No file yet'],
      ['File size', r.exists ? bytes(r.size_bytes) : '–'],
      ['Last changed', r.modified_at ? ago(r.modified_at) : '–'],
      ['File', h('span', { class: 'mono', text: r.path })]
    ]);

    const box = clear($('lastUpdateBox'));
    const last = st.last_rule_update;

    if (!last) {
      box.append(h('p', { class: 'card-sub', text: 'No signature update has run since the firewall started.' }));
      return;
    }

    const counts = last.total_rules !== null && last.total_rules !== undefined
      ? num(last.total_rules) + ' signatures' + (last.enabled_rules !== null && last.enabled_rules !== undefined ? ' (' + num(last.enabled_rules) + ' enabled)' : '')
      : '';

    box.append(h('div', { class: 'notice ' + (last.success ? 'ok' : 'bad') },
      icon(last.success ? 'i-check' : 'i-alert'),
      h('div', null,
        h('b', { text: last.success ? 'Last update succeeded ' + ago(last.finished_at) : 'Last update failed ' + ago(last.finished_at) }),
        counts ? h('div', { text: counts }) : null,
        last.message ? h('pre', { text: last.message }) : null)));
  }

  async function refreshStatus() {
    const st = await api('/api/ids/status');
    state.status = st;
    renderNotices(st);
    renderEngine(st);
    renderRules(st);
  }

  /* ---------------- summary and top alerts ---------------- */

  function renderTopSignatures(list) {
    const body = clear($('topSigs'));

    if (!list.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 4, text: 'No alerts in the last 24 hours.' })));
      return;
    }

    list.forEach((item) => {
      body.append(h('tr', null,
        h('td', { class: 'mono nowrap', text: item.sid }),
        h('td', { text: item.signature }),
        h('td', { class: 'num', text: num(item.hits) }),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => showEventsFor(item.sid) }, 'Events'),
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => disableSignature(item) }, 'Disable'))));
    });
  }

  async function refreshSummary() {
    const s = await api('/api/ids/summary');
    $('stTotal').textContent = num(s.total_events);
    $('stBlocked').textContent = num(s.blocked_24h);
    $('stAlerted').textContent = num(s.alerted_24h);
    renderTopSignatures(s.top_signatures_24h || []);
  }

  function showEventsFor(sid) {
    $('evSid').value = String(sid);
    $('evAction').value = '';
    state.evOffset = 0;
    tabCtl.show('events');
  }

  async function disableSignature(item) {
    const ok = await confirmBox(
      'Disable signature ' + item.sid + '?\n\n' + item.signature + '\n\nIt stops raising alerts after the next signature update.',
      { ok: 'Disable', danger: true, title: 'Disable signature' }
    );
    if (!ok) return;

    try {
      await api('/api/ids/overrides', { method: 'POST', body: { sid: item.sid, action: 'disable', comment: 'Disabled from the top alerts list' } });
      toast('Signature ' + item.sid + ' will be disabled. Press "Update rules now" to apply it straight away.', 'ok');
      await loadOverrides();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  /* ---------------- settings ---------------- */

  function readForm() {
    return {
      enabled: $('sEnabled').checked,
      mode: $('sMode').value,
      interfaces: $('sInterfaces').value.trim(),
      queue_num: Number($('sQueue').value),
      fail_mode: $('sFailMode').value,
      home_net: $('sHomeNet').value.trim(),
      rule_update_hours: Number($('sRuleHours').value),
      event_retention_days: Number($('sRetention').value)
    };
  }

  function fillForm(s) {
    $('sEnabled').checked = !!s.enabled;
    $('sMode').value = s.mode;
    $('sInterfaces').value = s.interfaces || '';
    $('sQueue').value = s.queue_num;
    $('sFailMode').value = s.fail_mode;
    $('sHomeNet').value = s.home_net || '';
    $('sRuleHours').value = s.rule_update_hours;
    $('sRetention').value = s.event_retention_days;
  }

  function syncModeFields() {
    const mode = $('sMode').value;
    $('sModeHelp').textContent = MODE_HELP[mode] || '';
    document.querySelectorAll('#settingsForm [data-for]').forEach((f) => {
      f.hidden = f.dataset.for !== mode;
    });
  }

  function isDirty() {
    return state.loadedJson !== '' && JSON.stringify(readForm()) !== state.loadedJson;
  }

  function updateDirty() {
    $('settingsState').textContent = isDirty() ? 'You have unsaved changes.' : '';
  }

  async function loadSettings() {
    const s = await api('/api/ids/settings');
    fillForm(s);
    syncModeFields();
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
    ['sInterfaces', 'sQueue', 'sHomeNet', 'sRuleHours', 'sRetention'].forEach((id) => markInvalid(id, false));

    const form = readForm();
    let message = '';

    if (form.mode === 'ids') {
      if (form.enabled && !form.interfaces) {
        markInvalid('sInterfaces', true);
        message = 'Enter at least one interface to watch, for example eth0.';
      }
    } else {
      message = message || whole('sQueue', 'Queue number', 1, 65535);
    }

    message = message || whole('sRuleHours', 'The signature update interval', 0, 720);
    message = message || whole('sRetention', 'The event retention', 1, 365);

    if (!form.home_net) {
      markInvalid('sHomeNet', true);
      message = message || 'Enter your home networks, for example [192.168.0.0/16,10.0.0.0/8].';
    }

    setError('settingsError', message);
    return !message;
  }

  /* Saves the form. Returns true when the server accepted it. */
  async function saveSettings() {
    if (!checkForm()) return false;

    try {
      await api('/api/ids/settings', { method: 'PUT', body: readForm() });
    } catch (e) {
      setError('settingsError', errorText(e));
      return false;
    }

    await loadSettings();
    await refreshStatus().catch(() => {});
    return true;
  }

  /* ---------------- apply ---------------- */

  async function applyNow() {
    if (isDirty()) {
      const go = await confirmBox(
        'Some settings on the Settings tab are not saved. Apply only uses what is already saved.\n\nApply the saved settings anyway?',
        { ok: 'Apply saved settings', title: 'Unsaved changes' }
      );
      if (!go) return;
    }

    await runApply();
  }

  async function runApply() {
    toast('Applying… this can take a minute while Suricata loads its signatures.', 'info', 8000);

    try {
      const result = await lock([btnApply, $('btnSaveApply')], () => api('/api/ids/apply', { method: 'POST' }));
      toast(result && result.message ? result.message : 'Applied.', 'ok');
    } catch (e) {
      toast(errorText(e), 'bad');
    }

    await refreshStatus().catch(() => {});
  }

  /* ---------------- signature update ---------------- */

  async function updateRules() {
    toast('Downloading signatures… this can take a few minutes.', 'info', 8000);

    try {
      const status = await lock([$('btnUpdateRules'), $('btnOvUpdate')], () => api('/api/ids/rules/update', { method: 'POST' }));
      const count = status && status.total_rules !== null && status.total_rules !== undefined
        ? ' (' + num(status.total_rules) + ' signatures)'
        : '';
      toast('Signatures updated' + count + '.', 'ok');
    } catch (e) {
      toast(errorText(e), 'bad');
    }

    await refreshStatus().catch(() => {});
  }

  /* ---------------- rule overrides ---------------- */

  const OVERRIDE_LABELS = {
    disable: ['Disabled', ''],
    alert: ['Alert only', 'info'],
    drop: ['Drop (block)', 'bad']
  };

  async function loadOverrides() {
    const list = await api('/api/ids/overrides');
    $('tabCountOverrides').textContent = String(list.length);

    const body = clear($('ovBody'));

    if (!list.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 4, text: 'No overrides. Every signature behaves as shipped.' })));
      return;
    }

    list.forEach((item) => {
      const label = OVERRIDE_LABELS[item.action] || [item.action, ''];

      body.append(h('tr', null,
        h('td', { class: 'mono nowrap', text: item.sid }),
        h('td', null, badge(label[0], label[1])),
        h('td', { class: 'wide', text: item.comment || '' }),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteOverride(item) },
            icon('i-trash'), 'Remove'))));
    });
  }

  async function deleteOverride(item) {
    const ok = await confirmBox('Remove the override for signature ' + item.sid + '? It goes back to its normal behaviour after the next signature update.',
      { ok: 'Remove', danger: true, title: 'Remove override' });
    if (!ok) return;

    try {
      await api('/api/ids/overrides/' + encodeURIComponent(item.id), { method: 'DELETE' });
      toast('Override removed.', 'ok');
      await loadOverrides();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  async function addOverride(ev) {
    ev.preventDefault();
    setError('ovError', '');
    markInvalid('ovSid', false);

    const raw = $('ovSid').value.trim();
    const sid = Number(raw);

    if (raw === '' || !Number.isInteger(sid) || sid < 1) {
      markInvalid('ovSid', true);
      setError('ovError', 'Enter the signature ID as a positive whole number.');
      return;
    }

    const comment = $('ovComment').value.trim();

    try {
      await lock([$('btnAddOverride')], () => api('/api/ids/overrides', {
        method: 'POST',
        body: { sid, action: $('ovAction').value, comment: comment || null }
      }));
    } catch (e) {
      setError('ovError', errorText(e));
      return;
    }

    $('ovSid').value = '';
    $('ovComment').value = '';
    toast('Override saved. Press "Update rules now" to apply it straight away.', 'ok');
    await loadOverrides();
  }

  /* ---------------- events ---------------- */

  const SEVERITY = {
    1: ['High', 'tag-red'],
    2: ['Medium', 'tag-orange'],
    3: ['Low', 'tag-blue']
  };

  function eventRow(e) {
    const sev = SEVERITY[e.severity] || ['Info', 'tag-violet'];
    const blocked = e.action === 'blocked';
    const proto = String(e.proto || '').toUpperCase() + (e.app_proto ? ' · ' + e.app_proto : '');

    return h('tr', null,
      h('td', { class: 'nowrap', text: fmtTime(e.ts) }),
      h('td', { class: 'mono nowrap', text: endpoint(e.src_ip, e.src_port) }),
      h('td', { class: 'mono nowrap', text: endpoint(e.dest_ip, e.dest_port) }),
      h('td', { class: 'nowrap', text: proto }),
      h('td', { class: 'wide' },
        e.signature,
        h('span', { class: 'sub', text: 'ID ' + e.sid + (e.category ? ' · ' + e.category : '') })),
      h('td', null, h('span', { class: 'tag ' + sev[1], text: sev[0] })),
      h('td', null, blocked ? badge('Blocked', 'bad') : badge('Alert', 'warn')));
  }

  function eventQuery() {
    const q = new URLSearchParams();
    q.set('limit', String(PAGE_SIZE + 1));
    q.set('offset', String(state.evOffset));

    const action = $('evAction').value;
    if (action) q.set('action', action);

    const sid = $('evSid').value.trim();
    if (sid !== '') q.set('sid', sid);

    return q.toString();
  }

  async function loadEvents() {
    let list;
    try {
      list = await api('/api/ids/events?' + eventQuery());
    } catch (e) {
      toast(errorText(e), 'bad');
      return;
    }

    state.evHasNext = list.length > PAGE_SIZE;
    const shown = list.slice(0, PAGE_SIZE);

    const body = clear($('evBody'));

    if (!shown.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 7, text: state.evOffset > 0 ? 'No more events.' : 'No events match.' })));
    } else {
      shown.forEach((e) => body.append(eventRow(e)));
    }

    const from = shown.length ? state.evOffset + 1 : 0;
    $('evInfo').textContent = shown.length ? 'Showing ' + from + ' to ' + (state.evOffset + shown.length) : '';
    $('evPrev').disabled = state.evOffset === 0;
    $('evNext').disabled = !state.evHasNext;
  }

  async function clearEvents() {
    const ok = await confirmBox('Delete every stored intrusion event? This cannot be undone.',
      { ok: 'Delete all', danger: true, title: 'Clear events' });
    if (!ok) return;

    try {
      const r = await api('/api/ids/events', { method: 'DELETE' });
      toast((r && r.deleted !== undefined ? num(r.deleted) : 'All') + ' events deleted.', 'ok');
      state.evOffset = 0;
      await Promise.all([loadEvents(), refreshSummary()]);
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  /* ---------------- polling ---------------- */

  async function refresh() {
    try {
      await Promise.all([refreshStatus(), refreshSummary()]);

      const dialogOpen = !!document.querySelector('.modal-back');
      if (state.tab === 'events' && state.evOffset === 0 && !dialogOpen) await loadEvents();

      live(true, 'Live');
    } catch (e) {
      live(false, 'Connection lost');
    }
  }

  /* ---------------- wiring ---------------- */

  const tabCtl = tabs($('page'), 'ids', (name) => {
    state.tab = name;
    if (name === 'events') loadEvents();
    if (name === 'overrides') loadOverrides().catch(() => {});
  });

  $('sMode').addEventListener('change', () => { syncModeFields(); updateDirty(); });
  $('settingsForm').addEventListener('input', (ev) => {
    if (ev.target.classList) ev.target.classList.remove('invalid');
    updateDirty();
  });

  $('settingsForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const ok = await lock([$('btnSaveSettings')], saveSettings);
    if (ok) toast('Settings saved. Press Apply to put them into effect.', 'ok');
  });

  $('btnSaveApply').addEventListener('click', async () => {
    const ok = await lock([$('btnSaveApply')], saveSettings);
    if (ok) await runApply();
  });

  btnApply.addEventListener('click', applyNow);

  btnRefresh.addEventListener('click', async () => {
    btnRefresh.classList.add('spin');
    await refresh();
    if (state.tab === 'overrides') await loadOverrides().catch(() => {});
    btnRefresh.classList.remove('spin');
  });

  $('btnUpdateRules').addEventListener('click', updateRules);
  $('btnOvUpdate').addEventListener('click', updateRules);

  $('ovForm').addEventListener('submit', addOverride);
  $('ovSid').addEventListener('input', () => $('ovSid').classList.remove('invalid'));

  $('evAction').addEventListener('change', () => { state.evOffset = 0; loadEvents(); });

  let sidTimer = null;
  $('evSid').addEventListener('input', () => {
    clearTimeout(sidTimer);
    sidTimer = setTimeout(() => { state.evOffset = 0; loadEvents(); }, 300);
  });

  $('btnEvRefresh').addEventListener('click', loadEvents);
  $('btnEvClear').addEventListener('click', clearEvents);
  $('evPrev').addEventListener('click', () => { state.evOffset = Math.max(0, state.evOffset - PAGE_SIZE); loadEvents(); });
  $('evNext').addEventListener('click', () => { if (state.evHasNext) { state.evOffset += PAGE_SIZE; loadEvents(); } });

  loadSettings().catch((e) => toast(errorText(e), 'bad'));
  loadOverrides().catch(() => {});
  every(refresh, POLL_MS);
})();
