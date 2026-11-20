(function () {
  'use strict';

  const { h, icon, clear, toast, confirmBox, tabs, num, errorText } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'sni',
    title: 'App Control',
    subtitle: 'Block applications and sites by the name in the connection',
    content: $('page')
  });
  if (!frame) return;

  const state = { apps: [], rules: [] };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' }, icon('i-refresh'));
  frame.tools.append(btnRefresh);

  function setError(id, message) {
    const box = $(id);
    box.textContent = message || '';
    box.hidden = !message;
  }

  async function lock(buttons, work) {
    const list = buttons.filter(Boolean);
    list.forEach((b) => { b.disabled = true; b.classList.add('busy'); });
    try { return await work(); }
    finally { list.forEach((b) => { b.disabled = false; b.classList.remove('busy'); }); }
  }

  function badge(text, kind) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  }

  function updateStats() {
    $('stApps').textContent = num(state.apps.length);
    $('stBlocked').textContent = num(state.apps.filter((a) => a.action === 'block').length);
    $('stRules').textContent = num(state.rules.length);
    $('tabCountRules').textContent = String(state.rules.length);
  }

  /* ---------------- settings ---------------- */

  async function loadSettings() {
    const s = await api('/api/sni/settings');
    $('sEnabled').checked = !!s.enabled;
    $('sDns').checked = !!s.use_dns_filter_lists;
    $('sMalformed').checked = !!s.block_malformed;
    $('sQuic').checked = !!s.block_quic;
    $('sNoName').value = s.no_name_action || 'allow';
    $('settingsState').textContent = s.enabled ? 'Filtering is on.' : 'Filtering is off.';
  }

  async function saveSettings(ev) {
    ev.preventDefault();
    setError('settingsError', '');
    try {
      await lock([$('btnSave')], () => api('/api/sni/settings', {
        method: 'PUT',
        body: {
          enabled: $('sEnabled').checked,
          use_dns_filter_lists: $('sDns').checked,
          no_name_action: $('sNoName').value,
          block_malformed: $('sMalformed').checked,
          block_quic: $('sQuic').checked
        }
      }));
      toast('Settings saved.', 'ok');
      await loadSettings();
    } catch (e) {
      setError('settingsError', errorText(e));
    }
  }

  /* ---------------- apps ---------------- */

  async function loadApps() {
    state.apps = await api('/api/sni/apps');
    updateStats();

    const root = clear($('appGroups'));
    const groups = {};
    state.apps.forEach((a) => { (groups[a.category] = groups[a.category] || []).push(a); });

    Object.keys(groups).sort().forEach((cat) => {
      const body = h('tbody');
      groups[cat].forEach((a) => body.append(appRow(a)));

      root.append(h('div', { class: 'card' },
        h('div', { class: 'card-h' }, h('h3', { text: cat })),
        h('div', { class: 'tbl-wrap' },
          h('table', { class: 'dtable' },
            h('thead', null, h('tr', null, h('th', { text: 'App' }), h('th', { text: 'Sites' }), h('th', { text: 'Choice' }))),
            body))));
    });
  }

  function appRow(a) {
    const select = h('select', { class: 'in', 'aria-label': 'Choice for ' + a.name },
      h('option', { value: 'default', text: 'Not managed' }),
      h('option', { value: 'block', text: 'Block' }),
      h('option', { value: 'allow', text: 'Allow' }));
    select.value = a.action || 'default';
    select.addEventListener('change', () => setApp(a, select));

    return h('tr', null,
      h('td', null, h('b', { text: a.name }), a.note ? h('div', { class: 'muted', text: a.note }) : null),
      h('td', { class: 'mono wide', text: (a.domains || []).join(', ') }),
      h('td', null, h('span', { class: 'select-wrap' }, select)));
  }

  async function setApp(a, select) {
    const previous = a.action || 'default';
    select.disabled = true;
    try {
      await api('/api/sni/apps/' + encodeURIComponent(a.id), { method: 'PUT', body: { action: select.value } });
      toast(a.name + ': ' + (select.value === 'default' ? 'not managed' : select.value) + '.', 'ok');
      await loadApps();
    } catch (e) {
      select.value = previous;
      select.disabled = false;
      toast(errorText(e), 'bad');
    }
  }

  /* ---------------- site rules ---------------- */

  async function loadRules() {
    state.rules = await api('/api/sni/rules');
    updateStats();

    const body = clear($('ruleBody'));
    if (!state.rules.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 4, text: 'No site rules.' })));
      return;
    }

    state.rules.forEach((r) => {
      const next = r.action === 'block' ? 'allow' : 'block';
      body.append(h('tr', null,
        h('td', { class: 'mono wide', text: r.domain }),
        h('td', null, badge(r.action === 'block' ? 'Block' : 'Allow', r.action === 'block' ? 'bad' : 'ok')),
        h('td', { class: 'wide', text: r.comment || '' }),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => flipRule(r, next) },
            icon('i-swap'), next === 'allow' ? 'Make Allow' : 'Make Block'),
          ' ',
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteRule(r) },
            icon('i-trash'), 'Remove'))));
    });
  }

  async function flipRule(r, action) {
    try {
      await api('/api/sni/rules/' + encodeURIComponent(r.id), {
        method: 'PUT',
        body: { domain: r.domain, action, comment: r.comment || null }
      });
      await loadRules();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  async function deleteRule(r) {
    const ok = await confirmBox('Remove the rule for ' + r.domain + '?', { ok: 'Remove', danger: true, title: 'Remove rule' });
    if (!ok) return;
    try {
      await api('/api/sni/rules/' + encodeURIComponent(r.id), { method: 'DELETE' });
      toast('Rule removed.', 'ok');
      await loadRules();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  async function addRule(ev) {
    ev.preventDefault();
    setError('ruleError', '');
    const domain = $('rDomain').value.trim();
    if (!domain) { setError('ruleError', 'Enter a domain such as example.com.'); return; }

    try {
      await lock([$('btnAddRule')], () => api('/api/sni/rules', {
        method: 'POST',
        body: { domain, action: $('rAction').value, comment: $('rComment').value.trim() || null }
      }));
      $('rDomain').value = '';
      $('rComment').value = '';
      toast('Rule added.', 'ok');
      await loadRules();
    } catch (e) {
      setError('ruleError', errorText(e));
    }
  }

  /* ---------------- start ---------------- */

  async function refresh() {
    try {
      await Promise.all([loadSettings(), loadApps(), loadRules()]);
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  tabs($('page'), 'sni');
  $('settingsForm').addEventListener('submit', saveSettings);
  $('ruleForm').addEventListener('submit', addRule);
  btnRefresh.addEventListener('click', refresh);
  refresh();
})();
