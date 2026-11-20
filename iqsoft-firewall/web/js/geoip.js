(function () {
  'use strict';

  const { h, icon, clear, toast, confirmBox, tabs, num, errorText } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'geoip',
    title: 'GeoIP Blocking',
    subtitle: 'Block traffic to and from whole countries',
    content: $('page')
  });
  if (!frame) return;

  const state = { policies: [], sets: [] };
  const DIR_LABELS = { inbound: 'Inbound', outbound: 'Outbound', both: 'Both' };

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

  function code(value) {
    return String(value || '').trim().toUpperCase();
  }

  function validCode(value) {
    return /^[A-Z]{2}$/.test(value);
  }

  function hasList(cc) {
    return state.sets.some((s) => code(s.country_code) === code(cc));
  }

  function updateStats() {
    $('stCountries').textContent = num(state.sets.length);
    $('stPolicies').textContent = num(state.policies.filter((p) => p.enabled).length);
    $('stRanges').textContent = num(state.sets.reduce((n, s) => n + (s.ipv4_count || 0) + (s.ipv6_count || 0), 0));
    $('tabCountPolicies').textContent = String(state.policies.length);
    $('tabCountSets').textContent = String(state.sets.length);
  }

  /* ---------------- policies ---------------- */

  function renderPolicies() {
    const body = clear($('polBody'));
    if (!state.policies.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 6, text: 'No policies. No country is blocked.' })));
      return;
    }

    state.policies.forEach((p) => {
      const toggle = h('input', { type: 'checkbox' });
      toggle.checked = !!p.enabled;
      toggle.addEventListener('change', () => setEnabled(p, toggle));

      body.append(h('tr', null,
        h('td', { class: 'mono nowrap' }, h('b', { text: code(p.country_code) })),
        h('td', null, badge(DIR_LABELS[p.direction] || p.direction)),
        h('td', null, h('label', { class: 'switch' }, toggle, h('span', { class: 'slider' }))),
        h('td', null, hasList(p.country_code) ? badge('Loaded', 'ok') : badge('Not loaded', 'bad')),
        h('td', { class: 'wide', text: p.comment || '' }),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deletePolicy(p) },
            icon('i-trash'), 'Remove'))));
    });
  }

  async function loadPolicies() {
    state.policies = await api('/api/geoip/policies');
    updateStats();
    renderPolicies();
  }

  async function setEnabled(p, box) {
    box.disabled = true;
    try {
      await api('/api/geoip/policies/' + encodeURIComponent(p.id), {
        method: 'PUT',
        body: { country_code: p.country_code, direction: p.direction, enabled: box.checked, comment: p.comment || null }
      });
      toast(code(p.country_code) + (box.checked ? ' policy turned on.' : ' policy turned off.') + ' Apply the firewall rules to use it.', 'ok');
      await loadPolicies();
    } catch (e) {
      box.checked = !box.checked;
      box.disabled = false;
      toast(errorText(e), 'bad');
    }
  }

  async function deletePolicy(p) {
    const ok = await confirmBox('Remove the ' + (DIR_LABELS[p.direction] || p.direction).toLowerCase() + ' policy for ' + code(p.country_code) + '?',
      { ok: 'Remove', danger: true, title: 'Remove policy' });
    if (!ok) return;
    try {
      await api('/api/geoip/policies/' + encodeURIComponent(p.id), { method: 'DELETE' });
      toast('Policy removed. Apply the firewall rules to use the change.', 'ok');
      await loadPolicies();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  async function addPolicy(ev) {
    ev.preventDefault();
    setError('polError', '');
    const cc = code($('pCode').value);
    if (!validCode(cc)) { setError('polError', 'Enter a two-letter country code such as CN.'); return; }

    try {
      await lock([$('btnAddPol')], () => api('/api/geoip/policies', {
        method: 'POST',
        body: { country_code: cc, direction: $('pDir').value, enabled: true, comment: $('pComment').value.trim() || null }
      }));
      $('pCode').value = '';
      $('pComment').value = '';
      toast('Policy added. Apply the firewall rules to use it.', 'ok');
      await loadPolicies();
      $('polHint').textContent = hasList(cc) ? '' : 'No address list for ' + cc + ' yet. Load one in the Country lists tab.';
    } catch (e) {
      setError('polError', errorText(e));
    }
  }

  /* ---------------- country lists ---------------- */

  async function loadSets() {
    state.sets = await api('/api/geoip/datasets');
    updateStats();

    const body = clear($('setBody'));
    if (!state.sets.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 6, text: 'No country lists loaded.' })));
    }

    state.sets.forEach((s) => {
      body.append(h('tr', null,
        h('td', { class: 'mono nowrap' }, h('b', { text: code(s.country_code) })),
        h('td', { class: 'mono', text: num(s.ipv4_count || 0) }),
        h('td', { class: 'mono', text: num(s.ipv6_count || 0) }),
        h('td', { class: 'wide', text: s.source || '–' }),
        h('td', { class: 'nowrap', text: s.updated_at || '–' }),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => { $('dCode').value = code(s.country_code); $('dData').focus(); } },
            icon('i-upload'), 'Replace'),
          ' ',
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteSet(s) },
            icon('i-trash'), 'Delete'))));
    });

    renderPolicies();
  }

  async function deleteSet(s) {
    const ok = await confirmBox('Delete the address list for ' + code(s.country_code) + '? Policies for it stop blocking anything.',
      { ok: 'Delete', danger: true, title: 'Delete list' });
    if (!ok) return;
    try {
      await api('/api/geoip/datasets/' + encodeURIComponent(code(s.country_code)), { method: 'DELETE' });
      toast('List deleted.', 'ok');
      await loadSets();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  $('dFile').addEventListener('change', () => {
    const file = $('dFile').files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      $('dData').value = String(reader.result || '');
      if (!$('dSource').value) $('dSource').value = file.name;
    };
    reader.onerror = () => setError('setError', 'Could not read that file.');
    reader.readAsText(file);
  });

  async function importSet(ev) {
    ev.preventDefault();
    setError('setError', '');
    const cc = code($('dCode').value);
    const data = $('dData').value;

    if (!validCode(cc)) { setError('setError', 'Enter a two-letter country code such as CN.'); return; }
    if (!data.trim()) { setError('setError', 'Paste address ranges or choose a file.'); return; }

    if (hasList(cc)) {
      const ok = await confirmBox('Replace the address list for ' + cc + '?', { ok: 'Replace', title: 'Replace list' });
      if (!ok) return;
    }

    try {
      const r = await lock([$('btnImport')], () => api('/api/geoip/datasets/' + encodeURIComponent(cc), {
        method: 'PUT',
        body: { data, source: $('dSource').value.trim() || null }
      }));
      $('setState').textContent = num(r.ipv4_imported) + ' IPv4 and ' + num(r.ipv6_imported) + ' IPv6 ranges loaded, ' + num(r.skipped) + ' skipped.';
      $('dData').value = '';
      $('dFile').value = '';
      toast('List for ' + cc + ' loaded. Apply the firewall rules to use it.', 'ok');
      await loadSets();
    } catch (e) {
      setError('setError', errorText(e));
    }
  }

  /* ---------------- start ---------------- */

  async function refresh() {
    try {
      await loadSets();
      await loadPolicies();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  tabs($('page'), 'geoip');
  $('polForm').addEventListener('submit', addPolicy);
  $('setForm').addEventListener('submit', importSet);
  btnRefresh.addEventListener('click', refresh);
  refresh();
})();
