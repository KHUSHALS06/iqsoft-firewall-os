(function () {
  'use strict';

  const { h, icon, clear, toast, confirmBox, tabs, num, errorText } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'dnsfilter',
    title: 'DNS Filter',
    subtitle: 'Block unwanted domains at the DNS level',
    content: $('page')
  });
  if (!frame) return;

  const state = { cats: [], rules: [] };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' }, icon('i-refresh'));
  frame.tools.append(btnRefresh);

  /* ---------------- helpers ---------------- */

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

  /* Saving also applies the filter to the DNS service. If that step failed the data
     is still saved, so tell the user it is not live yet. */
  function checkApplied(r) {
    if (r && r.applied === false) {
      toast('Saved, but not applied to the DNS server: ' + (r.apply_error || 'unknown error') +
        ' Check the DNS server page.', 'bad');
      return false;
    }
    return true;
  }

  function badge(text, kind) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  }

  function updateStats() {
    $('stCats').textContent = num(state.cats.length);
    $('stDomains').textContent = num(state.cats.filter((c) => c.enabled).reduce((n, c) => n + (c.domain_count || 0), 0));
    $('stRules').textContent = num(state.rules.length);
    $('tabCountCats').textContent = String(state.cats.length);
    $('tabCountRules').textContent = String(state.rules.length);
  }

  /* ---------------- settings ---------------- */

  async function loadSettings() {
    const s = await api('/api/dnsfilter/settings');
    $('sEnabled').checked = !!s.enabled;
    $('sBlock').value = s.block_response || 'nxdomain';
    $('sSafe').checked = !!s.safe_search;
    $('sEnforce').checked = !!s.enforce_dns;
    $('settingsState').textContent = s.enabled ? 'Filtering is on.' : 'Filtering is off.';
  }

  async function saveSettings(ev) {
    ev.preventDefault();
    setError('settingsError', '');
    try {
      const res = await lock([$('btnSave')], () => api('/api/dnsfilter/settings', {
        method: 'PUT',
        body: {
          enabled: $('sEnabled').checked,
          block_response: $('sBlock').value,
          safe_search: $('sSafe').checked,
          enforce_dns: $('sEnforce').checked
        }
      }));
      if (checkApplied(res)) toast('DNS filter settings saved and applied.', 'ok');
      await loadSettings();
    } catch (e) {
      setError('settingsError', errorText(e));
    }
  }

  /* ---------------- categories ---------------- */

  async function loadCategories() {
    state.cats = await api('/api/dnsfilter/categories');
    updateStats();

    const body = clear($('catBody'));
    if (!state.cats.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 6, text: 'No categories yet. Add one above.' })));
    }

    state.cats.forEach((c) => {
      const toggle = h('input', { type: 'checkbox' });
      toggle.checked = !!c.enabled;
      toggle.addEventListener('change', () => setCategoryEnabled(c, toggle));

      body.append(h('tr', null,
        h('td', null, h('b', { text: c.name }), c.comment ? h('div', { class: 'muted', text: c.comment }) : null),
        h('td', null, h('label', { class: 'switch' }, toggle, h('span', { class: 'slider' }))),
        h('td', { class: 'mono nowrap', text: num(c.domain_count || 0) }),
        h('td', { class: 'wide', text: c.source || '–' }),
        h('td', { class: 'nowrap', text: c.updated_at || '–' }),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => { $('iCat').value = c.name; $('iData').focus(); } },
            icon('i-upload'), 'Import'),
          ' ',
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteCategory(c) },
            icon('i-trash'), 'Delete'))));
    });

    const sel = clear($('iCat'));
    state.cats.forEach((c) => sel.append(h('option', { value: c.name, text: c.name })));
  }

  async function setCategoryEnabled(c, box) {
    box.disabled = true;
    try {
      const res = await api('/api/dnsfilter/categories/' + encodeURIComponent(c.name), {
        method: 'PUT',
        body: { name: c.name, enabled: box.checked, comment: c.comment || null }
      });
      if (checkApplied(res)) toast('Category "' + c.name + '" ' + (box.checked ? 'turned on.' : 'turned off.'), 'ok');
      await loadCategories();
    } catch (e) {
      box.checked = !box.checked;
      toast(errorText(e), 'bad');
    } finally {
      box.disabled = false;
    }
  }

  async function deleteCategory(c) {
    const ok = await confirmBox('Delete the category "' + c.name + '" and its ' + num(c.domain_count || 0) + ' domains?',
      { ok: 'Delete', danger: true, title: 'Delete category' });
    if (!ok) return;
    try {
      const res = await api('/api/dnsfilter/categories/' + encodeURIComponent(c.name), { method: 'DELETE' });
      if (checkApplied(res)) toast('Category deleted.', 'ok');
      await loadCategories();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  async function addCategory(ev) {
    ev.preventDefault();
    setError('catError', '');
    const name = $('cName').value.trim();
    if (!name) { setError('catError', 'Enter a name for the category.'); return; }

    try {
      const res = await lock([$('btnAddCat')], () => api('/api/dnsfilter/categories', {
        method: 'POST',
        body: { name, enabled: true, comment: $('cComment').value.trim() || null }
      }));
      $('cName').value = '';
      $('cComment').value = '';
      if (checkApplied(res)) toast('Category added.', 'ok');
      await loadCategories();
    } catch (e) {
      setError('catError', errorText(e));
    }
  }

  /* ---------------- import ---------------- */

  $('iFile').addEventListener('change', () => {
    const file = $('iFile').files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      $('iData').value = String(reader.result || '');
      if (!$('iSource').value) $('iSource').value = file.name;
    };
    reader.onerror = () => setError('impError', 'Could not read that file.');
    reader.readAsText(file);
  });

  async function importList(ev) {
    ev.preventDefault();
    setError('impError', '');
    const name = $('iCat').value;
    const data = $('iData').value;

    if (!name) { setError('impError', 'Add a category first, then choose it here.'); return; }
    if (!data.trim()) { setError('impError', 'Paste a list of domains or choose a file.'); return; }

    const ok = await confirmBox('Replace the whole list of "' + name + '" with this one?',
      { ok: 'Import', title: 'Import list' });
    if (!ok) return;

    try {
      const r = await lock([$('btnImport')], () => api('/api/dnsfilter/categories/' + encodeURIComponent(name) + '/domains', {
        method: 'PUT',
        body: { data, source: $('iSource').value.trim() || null }
      }));
      $('impState').textContent = num(r.imported) + ' domains imported, ' + num(r.skipped) + ' skipped.';
      $('iData').value = '';
      $('iFile').value = '';
      if (checkApplied(r)) toast('Imported ' + num(r.imported) + ' domains into "' + r.category + '" and applied.', 'ok');
      await loadCategories();
    } catch (e) {
      setError('impError', errorText(e));
    }
  }

  /* ---------------- custom rules ---------------- */

  async function loadRules() {
    state.rules = await api('/api/dnsfilter/rules');
    updateStats();

    const body = clear($('ruleBody'));
    if (!state.rules.length) {
      body.append(h('tr', null, h('td', { class: 'empty-row', colspan: 4, text: 'No custom rules.' })));
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
      const res = await api('/api/dnsfilter/rules/' + encodeURIComponent(r.id), {
        method: 'PUT',
        body: { domain: r.domain, action, comment: r.comment || null }
      });
      if (checkApplied(res)) toast('Rule updated.', 'ok');
      await loadRules();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  async function deleteRule(r) {
    const ok = await confirmBox('Remove the rule for ' + r.domain + '?', { ok: 'Remove', danger: true, title: 'Remove rule' });
    if (!ok) return;
    try {
      const res = await api('/api/dnsfilter/rules/' + encodeURIComponent(r.id), { method: 'DELETE' });
      if (checkApplied(res)) toast('Rule removed.', 'ok');
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
      const res = await lock([$('btnAddRule')], () => api('/api/dnsfilter/rules', {
        method: 'POST',
        body: { domain, action: $('rAction').value, comment: $('rComment').value.trim() || null }
      }));
      $('rDomain').value = '';
      $('rComment').value = '';
      if (checkApplied(res)) toast('Rule added.', 'ok');
      await loadRules();
    } catch (e) {
      setError('ruleError', errorText(e));
    }
  }

  /* ---------------- start ---------------- */

  async function refresh() {
    try {
      await Promise.all([loadSettings(), loadCategories(), loadRules()]);
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  tabs($('page'), 'dnsfilter');
  $('settingsForm').addEventListener('submit', saveSettings);
  $('catForm').addEventListener('submit', addCategory);
  $('impForm').addEventListener('submit', importList);
  $('ruleForm').addEventListener('submit', addRule);
  btnRefresh.addEventListener('click', refresh);
  refresh();
})();
