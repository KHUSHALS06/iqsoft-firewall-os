(function () {
  'use strict';

  const { h, icon, clear, toast, openModal, confirmBox, busy, every, live, ago, fmtTime, num, errorText } = Shell;

  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'threat',
    title: 'Threat Intelligence',
    subtitle: 'Block traffic from and to known-bad addresses',
    content: $('page')
  });
  if (!frame) return;

  const PAGE_SIZE = 100;

  const DIRECTIONS = {
    inbound: ['Inbound', 'info'],
    outbound: ['Outbound', 'warn'],
    both: ['Both ways', '']
  };

  const state = { feeds: [], search: '' };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' },
    icon('i-refresh'));
  frame.tools.append(btnRefresh);

  function apiMessage(e) {
    if (e && e.data && typeof e.data === 'object') {
      if (e.data.error) return e.data.error;
      if (e.data.message) return e.data.message;
    }
    return errorText(e);
  }

  function badge(text, kind) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  }

  function report(res, done) {
    if (res && res.applied === false) {
      toast(done + ' It was saved, but could not be put into effect: ' + (res.apply_error || 'unknown error'), 'bad', 12000);
    } else {
      toast(done, 'ok');
    }
  }

  function matches(feed) {
    if (!state.search) return true;
    const hay = [feed.name, feed.url, feed.comment, feed.kind, feed.direction]
      .filter((v) => v).join(' ').toLowerCase();
    return hay.includes(state.search);
  }

  function renderStats() {
    const on = state.feeds.filter((f) => f.enabled);
    $('stFeeds').textContent = on.length + ' / ' + state.feeds.length;
    $('stV4').textContent = num(on.reduce((sum, f) => sum + (Number(f.ipv4_count) || 0), 0));
    $('stV6').textContent = num(on.reduce((sum, f) => sum + (Number(f.ipv6_count) || 0), 0));
  }

  function renderNotice() {
    const box = clear($('notice'));
    const failing = state.feeds.filter((f) => f.enabled && f.last_error);

    failing.forEach((f) => {
      box.append(h('div', { class: 'notice warn' },
        icon('i-alert'),
        h('div', null, h('b', { text: f.name + ' could not be updated.' }), ' ', f.last_error)));
    });
  }

  function lastUpdateCell(feed) {
    if (feed.last_error) {
      return h('div', null,
        badge('Failed', 'bad'),
        h('span', { class: 'sub', text: 'Tried ' + ago(feed.last_attempt) }));
    }

    if (!feed.last_updated) {
      return h('span', { class: 'muted', text: feed.kind === 'manual' ? 'No addresses yet' : 'Not downloaded yet' });
    }

    const sub = feed.kind === 'url' ? 'Every ' + feed.refresh_hours + ' h' : 'Manual list';
    return h('div', { title: fmtTime(feed.last_updated) }, h('b', { text: ago(feed.last_updated) }), h('span', { class: 'sub', text: sub }));
  }

  function iconButton(name, label, onClick, extra) {
    return h('button', { class: 'btn sm' + (extra ? ' ' + extra : ''), type: 'button', 'aria-label': label, title: label, onClick }, icon(name));
  }

  function renderFeeds() {
    renderStats();
    renderNotice();

    const body = clear($('feedBody'));
    const shown = state.feeds.filter(matches);

    if (!shown.length) {
      body.append(h('tr', null, h('td', {
        class: 'empty-row',
        colspan: 8,
        text: state.feeds.length ? 'No blocklists match the search.' : 'No blocklists yet. Add one from the presets, or create your own.'
      })));
      return;
    }

    shown.forEach((feed) => {
      const box = h('input', { type: 'checkbox', checked: feed.enabled, 'aria-label': 'Enable ' + feed.name });
      box.addEventListener('change', () => toggleFeed(feed, box));

      const direction = DIRECTIONS[feed.direction] || [feed.direction, ''];

      const primary = feed.kind === 'url'
        ? h('button', { class: 'btn sm', type: 'button', onClick: (ev) => refreshFeed(feed, ev.currentTarget) }, icon('i-refresh'), 'Download')
        : h('button', { class: 'btn sm', type: 'button', onClick: () => openImport(feed) }, icon('i-upload'), 'Import');

      body.append(h('tr', { class: feed.enabled ? '' : 'is-off' },
        h('td', null,
          h('b', { text: feed.name }),
          feed.kind === 'url' && feed.url ? h('span', { class: 'sub mono', text: feed.url }) : null,
          feed.comment ? h('span', { class: 'sub', text: feed.comment }) : null),
        h('td', null, badge(feed.kind === 'url' ? 'Download' : 'Manual', 'plain')),
        h('td', null, badge(direction[0], direction[1])),
        h('td', { class: 'num', text: num(feed.ipv4_count) }),
        h('td', { class: 'num', text: num(feed.ipv6_count) }),
        h('td', null, lastUpdateCell(feed)),
        h('td', null, h('label', { class: 'switch' }, box, h('span', { class: 'slider' }))),
        h('td', { class: 'actions' },
          primary,
          iconButton('i-eye', 'View addresses', () => openEntries(feed)),
          iconButton('i-edit', 'Edit', () => openFeedForm(feed)),
          iconButton('i-trash', 'Delete', () => deleteFeed(feed), 'danger'))));
    });
  }

  async function loadFeeds() {
    const list = await api('/api/threatfeeds');
    state.feeds = (Array.isArray(list) ? list : []).slice()
      .sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }));
    renderFeeds();
  }

  function payloadFrom(feed, changes) {
    return Object.assign({
      name: feed.name,
      kind: feed.kind,
      url: feed.kind === 'url' ? feed.url : null,
      enabled: feed.enabled,
      direction: feed.direction,
      refresh_hours: feed.refresh_hours,
      log_enabled: !!feed.log_enabled,
      comment: feed.comment || null
    }, changes || {});
  }

  async function toggleFeed(feed, box) {
    const wanted = box.checked;
    box.disabled = true;

    try {
      const res = await api('/api/threatfeeds/' + encodeURIComponent(feed.id), {
        method: 'PUT',
        body: payloadFrom(feed, { enabled: wanted })
      });
      report(res, '"' + feed.name + '" ' + (wanted ? 'switched on.' : 'switched off.'));
      await loadFeeds();
    } catch (e) {
      box.checked = !wanted;
      box.disabled = false;
      toast(apiMessage(e), 'bad');
    }
  }

  async function deleteFeed(feed) {
    const ok = await confirmBox('Delete the blocklist "' + feed.name + '" and all of its addresses? They stop being blocked straight away.',
      { ok: 'Delete', danger: true, title: 'Delete blocklist' });
    if (!ok) return;

    try {
      const res = await api('/api/threatfeeds/' + encodeURIComponent(feed.id), { method: 'DELETE' });
      report(res, 'Blocklist deleted.');
      await loadFeeds();
    } catch (e) {
      toast(apiMessage(e), 'bad');
    }
  }

  async function refreshFeed(feed, button) {
    try {
      const res = await busy(button, () => api('/api/threatfeeds/' + encodeURIComponent(feed.id) + '/refresh', { method: 'POST' }));
      report(res, 'Downloaded ' + num(res.ipv4_imported) + ' IPv4 and ' + num(res.ipv6_imported) + ' IPv6 networks for "' + feed.name + '".');
    } catch (e) {
      toast(apiMessage(e), 'bad', 12000);
    }

    await loadFeeds().catch(() => {});
  }

  async function downloadAfterAdd(id, name) {
    try {
      const res = await api('/api/threatfeeds/' + encodeURIComponent(id) + '/refresh', { method: 'POST' });
      report(res, 'Downloaded ' + num(res.ipv4_imported) + ' IPv4 and ' + num(res.ipv6_imported) + ' IPv6 networks for "' + name + '".');
    } catch (e) {
      toast('"' + name + '" was added, but the first download failed: ' + apiMessage(e), 'bad', 12000);
    }

    await loadFeeds().catch(() => {});
  }

  function openFeedForm(existing) {
    const editing = !!existing;
    const feed = existing || {
      name: '', kind: 'url', url: '', enabled: true, direction: 'both', refresh_hours: 6, log_enabled: false, comment: null
    };

    const c = {};

    function input(name, props) {
      c[name] = h('input', Object.assign({ class: 'in', name, autocomplete: 'off', spellcheck: 'false' }, props));
      return c[name];
    }

    function select(name, options, value, props) {
      c[name] = h('select', Object.assign({ class: 'in', name }, props),
        options.map(([v, t]) => h('option', { value: v, text: t, selected: v === value })));
      return h('span', { class: 'select-wrap' }, c[name]);
    }

    function fld(label, control, help, extra) {
      return h('label', { class: 'fld' + (extra ? ' ' + extra : '') },
        h('span', { text: label }), control, help ? h('small', { text: help }) : null);
    }

    function toggle(name, title, text, checked) {
      c[name] = h('input', { type: 'checkbox', name, checked });
      return h('div', { class: 'fld span-all' },
        h('div', { class: 'switch-row' },
          h('label', { class: 'switch' }, c[name], h('span', { class: 'slider' })),
          h('div', { class: 'switch-text' }, h('b', { text: title }), h('span', { text }))));
    }

    const urlField = fld('Download address', input('url', { type: 'url', class: 'in mono', placeholder: 'https://example.com/blocklist.txt', value: feed.url }),
      'A web address that serves one address or network per line.', 'span-all');
    const hoursField = fld('Download every (hours)', input('refresh_hours', { type: 'number', min: 1, max: 720, step: 1, value: feed.refresh_hours }),
      'From 1 to 720 hours.');

    const grid = h('div', { class: 'form-grid cols-2' },
      fld('Name', input('name', { type: 'text', maxlength: 60, placeholder: 'Spamhaus DROP', value: feed.name }), null, 'span-all'),
      fld('Type', select('kind', [['url', 'Download from a web address'], ['manual', 'Manual list']], feed.kind, editing ? { disabled: true } : null),
        editing ? 'The type cannot be changed after the blocklist is created.' : null),
      fld('Block traffic', select('direction', [['both', 'From and to these addresses'], ['inbound', 'Inbound only (from them)'], ['outbound', 'Outbound only (to them)']], feed.direction)),
      urlField,
      hoursField,
      fld('Comment', input('comment', { type: 'text', maxlength: 200, placeholder: 'Optional note', value: feed.comment }), null, 'span-all'),
      toggle('enabled', 'Blocklist switched on', 'A switched-off list is kept but not enforced.', feed.enabled),
      toggle('log_enabled', 'Log blocked traffic', 'Writes a log entry whenever traffic matches this list. This can be noisy.', feed.log_enabled)
    );

    function sync() {
      const isUrl = c.kind.value === 'url';
      urlField.hidden = !isUrl;
      hoursField.hidden = !isUrl;
      c.url.disabled = !isUrl;
      c.refresh_hours.disabled = !isUrl;
    }

    c.kind.addEventListener('change', sync);
    sync();

    const form = h('form', { novalidate: true, onSubmit: (ev) => { ev.preventDefault(); save(); } }, grid);
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const saveBtn = h('button', { class: 'btn primary', type: 'button' }, editing ? 'Save changes' : 'Add blocklist');

    const modal = openModal({
      title: editing ? 'Edit blocklist' : 'Add blocklist',
      body: form,
      footer: [cancel, saveBtn],
      wide: true
    });

    cancel.addEventListener('click', modal.close);
    saveBtn.addEventListener('click', save);

    function fail(message, field) {
      modal.setError(message);
      if (c[field]) {
        c[field].classList.add('invalid');
        c[field].focus();
      }
      return null;
    }

    function collect() {
      const name = c.name.value.trim();
      if (!name) return fail('Enter a name for the blocklist.', 'name');

      const kind = c.kind.value;
      let url = null;
      let hours = feed.refresh_hours || 6;

      if (kind === 'url') {
        url = c.url.value.trim();
        if (!url) return fail('Enter the web address to download the list from.', 'url');
        if (!/^https?:\/\//i.test(url)) return fail('The address must start with http:// or https://.', 'url');

        hours = Number(c.refresh_hours.value);
        if (!Number.isInteger(hours) || hours < 1 || hours > 720) {
          return fail('Download interval must be a whole number from 1 to 720 hours.', 'refresh_hours');
        }
      }

      const comment = c.comment.value.trim();

      return {
        name,
        kind,
        url,
        enabled: c.enabled.checked,
        direction: c.direction.value,
        refresh_hours: hours,
        log_enabled: c.log_enabled.checked,
        comment: comment === '' ? null : comment
      };
    }

    async function save() {
      modal.setError('');
      Object.values(c).forEach((el) => el.classList.remove('invalid'));

      const payload = collect();
      if (!payload) return;

      let res;
      try {
        res = await busy(saveBtn, () => api(editing ? '/api/threatfeeds/' + encodeURIComponent(existing.id) : '/api/threatfeeds', {
          method: editing ? 'PUT' : 'POST',
          body: payload
        }));
      } catch (e) {
        modal.setError(apiMessage(e));
        return;
      }

      modal.close();

      if (editing) {
        report(res, 'Blocklist saved.');
        await loadFeeds().catch((e) => toast(apiMessage(e), 'bad'));
        return;
      }

      await loadFeeds().catch(() => {});

      if (payload.kind === 'url' && payload.enabled && res && res.id) {
        toast('Blocklist added. Downloading it now…', 'info');
        await downloadAfterAdd(res.id, payload.name);
      } else {
        toast(payload.kind === 'manual' ? 'Blocklist added. Use Import to add addresses to it.' : 'Blocklist added.', 'ok');
      }
    }
  }

  async function openPresets() {
    let presets;
    try {
      presets = await busy($('btnPresets'), () => api('/api/threatfeeds/presets'));
    } catch (e) {
      toast(apiMessage(e), 'bad');
      return;
    }

    const body = h('div', { class: 'tbl-wrap' });
    const close = h('button', { class: 'btn', type: 'button' }, 'Close');
    const modal = openModal({ title: 'Add a ready-made blocklist', body, footer: [close], wide: true });
    close.addEventListener('click', modal.close);

    function draw() {
      const tbody = h('tbody');

      (Array.isArray(presets) ? presets : []).forEach((p) => {
        const have = state.feeds.some((f) => f.url === p.url);
        const btn = h('button', { class: 'btn sm primary', type: 'button', disabled: have }, have ? 'Added' : [icon('i-plus'), 'Add']);

        btn.addEventListener('click', async () => {
          try {
            const res = await busy(btn, () => api('/api/threatfeeds', {
              method: 'POST',
              body: {
                name: p.name, kind: 'url', url: p.url, enabled: true, direction: 'both',
                refresh_hours: p.refresh_hours, log_enabled: false, comment: null
              }
            }));
            await loadFeeds().catch(() => {});
            draw();
            toast('"' + p.name + '" added. Downloading it now…', 'info');
            await downloadAfterAdd(res && res.id, p.name);
            draw();
          } catch (e) {
            modal.setError(apiMessage(e));
          }
        });

        tbody.append(h('tr', null,
          h('td', null, h('b', { text: p.name }), h('span', { class: 'sub', text: p.description })),
          h('td', { class: 'nowrap', text: 'Every ' + p.refresh_hours + ' h' }),
          h('td', { class: 'actions' }, btn)));
      });

      clear(body).append(h('table', { class: 'dtable' },
        h('thead', null, h('tr', null, h('th', { text: 'Blocklist' }), h('th', { text: 'Updated' }), h('th'))),
        tbody));
    }

    draw();
  }

  function openImport(feed) {
    const text = h('textarea', {
      class: 'in mono', rows: 10, spellcheck: 'false', name: 'data',
      placeholder: '203.0.113.7\n198.51.100.0/24 ; note\n2001:db8::/32'
    });

    const mode = h('select', { class: 'in', name: 'mode' },
      [['append', 'Add to the existing addresses'], ['replace', 'Replace all existing addresses']]
        .map(([v, t]) => h('option', { value: v, text: t })));

    const file = h('input', { class: 'in', type: 'file', accept: '.txt,.csv,.list,.ioc,text/plain' });
    file.addEventListener('change', () => {
      const chosen = file.files && file.files[0];
      if (!chosen) return;
      const reader = new FileReader();
      reader.onload = () => { text.value = String(reader.result || ''); };
      reader.onerror = () => modal.setError('The file could not be read.');
      reader.readAsText(chosen);
    });

    const body = h('div', { class: 'stack' },
      h('p', { class: 'card-sub', text: 'Paste one address or network per line, or load a text file. Lines starting with # are ignored, and anything after a semicolon is treated as a note. Private and reserved ranges are skipped.' }),
      h('label', { class: 'fld' }, h('span', { text: 'Addresses' }), text),
      h('label', { class: 'fld' }, h('span', { text: 'Or load a file' }), file),
      h('label', { class: 'fld' }, h('span', { text: 'Import mode' }), h('span', { class: 'select-wrap' }, mode)));

    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const go = h('button', { class: 'btn primary', type: 'button' }, icon('i-upload'), 'Import');

    const modal = openModal({ title: 'Import addresses into "' + feed.name + '"', body, footer: [cancel, go], wide: true });

    cancel.addEventListener('click', modal.close);
    go.addEventListener('click', async () => {
      modal.setError('');

      if (!text.value.trim()) {
        modal.setError('Paste some addresses or load a file first.');
        text.classList.add('invalid');
        text.focus();
        return;
      }
      text.classList.remove('invalid');

      if (mode.value === 'replace') {
        const ok = await confirmBox('Replace every address in "' + feed.name + '" with this list?', { ok: 'Replace', danger: true, title: 'Replace addresses' });
        if (!ok) return;
      }

      try {
        const res = await busy(go, () => api('/api/threatfeeds/' + encodeURIComponent(feed.id) + '/entries', {
          method: 'PUT',
          body: { data: text.value, mode: mode.value }
        }));
        modal.close();
        report(res, 'Imported ' + num(res.ipv4_imported) + ' IPv4 and ' + num(res.ipv6_imported) + ' IPv6 networks, skipped ' + num(res.skipped) + '. The list now holds ' + num(res.ipv4_total) + ' IPv4 and ' + num(res.ipv6_total) + ' IPv6 networks.');
        await loadFeeds();
      } catch (e) {
        modal.setError(apiMessage(e));
      }
    });
  }

  function openEntries(feed) {
    const view = { offset: 0, total: 0, search: '', timer: null };

    const search = h('input', { class: 'in', type: 'search', placeholder: 'Search addresses', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Search addresses' });
    const list = h('tbody');
    const info = h('span', { text: '' });
    const prev = h('button', { class: 'btn sm', type: 'button' }, 'Previous');
    const next = h('button', { class: 'btn sm', type: 'button' }, 'Next');

    const body = h('div', null,
      h('div', { class: 'toolbar' }, search),
      h('div', { class: 'tbl-wrap' },
        h('table', { class: 'dtable' }, h('thead', null, h('tr', null, h('th', { text: 'Address or network' }))), list)),
      h('div', { class: 'pager' }, info, h('div', { class: 'btn-row' }, prev, next)));

    const close = h('button', { class: 'btn', type: 'button' }, 'Close');
    const modal = openModal({
      title: 'Addresses in "' + feed.name + '"',
      body,
      footer: [close],
      onClose: () => clearTimeout(view.timer)
    });
    close.addEventListener('click', modal.close);

    async function load() {
      try {
        const query = '?limit=' + PAGE_SIZE + '&offset=' + view.offset + (view.search ? '&search=' + encodeURIComponent(view.search) : '');
        const res = await api('/api/threatfeeds/' + encodeURIComponent(feed.id) + '/entries' + query);
        const entries = Array.isArray(res.entries) ? res.entries : [];
        view.total = Number(res.total) || 0;

        clear(list);
        if (!entries.length) {
          list.append(h('tr', null, h('td', { class: 'empty-row', text: view.search ? 'No addresses match the search.' : 'This blocklist has no addresses yet.' })));
        } else {
          entries.forEach((entry) => list.append(h('tr', null, h('td', { class: 'mono', text: entry }))));
        }

        const from = entries.length ? view.offset + 1 : 0;
        info.textContent = 'Showing ' + num(from) + '–' + num(view.offset + entries.length) + ' of ' + num(view.total);
        prev.disabled = view.offset <= 0;
        next.disabled = view.offset + entries.length >= view.total;
        modal.setError('');
      } catch (e) {
        modal.setError(apiMessage(e));
      }
    }

    prev.addEventListener('click', () => { view.offset = Math.max(0, view.offset - PAGE_SIZE); load(); });
    next.addEventListener('click', () => { view.offset += PAGE_SIZE; load(); });
    search.addEventListener('input', () => {
      clearTimeout(view.timer);
      view.timer = setTimeout(() => { view.search = search.value.trim(); view.offset = 0; load(); }, 300);
    });

    load();
  }

  async function applyNow() {
    try {
      await busy($('btnApplyNow'), () => api('/api/threatfeeds/apply', { method: 'POST' }));
      toast('Blocklists loaded into the firewall.', 'ok');
    } catch (e) {
      toast('Blocklists could not be put into effect: ' + apiMessage(e), 'bad', 12000);
    }
  }

  async function reload() {
    try {
      await loadFeeds();
      live(true, 'Live');
    } catch (e) {
      live(false, 'Connection lost');
      toast(apiMessage(e), 'bad');
    }
  }

  $('search').addEventListener('input', (ev) => { state.search = ev.target.value.trim().toLowerCase(); renderFeeds(); });
  $('btnAdd').addEventListener('click', () => openFeedForm(null));
  $('btnPresets').addEventListener('click', openPresets);
  $('btnApplyNow').addEventListener('click', applyNow);
  btnRefresh.addEventListener('click', () => busy(btnRefresh, reload));

  reload();
  every(() => loadFeeds().then(() => live(true, 'Live')).catch(() => live(false, 'Connection lost')), 15000);
})();
