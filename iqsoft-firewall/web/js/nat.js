(function () {
  'use strict';

  const { h, icon, clear, toast, openModal, confirmBox, busy, every, tabs, live, errorText } = Shell;

  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'nat',
    title: 'NAT / Port Forwarding',
    subtitle: 'Publish LAN services and map public addresses to internal hosts',
    content: $('page')
  });
  if (!frame) return;

  const state = {
    forwards: [],
    onetoone: [],
    pfSearch: '',
    nnSearch: '',
    wasPending: false,
    quiet: false
  };

  const btnApply = h('button', { class: 'btn primary', type: 'button', title: 'Put the saved rules into effect' },
    icon('i-play'), 'Apply');
  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' },
    icon('i-refresh'));
  frame.tools.append(btnApply, btnRefresh);

  function apiMessage(e) {
    if (e && e.data && typeof e.data === 'object') {
      if (e.data.message) return e.data.message;
      if (e.data.error) return e.data.error;
    }
    return errorText(e);
  }

  function badge(text, kind) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  }

  function byName(a, b) {
    return String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }) || ((a.id || 0) - (b.id || 0));
  }

  function validIPv4(value) {
    const parts = String(value).split('.');
    return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
  }

  function formKit() {
    const c = {};

    return {
      c,
      input(name, props) {
        c[name] = h('input', Object.assign({ class: 'in', name, autocomplete: 'off', spellcheck: 'false' }, props));
        return c[name];
      },
      select(name, options, value) {
        c[name] = h('select', { class: 'in', name },
          options.map(([v, t]) => h('option', { value: v, text: t, selected: v === value })));
        return h('span', { class: 'select-wrap' }, c[name]);
      },
      fld(label, control, help, extra) {
        return h('label', { class: 'fld' + (extra ? ' ' + extra : '') },
          h('span', { text: label }), control, help ? h('small', { text: help }) : null);
      },
      toggle(name, title, text, checked) {
        c[name] = h('input', { type: 'checkbox', name, checked });
        return h('div', { class: 'fld span-all' },
          h('div', { class: 'switch-row' },
            h('label', { class: 'switch' }, c[name], h('span', { class: 'slider' })),
            h('div', { class: 'switch-text' }, h('b', { text: title }), h('span', { text }))));
      },
      text(name) {
        const v = c[name].value.trim();
        return v === '' ? null : v;
      },
      clearMarks() {
        Object.values(c).forEach((el) => el.classList.remove('invalid'));
      },
      mark(field) {
        if (!c[field]) return;
        c[field].classList.add('invalid');
        c[field].focus();
      }
    };
  }

  function portNumber(raw, label) {
    const text = String(raw).trim();
    if (text === '') return { blank: true };
    const n = Number(text);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return { error: label + ' must be a number from 1 to 65535.' };
    return { value: n };
  }

  function showPorts(start, end) {
    return start === end ? String(start) : start + '–' + end;
  }

  function internalEnd(rule) {
    return rule.internal_port_start + (rule.external_port_end - rule.external_port_start);
  }

  function forwardMatches(rule) {
    if (!state.pfSearch) return true;
    const hay = [rule.name, rule.comment, rule.protocol, rule.internal_ip, rule.external_port_start, rule.external_port_end, rule.internal_port_start]
      .filter((v) => v !== null && v !== undefined).join(' ').toLowerCase();
    return hay.includes(state.pfSearch);
  }

  function oneToOneMatches(rule) {
    if (!state.nnSearch) return true;
    const hay = [rule.name, rule.comment, rule.external_ip, rule.internal_ip]
      .filter((v) => v !== null && v !== undefined).join(' ').toLowerCase();
    return hay.includes(state.nnSearch);
  }

  function enableSwitch(rule, onChange) {
    const box = h('input', { type: 'checkbox', checked: rule.enabled, 'aria-label': 'Enable ' + rule.name });
    box.addEventListener('change', () => onChange(box));
    return h('label', { class: 'switch' }, box, h('span', { class: 'slider' }));
  }

  function renderForwards() {
    $('countForwards').textContent = String(state.forwards.length);

    const body = clear($('pfBody'));
    const shown = state.forwards.filter(forwardMatches);

    if (!shown.length) {
      body.append(h('tr', null, h('td', {
        class: 'empty-row',
        colspan: 6,
        text: state.forwards.length ? 'No port forwards match the search.' : 'No port forwards yet. Press Add port forward to create one.'
      })));
      return;
    }

    shown.forEach((rule) => {
      const target = rule.internal_ip + ':' + showPorts(rule.internal_port_start, internalEnd(rule));

      body.append(h('tr', { class: rule.enabled ? '' : 'is-off' },
        h('td', null, h('b', { text: rule.name }), rule.comment ? h('span', { class: 'sub', text: rule.comment }) : null),
        h('td', null, badge(rule.protocol === 'both' ? 'TCP + UDP' : rule.protocol.toUpperCase(), 'info')),
        h('td', { class: 'mono nowrap', text: showPorts(rule.external_port_start, rule.external_port_end) }),
        h('td', { class: 'mono nowrap', text: target }),
        h('td', null, enableSwitch(rule, (box) => toggleRule('/api/port-forwards/', rule, box, loadForwards))),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => openForwardForm(rule) }, icon('i-edit'), 'Edit'),
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteRule('/api/port-forwards/', rule, 'port forward', loadForwards) }, icon('i-trash'), 'Delete'))));
    });
  }

  function renderOneToOne() {
    $('countOneToOne').textContent = String(state.onetoone.length);

    const body = clear($('nnBody'));
    const shown = state.onetoone.filter(oneToOneMatches);

    if (!shown.length) {
      body.append(h('tr', null, h('td', {
        class: 'empty-row',
        colspan: 5,
        text: state.onetoone.length ? 'No 1:1 NAT rules match the search.' : 'No 1:1 NAT rules yet. Press Add 1:1 NAT to create one.'
      })));
      return;
    }

    shown.forEach((rule) => {
      body.append(h('tr', { class: rule.enabled ? '' : 'is-off' },
        h('td', null, h('b', { text: rule.name }), rule.comment ? h('span', { class: 'sub', text: rule.comment }) : null),
        h('td', { class: 'mono nowrap', text: rule.external_ip }),
        h('td', { class: 'mono nowrap', text: rule.internal_ip }),
        h('td', null, enableSwitch(rule, (box) => toggleRule('/api/one-to-one-nat/', rule, box, loadOneToOne))),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => openOneToOneForm(rule) }, icon('i-edit'), 'Edit'),
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteRule('/api/one-to-one-nat/', rule, '1:1 NAT rule', loadOneToOne) }, icon('i-trash'), 'Delete'))));
    });
  }

  async function loadForwards() {
    const list = await api('/api/port-forwards');
    state.forwards = (Array.isArray(list) ? list : []).slice().sort(byName);
    renderForwards();
  }

  async function loadOneToOne() {
    const list = await api('/api/one-to-one-nat');
    state.onetoone = (Array.isArray(list) ? list : []).slice().sort(byName);
    renderOneToOne();
  }

  async function toggleRule(base, rule, box, reload) {
    const wanted = box.checked;
    box.disabled = true;

    try {
      await api(base + encodeURIComponent(rule.id), { method: 'PUT', body: Object.assign({}, rule, { enabled: wanted }) });
      toast('"' + rule.name + '" ' + (wanted ? 'enabled' : 'disabled') + '. Press Apply to put it into effect.', 'ok');
      await reload();
    } catch (e) {
      box.checked = !wanted;
      box.disabled = false;
      toast(apiMessage(e), 'bad');
    }
  }

  async function deleteRule(base, rule, label, reload) {
    const ok = await confirmBox('Delete the ' + label + ' "' + rule.name + '"? It stays active on the firewall until you press Apply.',
      { ok: 'Delete', danger: true, title: 'Delete ' + label });
    if (!ok) return;

    try {
      await api(base + encodeURIComponent(rule.id), { method: 'DELETE' });
      toast('Deleted.', 'ok');
      await reload();
    } catch (e) {
      toast(apiMessage(e), 'bad');
    }
  }

  function openFormModal(opts) {
    const form = h('form', { novalidate: true, onSubmit: (ev) => { ev.preventDefault(); save(); } }, opts.grid);
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const saveBtn = h('button', { class: 'btn primary', type: 'button' }, opts.editing ? 'Save changes' : 'Add');

    const modal = openModal({
      title: opts.title,
      body: form,
      footer: [cancel, saveBtn],
      wide: opts.wide
    });

    cancel.addEventListener('click', modal.close);
    saveBtn.addEventListener('click', save);

    async function save() {
      modal.setError('');
      opts.kit.clearMarks();

      const result = opts.collect();
      if (result.error) {
        modal.setError(result.error);
        opts.kit.mark(result.field);
        return;
      }

      try {
        await busy(saveBtn, () => api(opts.url, { method: opts.editing ? 'PUT' : 'POST', body: result.payload }));
      } catch (e) {
        modal.setError(apiMessage(e));
        return;
      }

      modal.close();
      toast((opts.editing ? 'Saved' : 'Added') + '. Press Apply to put it into effect.', 'ok');
      await opts.reload().catch((e) => toast(apiMessage(e), 'bad'));
    }
  }

  function openForwardForm(existing) {
    const editing = !!existing;
    const rule = existing || {
      name: '', enabled: true, protocol: 'tcp', external_port_start: '', external_port_end: '',
      internal_ip: '', internal_port_start: '', comment: null
    };

    const kit = formKit();
    const c = kit.c;

    const range = rule.external_port_start !== '' && rule.external_port_start !== rule.external_port_end;

    const grid = h('div', { class: 'form-grid cols-2' },
      kit.fld('Name', kit.input('name', { type: 'text', maxlength: 80, placeholder: 'Web server', value: rule.name }), null, 'span-all'),
      kit.fld('Protocol', kit.select('protocol', [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP and UDP']], rule.protocol)),
      kit.fld('Internal host (LAN IP)', kit.input('internal_ip', { type: 'text', class: 'in mono', placeholder: '192.168.1.10', value: rule.internal_ip })),
      kit.fld('External port', kit.input('external_port_start', { type: 'number', min: 1, max: 65535, step: 1, placeholder: '8080', value: rule.external_port_start }), 'The port people connect to on the WAN side.'),
      kit.fld('External end port (optional)', kit.input('external_port_end', { type: 'number', min: 1, max: 65535, step: 1, placeholder: 'Same as above', value: range ? rule.external_port_end : '' }), 'Fill this in only to forward a range of ports.'),
      kit.fld('Internal port', kit.input('internal_port_start', { type: 'number', min: 1, max: 65535, step: 1, placeholder: 'Same as external', value: rule.internal_port_start }), 'The port on the LAN host. For a range it must match the external start port.'),
      kit.fld('Comment', kit.input('comment', { type: 'text', maxlength: 200, placeholder: 'Optional note', value: rule.comment }), null),
      kit.toggle('enabled', 'Port forward enabled', 'A disabled rule is kept but never applied.', rule.enabled)
    );

    function collect() {
      const name = c.name.value.trim();
      if (!name) return { error: 'Enter a name for the port forward.', field: 'name' };

      const ip = c.internal_ip.value.trim();
      if (!ip) return { error: 'Enter the LAN IP address of the host that should receive the traffic.', field: 'internal_ip' };
      if (!validIPv4(ip)) return { error: 'The internal host must be a valid IPv4 address, for example 192.168.1.10.', field: 'internal_ip' };

      const start = portNumber(c.external_port_start.value, 'External port');
      if (start.blank) return { error: 'Enter the external port.', field: 'external_port_start' };
      if (start.error) return { error: start.error, field: 'external_port_start' };

      const end = portNumber(c.external_port_end.value, 'External end port');
      if (end.error) return { error: end.error, field: 'external_port_end' };
      const endValue = end.blank ? start.value : end.value;
      if (endValue < start.value) return { error: 'The external end port cannot be lower than the start port.', field: 'external_port_end' };

      const internal = portNumber(c.internal_port_start.value, 'Internal port');
      if (internal.error) return { error: internal.error, field: 'internal_port_start' };
      const internalValue = internal.blank ? start.value : internal.value;

      if (endValue !== start.value && internalValue !== start.value) {
        return { error: 'For a port range the internal port must equal the external start port. Use a single port to change the port number.', field: 'internal_port_start' };
      }

      if (internalValue + (endValue - start.value) > 65535) {
        return { error: 'The internal port range goes past 65535. Lower the internal port.', field: 'internal_port_start' };
      }

      const payload = {
        name,
        enabled: c.enabled.checked,
        protocol: c.protocol.value,
        external_port_start: start.value,
        external_port_end: endValue,
        internal_ip: ip,
        internal_port_start: internalValue,
        comment: kit.text('comment')
      };

      if (editing) payload.id = existing.id;
      return { payload };
    }

    openFormModal({
      title: editing ? 'Edit port forward' : 'Add port forward',
      grid,
      kit,
      editing,
      wide: true,
      collect,
      url: editing ? '/api/port-forwards/' + encodeURIComponent(existing.id) : '/api/port-forwards',
      reload: loadForwards
    });
  }

  function openOneToOneForm(existing) {
    const editing = !!existing;
    const rule = existing || { name: '', enabled: true, external_ip: '', internal_ip: '', comment: null };

    const kit = formKit();
    const c = kit.c;

    const grid = h('div', { class: 'form-grid cols-2' },
      kit.fld('Name', kit.input('name', { type: 'text', maxlength: 80, placeholder: 'Mail server', value: rule.name }), null, 'span-all'),
      kit.fld('External IP (WAN side)', kit.input('external_ip', { type: 'text', class: 'in mono', placeholder: '203.0.113.20', value: rule.external_ip }), 'Must already be an address on the WAN interface.'),
      kit.fld('Internal IP (LAN host)', kit.input('internal_ip', { type: 'text', class: 'in mono', placeholder: '192.168.1.20', value: rule.internal_ip }), 'The host behind the firewall.'),
      kit.fld('Comment', kit.input('comment', { type: 'text', maxlength: 200, placeholder: 'Optional note', value: rule.comment }), null, 'span-all'),
      kit.toggle('enabled', 'Rule enabled', 'A disabled rule is kept but never applied.', rule.enabled)
    );

    function collect() {
      const name = c.name.value.trim();
      if (!name) return { error: 'Enter a name for the rule.', field: 'name' };

      const external = c.external_ip.value.trim();
      if (!validIPv4(external)) return { error: 'The external IP must be a valid IPv4 address, for example 203.0.113.20.', field: 'external_ip' };

      const internal = c.internal_ip.value.trim();
      if (!validIPv4(internal)) return { error: 'The internal IP must be a valid IPv4 address, for example 192.168.1.20.', field: 'internal_ip' };

      if (external === internal) return { error: 'The external IP and internal IP must be different.', field: 'internal_ip' };

      const payload = {
        name,
        enabled: c.enabled.checked,
        external_ip: external,
        internal_ip: internal,
        comment: kit.text('comment')
      };

      if (editing) payload.id = existing.id;
      return { payload };
    }

    openFormModal({
      title: editing ? 'Edit 1:1 NAT rule' : 'Add 1:1 NAT rule',
      grid,
      kit,
      editing,
      wide: false,
      collect,
      url: editing ? '/api/one-to-one-nat/' + encodeURIComponent(existing.id) : '/api/one-to-one-nat',
      reload: loadOneToOne
    });
  }

  function openApply() {
    const timer = h('select', { class: 'in' },
      [[60, '60 seconds (recommended)'], [30, '30 seconds'], [120, '2 minutes'], [300, '5 minutes'], [0, 'No timer – apply permanently']]
        .map(([v, t]) => h('option', { value: v, text: t })));

    const body = h('div', null,
      h('p', { class: 'card-sub', text: 'This puts all saved firewall settings into effect, including the NAT rules on this page. With a safety timer, the firewall returns to the previous rules by itself unless you confirm that you can still reach it.' }),
      h('label', { class: 'fld' },
        h('span', { text: 'Safety timer' }),
        h('span', { class: 'select-wrap' }, timer),
        h('small', { text: 'Use a timer whenever you change rules over the network you are connected through.' })));

    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const go = h('button', { class: 'btn primary', type: 'button' }, icon('i-play'), 'Apply now');

    const modal = openModal({ title: 'Apply firewall rules', body, footer: [cancel, go] });

    cancel.addEventListener('click', modal.close);
    go.addEventListener('click', async () => {
      modal.setError('');
      const seconds = Number(timer.value);

      try {
        const res = await busy(go, () => api('/api/commit' + (seconds > 0 ? '?confirm_within=' + seconds : ''), { method: 'POST' }));
        modal.close();
        toast((res && res.message) || 'Firewall rules applied.', 'ok');
        await refreshPending();
      } catch (e) {
        modal.setError(apiMessage(e));
      }
    });
  }

  async function doRollback() {
    const ok = await confirmBox('Go back to the previous firewall ruleset? Rules saved since then stay in the lists.',
      { ok: 'Roll back', danger: true, title: 'Roll back' });
    if (!ok) return;

    state.quiet = true;

    try {
      const res = await api('/api/rollback', { method: 'POST' });
      toast((res && res.message) || 'Rolled back to the previous rules.', 'ok');
    } catch (e) {
      toast(apiMessage(e), 'bad');
    } finally {
      state.quiet = false;
    }

    await refreshPending();
  }

  async function confirmPending(button) {
    state.quiet = true;

    try {
      const res = await busy(button, () => api('/api/commit/confirm', { method: 'POST' }));
      toast((res && res.message) || 'Change confirmed.', 'ok');
    } catch (e) {
      toast(apiMessage(e), 'bad');
    } finally {
      state.quiet = false;
    }

    await refreshPending();
  }

  const pendingUi = { box: null, counter: null };

  function renderPending(status) {
    const notice = $('notice');

    if (!status || !status.pending) {
      if (pendingUi.box) {
        clear(notice);
        pendingUi.box = null;
        pendingUi.counter = null;
      }

      if (state.wasPending && !state.quiet) {
        toast('The confirmation time ran out or the change was rolled back. The firewall is using the previous rules.', 'info', 9000);
      }

      state.wasPending = false;
      return;
    }

    state.wasPending = true;

    if (!pendingUi.box) {
      pendingUi.counter = h('b', { text: '' });

      const confirmBtn = h('button', { class: 'btn primary sm', type: 'button' }, icon('i-check'), 'Keep these rules');
      const undoBtn = h('button', { class: 'btn danger sm', type: 'button' }, icon('i-undo'), 'Roll back now');
      confirmBtn.addEventListener('click', () => confirmPending(confirmBtn));
      undoBtn.addEventListener('click', doRollback);

      pendingUi.box = h('div', { class: 'notice warn' },
        icon('i-alert'),
        h('div', null,
          h('b', { text: 'New rules are waiting for your confirmation.' }), ' ',
          'If you can still use the firewall, keep them. Otherwise they are rolled back automatically in ', pendingUi.counter, '.',
          h('div', { class: 'btn-row' }, confirmBtn, undoBtn)));

      clear(notice).append(pendingUi.box);
    }

    pendingUi.counter.textContent = Number(status.seconds_left) + ' s';
  }

  async function refreshPending() {
    try {
      const status = await api('/api/commit/status');
      renderPending(status);
      live(true, 'Live');
    } catch (_) {
      live(false, 'Connection lost');
    }
  }

  async function reloadAll() {
    await Promise.allSettled([
      loadForwards().catch((e) => toast(apiMessage(e), 'bad')),
      loadOneToOne().catch((e) => toast(apiMessage(e), 'bad')),
      refreshPending()
    ]);
  }

  tabs($('page'), 'nat');

  $('pfSearch').addEventListener('input', (ev) => { state.pfSearch = ev.target.value.trim().toLowerCase(); renderForwards(); });
  $('nnSearch').addEventListener('input', (ev) => { state.nnSearch = ev.target.value.trim().toLowerCase(); renderOneToOne(); });
  $('btnAddForward').addEventListener('click', () => openForwardForm(null));
  $('btnAddOneToOne').addEventListener('click', () => openOneToOneForm(null));

  btnApply.addEventListener('click', openApply);
  btnRefresh.addEventListener('click', () => busy(btnRefresh, reloadAll));

  reloadAll();
  every(refreshPending, 3000);
})();
