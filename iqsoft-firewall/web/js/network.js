(function () {
  'use strict';

  const { h, icon, clear, toast, openModal, confirmBox, busy, every, tabs, live, errorText, fmtTime } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'network',
    title: 'Network',
    subtitle: 'Interfaces, DHCP, DNS, routing and address objects',
    content: $('page')
  });
  if (!frame) return;

  const state = {
    ifaces: [], net: null, live: [], ifcfg: [],
    dhcp: null, reservations: [], leases: [],
    dns: null, records: [],
    routes: [], objects: [], groups: []
  };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' }, icon('i-refresh'));
  frame.tools.append(btnRefresh);

  /* ---------------- helpers ---------------- */

  function apiMessage(e) {
    if (e && e.data && typeof e.data === 'object') {
      if (e.data.message) return e.data.message;
      if (e.data.error) return e.data.error;
    }
    return errorText(e);
  }

  const badge = (text, kind) => h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  const list = (v) => (Array.isArray(v) ? v : []);
  const byKey = (k) => (a, b) => String(a[k]).localeCompare(String(b[k]), undefined, { sensitivity: 'base' });

  function fmtBytes(n) {
    let v = Number(n) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + ' ' + u[i];
  }

  function emptyRow(body, cols, text) {
    body.append(h('tr', null, h('td', { class: 'empty-row', colspan: cols, text })));
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
      clearMarks() { Object.values(c).forEach((el) => el.classList && el.classList.remove('invalid')); },
      mark(field) {
        if (!c[field]) return;
        c[field].classList.add('invalid');
        c[field].focus();
      }
    };
  }

  /* checkbox list: returns { node, values() } */
  function checkList(items, selected) {
    const sel = new Set(selected || []);
    const boxes = items.map(([value, label]) => {
      const box = h('input', { type: 'checkbox', checked: sel.has(value) });
      return { value, box, node: h('label', { class: 'nowrap' }, box, ' ', label) };
    });
    return {
      node: h('div', { class: 'btn-row' }, boxes.length ? boxes.map((b) => b.node) : h('span', { class: 'card-sub', text: 'Nothing available yet.' })),
      values: () => boxes.filter((b) => b.box.checked).map((b) => b.value)
    };
  }

  function enableSwitch(item, onChange) {
    const box = h('input', { type: 'checkbox', checked: item.enabled, 'aria-label': 'Enable ' + item.name });
    box.addEventListener('change', () => onChange(box));
    return h('label', { class: 'switch' }, box, h('span', { class: 'slider' }));
  }

  /* Add / edit dialog. o: { title, grid, kit, collect, url, editing, done, reload, wide } */
  function openForm(o) {
    const form = h('form', { novalidate: true, onSubmit: (ev) => { ev.preventDefault(); save(); } }, o.grid);
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const saveBtn = h('button', { class: 'btn primary', type: 'button' }, o.editing ? 'Save changes' : 'Add');
    const modal = openModal({ title: o.title, body: form, footer: [cancel, saveBtn], wide: o.wide });

    cancel.addEventListener('click', modal.close);
    saveBtn.addEventListener('click', save);

    async function save() {
      modal.setError('');
      o.kit.clearMarks();
      const r = o.collect();
      if (r.error) { modal.setError(r.error); o.kit.mark(r.field); return; }
      try {
        await busy(saveBtn, () => api(o.url, { method: o.editing ? 'PUT' : 'POST', body: r.payload }));
      } catch (e) { modal.setError(apiMessage(e)); return; }
      modal.close();
      toast(o.done, 'ok');
      await o.reload().catch((e) => toast(apiMessage(e), 'bad'));
    }
  }

  async function removeItem(base, item, label, reload, note) {
    const ok = await confirmBox('Delete the ' + label + ' "' + (item.name || item.hostname || item.mac) + '"? ' + (note || ''),
      { ok: 'Delete', danger: true, title: 'Delete ' + label });
    if (!ok) return;
    try {
      await api(base + '/' + encodeURIComponent(item.id), { method: 'DELETE' });
      toast('Deleted.', 'ok');
      await reload();
    } catch (e) { toast(apiMessage(e), 'bad'); }
  }

  async function toggleItem(base, item, box, reload, note) {
    const wanted = box.checked;
    box.disabled = true;
    try {
      await api(base + '/' + encodeURIComponent(item.id), { method: 'PUT', body: Object.assign({}, item, { enabled: wanted }) });
      toast('"' + item.name + '" ' + (wanted ? 'enabled' : 'disabled') + '. ' + (note || ''), 'ok');
      await reload();
    } catch (e) {
      box.checked = !wanted;
      box.disabled = false;
      toast(apiMessage(e), 'bad');
    }
  }

  const actions = (onEdit, onDelete) => h('td', { class: 'actions' },
    h('button', { class: 'btn sm', type: 'button', onClick: onEdit }, icon('i-edit'), 'Edit'),
    h('button', { class: 'btn sm danger', type: 'button', onClick: onDelete }, icon('i-trash'), 'Delete'));

  /* Preview / Apply / Roll back bar for DHCP, DNS and routes */
  function applyBar(base, what) {
    const prev = h('button', { class: 'btn sm', type: 'button' }, icon('i-file'), 'Preview');
    const apply = h('button', { class: 'btn primary sm', type: 'button' }, icon('i-play'), 'Apply');
    const undo = h('button', { class: 'btn danger sm', type: 'button' }, icon('i-undo'), 'Roll back');

    prev.addEventListener('click', () => busy(prev, async () => {
      try {
        const d = await api(base + '/generate');
        const text = typeof d === 'string' ? d : (d && (d.config || d.script || d.rules)) || JSON.stringify(d, null, 2);
        const close = h('button', { class: 'btn', type: 'button' }, 'Close');
        const m = openModal({ title: 'Preview of generated ' + what, body: h('pre', { class: 'mono', text }), footer: [close], wide: true });
        close.addEventListener('click', m.close);
      } catch (e) { toast(apiMessage(e), 'bad'); }
    }));

    apply.addEventListener('click', async () => {
      const ok = await confirmBox('Put the saved ' + what + ' into effect now? A wrong setting can cut off access to this firewall.', { ok: 'Apply', title: 'Apply ' + what });
      if (!ok) return;
      try {
        const r = await busy(apply, () => api(base + '/commit', { method: 'POST' }));
        toast((r && r.message) || 'Applied.', 'ok', 9000);
        if (r && r.confirm_seconds) showConfirm(r.confirm_seconds);
        if (base === '/api/interfaces') loadPorts().catch(() => {});
      } catch (e) { toast(apiMessage(e), 'bad'); }
    });

    undo.addEventListener('click', async () => {
      const ok = await confirmBox('Go back to the previously applied ' + what + '?', { ok: 'Roll back', danger: true, title: 'Roll back' });
      if (!ok) return;
      try {
        const r = await busy(undo, () => api(base + '/rollback', { method: 'POST' }));
        toast((r && r.message) || 'Rolled back.', 'ok', 9000);
        hideConfirm();
        await reloadAll();
      } catch (e) { toast(apiMessage(e), 'bad'); }
    });

    return h('div', { class: 'notice' }, icon('i-alert'),
      h('div', null,
        h('b', { text: 'Saved changes are not live until you apply them.' }), ' Use Preview to see what will be applied.',
        h('div', { class: 'btn-row' }, prev, apply, undo)));
  }

  function ifOptions(current, blank) {
    const names = state.ifaces.map((i) => i.name).filter((n) => n !== 'lo');
    if (current && !names.includes(current)) names.unshift(current);
    const opts = names.map((n) => [n, n]);
    return blank ? [['', '— none —']].concat(opts) : opts;
  }

  const splitList = (s) => String(s).split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);

  /* inline config form with a Save button */
  function configForm(container, grid, kit, collect, url, done) {
    const saveBtn = h('button', { class: 'btn primary', type: 'button' }, icon('i-check'), 'Save settings');
    const err = h('div', { class: 'form-error', role: 'alert', hidden: true });

    async function save() {
      err.hidden = true;
      kit.clearMarks();
      const r = collect();
      if (r.error) { err.textContent = r.error; err.hidden = false; kit.mark(r.field); return; }
      try {
        await busy(saveBtn, () => api(url, { method: 'PUT', body: r.payload }));
        toast(done, 'ok');
      } catch (e) { err.textContent = apiMessage(e); err.hidden = false; }
    }

    saveBtn.addEventListener('click', save);
    clear(container).append(grid, err, h('div', { class: 'btn-row end' }, saveBtn));
  }

  /* ---------------- interfaces ---------------- */

  function renderIfTable() {
    const body = clear($('ifBody'));
    if (!state.ifaces.length) return emptyRow(body, 6, 'No interfaces found.');
    state.ifaces.forEach((i) => {
      body.append(h('tr', null,
        h('td', null, h('b', { text: i.name })),
        h('td', null, badge(i.state, i.state === 'up' ? 'ok' : i.state === 'down' ? 'bad' : 'plain')),
        h('td', { class: 'mono nowrap', text: fmtBytes(i.rx_bytes) + ' (' + Shell.num(i.rx_packets) + ' pkts)' }),
        h('td', { class: 'mono nowrap', text: fmtBytes(i.tx_bytes) + ' (' + Shell.num(i.tx_packets) + ' pkts)' }),
        h('td', { class: 'mono', text: Shell.num(i.rx_errors) + ' / ' + Shell.num(i.rx_dropped) }),
        h('td', { class: 'mono', text: Shell.num(i.tx_errors) + ' / ' + Shell.num(i.tx_dropped) })));
    });
  }

  async function loadIfaces() {
    try {
      state.ifaces = list(await api('/api/monitor/interfaces'));
      renderIfTable();
      live(true, 'Live');
    } catch (e) {
      live(false, 'Connection lost');
      throw e;
    }
  }

  async function loadNet() {
    state.net = await api('/api/network');
    const cfg = state.net || { wan_interface: '', lan_interface: '', nat_enabled: true, ip_forward_enabled: true };
    const kit = formKit();
    const grid = h('div', { class: 'form-grid cols-2' },
      kit.fld('WAN interface', kit.select('wan_interface', ifOptions(cfg.wan_interface), cfg.wan_interface), 'Faces the internet.'),
      kit.fld('LAN interface', kit.select('lan_interface', ifOptions(cfg.lan_interface), cfg.lan_interface), 'Faces your internal network.'),
      kit.toggle('nat_enabled', 'NAT (masquerade) enabled', 'Hide internal addresses behind the WAN address.', cfg.nat_enabled),
      kit.toggle('ip_forward_enabled', 'IP forwarding enabled', 'Let the firewall pass traffic between interfaces.', cfg.ip_forward_enabled));

    configForm($('ifForm'), grid, kit, () => {
      const wan = kit.c.wan_interface.value, lan = kit.c.lan_interface.value;
      if (!wan) return { error: 'Choose the WAN interface.', field: 'wan_interface' };
      if (!lan) return { error: 'Choose the LAN interface.', field: 'lan_interface' };
      if (wan === lan) return { error: 'WAN and LAN must be different interfaces.', field: 'lan_interface' };
      return { payload: { wan_interface: wan, lan_interface: lan, nat_enabled: kit.c.nat_enabled.checked, ip_forward_enabled: kit.c.ip_forward_enabled.checked } };
    }, '/api/network', 'Saved. It is used the next time you apply the firewall rules.');
  }

  /* ---------------- port settings (IP address, gateway, DNS, MTU) ---------------- */

  let confirmTimer = null;

  function hideConfirm() {
    if (confirmTimer) { clearInterval(confirmTimer); confirmTimer = null; }
    clear($('ifConfirm'));
  }

  /* After a change to the port you are connected through, the device undoes it unless you confirm. */
  function showConfirm(seconds) {
    hideConfirm();
    let left = Math.max(0, Math.round(seconds));
    const text = h('span');
    const keep = h('button', { class: 'btn primary sm', type: 'button' }, icon('i-check'), 'Keep these settings');
    const undo = h('button', { class: 'btn danger sm', type: 'button' }, icon('i-undo'), 'Undo now');
    const paint = () => {
      text.textContent = ' If you can read this, the new settings work. They will be undone automatically in ' + left + ' seconds unless you keep them.';
    };

    keep.addEventListener('click', () => busy(keep, async () => {
      try {
        await api('/api/interfaces/confirm', { method: 'POST' });
        toast('Port settings kept.', 'ok');
        hideConfirm();
      } catch (e) { toast(apiMessage(e), 'bad'); }
    }));

    undo.addEventListener('click', () => busy(undo, async () => {
      try {
        const r = await api('/api/interfaces/rollback', { method: 'POST' });
        toast((r && r.message) || 'Rolled back.', 'ok', 9000);
        hideConfirm();
        await reloadAll();
      } catch (e) { toast(apiMessage(e), 'bad'); }
    }));

    paint();
    clear($('ifConfirm')).append(h('div', { class: 'notice' }, icon('i-alert'),
      h('div', null, h('b', { text: 'Confirm the new port settings.' }), text,
        h('div', { class: 'btn-row' }, keep, undo))));

    confirmTimer = setInterval(() => {
      left -= 1;
      if (left <= 0) {
        hideConfirm();
        toast('Time is up. The previous port settings are being restored.', 'bad', 9000);
        setTimeout(() => reloadAll().catch(() => {}), 4000);
        return;
      }
      paint();
    }, 1000);
  }

  /* Picks up a waiting confirmation, for example after logging in again on the new address. */
  async function loadPending() {
    try {
      const st = await api('/api/interfaces/status');
      if (st && st.pending && !confirmTimer) showConfirm(st.seconds_left || 0);
      if (st && !st.pending && confirmTimer) hideConfirm();
    } catch (_) {}
  }

  function portRows() {
    const saved = {};
    state.ifcfg.forEach((c) => { saved[c.name] = c; });
    const liveBy = {};
    state.live.forEach((p) => { liveBy[p.name] = p; });

    // The monitor list also knows ports when the live list could not be read.
    state.ifaces.forEach((i) => {
      if (i.name !== 'lo' && !liveBy[i.name]) liveBy[i.name] = { name: i.name, state: i.state, addresses: [], mac: null, mtu: null };
    });

    const names = new Set(Object.keys(liveBy).concat(Object.keys(saved)));
    const wan = state.net && state.net.wan_interface, lan = state.net && state.net.lan_interface;
    const rank = (n) => (n === wan ? 0 : n === lan ? 1 : 2);

    return Array.from(names)
      .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))
      .map((name) => ({ name, live: liveBy[name] || null, saved: saved[name] || null, role: name === wan ? 'WAN' : name === lan ? 'LAN' : null }));
  }

  function savedSummary(c) {
    if (c.mode === 'dhcp') return 'Address from DHCP' + (c.dns.length ? ' · DNS ' + c.dns.join(', ') : '');
    const parts = [c.addresses.length ? c.addresses.join(', ') : 'No address'];
    if (c.gateway) parts.push('gw ' + c.gateway);
    if (c.dns.length) parts.push('DNS ' + c.dns.join(', '));
    if (c.mtu) parts.push('MTU ' + c.mtu);
    return parts.join(' · ');
  }

  function renderPorts() {
    const body = clear($('portBody'));
    const rows = portRows();
    if (!rows.length) return emptyRow(body, 5, 'No ports found.');

    rows.forEach((r) => {
      const st = r.live ? String(r.live.state || 'unknown').toLowerCase() : 'missing';
      const first = h('td', null, h('b', { text: r.name }), r.role ? ' ' : null, r.role ? badge(r.role, 'plain') : null);
      if (r.live && r.live.mac) first.append(h('span', { class: 'sub mono', text: r.live.mac }));

      const current = h('td', { class: 'mono' });
      const addrs = r.live ? r.live.addresses || [] : [];
      if (addrs.length) addrs.forEach((a) => current.append(h('div', { text: a })));
      else current.textContent = '–';

      const saved = h('td');
      if (r.saved) {
        saved.append(badge(r.saved.mode === 'dhcp' ? 'DHCP' : 'Static', 'ok'));
        if (!r.saved.enabled) saved.append(' ', badge('Disabled', 'bad'));
        saved.append(h('span', { class: 'sub mono', text: savedSummary(r.saved) }));
      } else {
        saved.append(h('span', { class: 'sub', text: 'Not managed by the firewall' }));
      }
      if (!r.live) saved.append(h('span', { class: 'sub', text: 'This port is not on this system.' }));

      const acts = h('td', { class: 'actions' });
      if (r.live) acts.append(h('button', { class: 'btn sm', type: 'button', onClick: () => openPort(r) }, icon('i-edit'), 'Configure'));
      if (r.saved) acts.append(h('button', { class: 'btn sm danger', type: 'button', onClick: () => resetPort(r) }, icon('i-trash'), 'Reset'));

      body.append(h('tr', { class: r.saved && !r.saved.enabled ? 'is-off' : '' },
        first,
        h('td', null, badge(st, st === 'up' ? 'ok' : st === 'down' || st === 'missing' ? 'bad' : 'plain')),
        current, saved, acts));
    });
  }

  async function loadPorts() {
    const [live, cfg] = await Promise.allSettled([api('/api/interfaces/live'), api('/api/interfaces')]);
    if (live.status === 'fulfilled') state.live = list(live.value);
    if (cfg.status === 'fulfilled') state.ifcfg = list(cfg.value);
    renderPorts();
    if (cfg.status === 'rejected') throw cfg.reason;
  }

  async function resetPort(r) {
    const ok = await confirmBox('Remove the saved settings of port "' + r.name + '"? The port keeps its current address until the next reboot, after that the system decides.',
      { ok: 'Remove', danger: true, title: 'Reset port settings' });
    if (!ok) return;
    try {
      await api('/api/interfaces/' + encodeURIComponent(r.name), { method: 'DELETE' });
      toast('Saved settings removed. Press Apply to update the system.', 'ok');
      await loadPorts();
    } catch (e) { toast(apiMessage(e), 'bad'); }
  }

  function openPort(r) {
    const live = r.live || {};
    const base = r.saved || {
      name: r.name, mode: 'static', addresses: live.addresses || [], gateway: null, dns: [],
      mtu: live.mtu || null, enabled: true, comment: null
    };
    const kit = formKit();

    const modeFld = kit.fld('Address mode', kit.select('mode', [['static', 'Static (fixed address)'], ['dhcp', 'DHCP (get address from the network)']], base.mode),
      'Use static for LAN ports and for a WAN with a fixed address.', 'span-all');
    const addrFld = kit.fld('IP address(es)', kit.input('addresses', { type: 'text', class: 'in mono', placeholder: '192.168.1.1/24', value: (base.addresses || []).join(', ') }),
      'Address with prefix length. Separate several with commas.', 'span-all');
    const gwFld = kit.fld('Gateway', kit.input('gateway', { type: 'text', class: 'in mono', placeholder: '192.168.1.254', value: base.gateway }),
      'Only for the port that leads to the internet.');
    const dnsFld = kit.fld('DNS servers', kit.input('dns', { type: 'text', class: 'in mono', placeholder: '1.1.1.1, 8.8.8.8', value: (base.dns || []).join(', ') }),
      'Up to three, separated by commas.');
    const mtuFld = kit.fld('MTU', kit.input('mtu', { type: 'number', min: 576, max: 9216, step: 1, placeholder: '1500', value: base.mtu }), 'Leave empty for the default.');

    const grid = h('div', { class: 'form-grid cols-2' },
      modeFld, addrFld, gwFld, dnsFld, mtuFld,
      kit.fld('Comment', kit.input('comment', { type: 'text', maxlength: 200, placeholder: 'Optional note', value: base.comment })),
      kit.toggle('enabled', 'Port enabled', 'A disabled port is kept down.', base.enabled));

    const syncMode = () => {
      const on = kit.c.mode.value === 'static';
      addrFld.style.display = on ? '' : 'none';
      gwFld.style.display = on ? '' : 'none';
    };
    kit.c.mode.addEventListener('change', syncMode);
    syncMode();

    openForm({
      title: 'Port settings: ' + r.name, grid, kit, editing: true, wide: true,
      url: '/api/interfaces/' + encodeURIComponent(r.name),
      collect() {
        const c = kit.c;
        const mode = c.mode.value;
        const addresses = mode === 'static' ? splitList(c.addresses.value) : [];
        if (mode === 'static' && !addresses.length) return { error: 'Enter at least one IP address, for example 192.168.1.1/24, or choose DHCP.', field: 'addresses' };
        const mtuText = c.mtu.value.trim();
        const mtu = mtuText === '' ? null : Number(mtuText);
        if (mtu !== null && (!Number.isInteger(mtu) || mtu < 576 || mtu > 9216)) return { error: 'MTU must be a whole number from 576 to 9216.', field: 'mtu' };
        return { payload: {
          name: r.name, mode, addresses,
          gateway: mode === 'static' ? kit.text('gateway') : null,
          dns: splitList(c.dns.value), mtu,
          enabled: c.enabled.checked, comment: kit.text('comment')
        } };
      },
      done: 'Saved. Press Apply on this tab to put it into effect.',
      reload: loadPorts
    });
  }

  /* ---------------- DHCP ---------------- */

  async function loadDhcpConfig() {
    let cfg = null;
    try { cfg = await api('/api/dhcp/config'); } catch (_) { cfg = null; }
    cfg = cfg || {};
    const d = Object.assign({
      enabled: false, interface_name: state.net ? state.net.lan_interface : '', subnet: '192.168.1.0/24',
      range_start: '192.168.1.100', range_end: '192.168.1.200', gateway: null, dns_servers: [],
      lease_time_seconds: 86400, domain: null
    }, cfg);
    state.dhcp = d;

    const kit = formKit();
    const grid = h('div', { class: 'form-grid cols-2' },
      kit.toggle('enabled', 'DHCP server enabled', 'Hand out addresses on the interface below.', d.enabled),
      kit.fld('Interface', kit.select('interface_name', ifOptions(d.interface_name), d.interface_name)),
      kit.fld('Subnet', kit.input('subnet', { type: 'text', class: 'in mono', placeholder: '192.168.1.0/24', value: d.subnet })),
      kit.fld('Range start', kit.input('range_start', { type: 'text', class: 'in mono', placeholder: '192.168.1.100', value: d.range_start })),
      kit.fld('Range end', kit.input('range_end', { type: 'text', class: 'in mono', placeholder: '192.168.1.200', value: d.range_end })),
      kit.fld('Gateway', kit.input('gateway', { type: 'text', class: 'in mono', placeholder: '192.168.1.1', value: d.gateway }), 'Must be outside the range.'),
      kit.fld('DNS servers', kit.input('dns_servers', { type: 'text', class: 'in mono', placeholder: '192.168.1.1, 1.1.1.1', value: list(d.dns_servers).join(', ') }), 'Comma separated, 1 to 4.'),
      kit.fld('Lease time (seconds)', kit.input('lease_time_seconds', { type: 'number', min: 120, step: 1, value: d.lease_time_seconds }), '86400 = 1 day.'),
      kit.fld('Domain (optional)', kit.input('domain', { type: 'text', placeholder: 'lan.example', value: d.domain })));

    configForm($('dhcpForm'), grid, kit, () => {
      const c = kit.c;
      if (!c.interface_name.value) return { error: 'Choose an interface.', field: 'interface_name' };
      if (!c.subnet.value.trim()) return { error: 'Enter the subnet, for example 192.168.1.0/24.', field: 'subnet' };
      if (!c.range_start.value.trim()) return { error: 'Enter the first address of the range.', field: 'range_start' };
      if (!c.range_end.value.trim()) return { error: 'Enter the last address of the range.', field: 'range_end' };
      const dns = splitList(c.dns_servers.value);
      if (!dns.length) return { error: 'Enter at least one DNS server.', field: 'dns_servers' };
      const lease = Number(c.lease_time_seconds.value);
      if (!Number.isInteger(lease) || lease < 120) return { error: 'Lease time must be a whole number of at least 120 seconds.', field: 'lease_time_seconds' };
      return { payload: {
        enabled: c.enabled.checked, interface_name: c.interface_name.value, subnet: c.subnet.value.trim(),
        range_start: c.range_start.value.trim(), range_end: c.range_end.value.trim(),
        gateway: kit.text('gateway'), dns_servers: dns, lease_time_seconds: lease, domain: kit.text('domain')
      } };
    }, '/api/dhcp/config', 'DHCP settings saved. Press Apply to make them live.');
  }

  function renderReservations() {
    $('countRsv').textContent = String(state.reservations.length);
    const body = clear($('rsvBody'));
    if (!state.reservations.length) return emptyRow(body, 4, 'No reservations yet.');
    state.reservations.forEach((r) => {
      body.append(h('tr', null,
        h('td', { class: 'mono nowrap', text: r.mac }),
        h('td', { class: 'mono nowrap', text: r.ip }),
        h('td', { text: r.hostname || '–' }),
        actions(() => openReservation(r), () => removeItem('/api/dhcp/reservations', { id: r.id, name: r.mac }, 'reservation', loadReservations, 'It stays active until you press Apply.'))));
    });
  }

  async function loadReservations() {
    state.reservations = list(await api('/api/dhcp/reservations')).slice().sort(byKey('ip'));
    renderReservations();
  }

  function renderLeases() {
    $('countLeases').textContent = String(state.leases.length);
    const body = clear($('leaseBody'));
    if (!state.leases.length) return emptyRow(body, 4, 'No active leases.');
    state.leases.forEach((l) => {
      body.append(h('tr', null,
        h('td', { class: 'mono nowrap', text: l.ip }),
        h('td', { class: 'mono nowrap', text: l.mac }),
        h('td', { text: l.hostname || '–' }),
        h('td', { class: 'nowrap', text: l.expires ? fmtTime(l.expires) : 'Never' })));
    });
  }

  async function loadLeases() {
    state.leases = list(await api('/api/dhcp/leases'));
    renderLeases();
  }

  function openReservation(existing) {
    const r = existing || { mac: '', ip: '', hostname: null };
    const kit = formKit();
    const grid = h('div', { class: 'form-grid cols-2' },
      kit.fld('MAC address', kit.input('mac', { type: 'text', class: 'in mono', placeholder: 'aa:bb:cc:dd:ee:ff', value: r.mac })),
      kit.fld('IP address', kit.input('ip', { type: 'text', class: 'in mono', placeholder: '192.168.1.50', value: r.ip }), 'Must be inside the DHCP subnet.'),
      kit.fld('Hostname (optional)', kit.input('hostname', { type: 'text', placeholder: 'printer', value: r.hostname }), null, 'span-all'));
    openForm({
      title: existing ? 'Edit reservation' : 'Add reservation', grid, kit, editing: !!existing,
      url: existing ? '/api/dhcp/reservations/' + encodeURIComponent(existing.id) : '/api/dhcp/reservations',
      collect() {
        const mac = kit.c.mac.value.trim(), ip = kit.c.ip.value.trim();
        if (!mac) return { error: 'Enter the MAC address.', field: 'mac' };
        if (!ip) return { error: 'Enter the IP address.', field: 'ip' };
        const p = { mac, ip, hostname: kit.text('hostname') };
        if (existing) p.id = existing.id;
        return { payload: p };
      },
      done: 'Saved. Press Apply on this tab to make it live.', reload: loadReservations
    });
  }

  /* ---------------- DNS ---------------- */

  async function loadDnsConfig() {
    let cfg = null;
    try { cfg = await api('/api/dns/config'); } catch (_) { cfg = null; }
    const d = Object.assign({ enabled: false, listen_interfaces: [], upstream_servers: ['1.1.1.1', '8.8.8.8'], local_domain: null, use_dhcp_hostnames: true }, cfg || {});
    state.dns = d;

    const kit = formKit();
    const listen = checkList(ifOptions('').concat(list(d.listen_interfaces).filter((n) => !state.ifaces.some((i) => i.name === n)).map((n) => [n, n])).filter(([n]) => n !== ''), d.listen_interfaces);

    const grid = h('div', { class: 'form-grid cols-2' },
      kit.toggle('enabled', 'DNS server enabled', 'Answer DNS queries from your network.', d.enabled),
      kit.fld('Listen on interfaces', listen.node, 'Tick the interfaces that should answer DNS queries.', 'span-all'),
      kit.fld('Upstream DNS servers', kit.input('upstream_servers', { type: 'text', class: 'in mono', placeholder: '1.1.1.1, 8.8.8.8', value: list(d.upstream_servers).join(', ') }), 'Comma separated.'),
      kit.fld('Local domain (optional)', kit.input('local_domain', { type: 'text', placeholder: 'lan.example', value: d.local_domain })),
      kit.toggle('use_dhcp_hostnames', 'Use DHCP hostnames', 'Resolve names of devices that got an address from the DHCP server.', d.use_dhcp_hostnames));

    configForm($('dnsForm'), grid, kit, () => {
      const up = splitList(kit.c.upstream_servers.value);
      if (!up.length) return { error: 'Enter at least one upstream DNS server.', field: 'upstream_servers' };
      const ifs = listen.values();
      if (kit.c.enabled.checked && !ifs.length) return { error: 'Tick at least one interface to listen on.' };
      return { payload: {
        enabled: kit.c.enabled.checked, listen_interfaces: ifs, upstream_servers: up,
        local_domain: kit.text('local_domain'), use_dhcp_hostnames: kit.c.use_dhcp_hostnames.checked
      } };
    }, '/api/dns/config', 'DNS settings saved. Press Apply to make them live.');
  }

  function renderRecords() {
    $('countDns').textContent = String(state.records.length);
    const body = clear($('recBody'));
    if (!state.records.length) return emptyRow(body, 3, 'No static records yet.');
    state.records.forEach((r) => {
      body.append(h('tr', null,
        h('td', null, h('b', { text: r.hostname })),
        h('td', { class: 'mono nowrap', text: r.ip }),
        actions(() => openRecord(r), () => removeItem('/api/dns/records', { id: r.id, name: r.hostname }, 'record', loadRecords, 'It stays active until you press Apply.'))));
    });
  }

  async function loadRecords() {
    state.records = list(await api('/api/dns/records')).slice().sort(byKey('hostname'));
    renderRecords();
  }

  function openRecord(existing) {
    const r = existing || { hostname: '', ip: '' };
    const kit = formKit();
    const grid = h('div', { class: 'form-grid cols-2' },
      kit.fld('Hostname', kit.input('hostname', { type: 'text', placeholder: 'nas.lan.example', value: r.hostname })),
      kit.fld('IP address', kit.input('ip', { type: 'text', class: 'in mono', placeholder: '192.168.1.20', value: r.ip })));
    openForm({
      title: existing ? 'Edit DNS record' : 'Add DNS record', grid, kit, editing: !!existing,
      url: existing ? '/api/dns/records/' + encodeURIComponent(existing.id) : '/api/dns/records',
      collect() {
        const hostname = kit.c.hostname.value.trim(), ip = kit.c.ip.value.trim();
        if (!hostname) return { error: 'Enter the hostname.', field: 'hostname' };
        if (!ip) return { error: 'Enter the IP address.', field: 'ip' };
        const p = { hostname, ip };
        if (existing) p.id = existing.id;
        return { payload: p };
      },
      done: 'Saved. Press Apply on this tab to make it live.', reload: loadRecords
    });
  }

  /* ---------------- static routes ---------------- */

  function renderRoutes() {
    $('countRoutes').textContent = String(state.routes.length);
    const body = clear($('routeBody'));
    if (!state.routes.length) return emptyRow(body, 7, 'No static routes yet. Press Add route to create one.');
    state.routes.forEach((r) => {
      body.append(h('tr', { class: r.enabled ? '' : 'is-off' },
        h('td', null, h('b', { text: r.name }), r.comment ? h('span', { class: 'sub', text: r.comment }) : null),
        h('td', { class: 'mono nowrap', text: r.destination }),
        h('td', { class: 'mono nowrap', text: r.gateway || '–' }),
        h('td', { text: r.interface_name || '–' }),
        h('td', { class: 'mono', text: String(r.metric) }),
        h('td', null, enableSwitch(r, (box) => toggleItem('/api/routes', r, box, loadRoutes, 'Press Apply to put it into effect.'))),
        actions(() => openRoute(r), () => removeItem('/api/routes', r, 'route', loadRoutes, 'It stays active until you press Apply.'))));
    });
  }

  async function loadRoutes() {
    state.routes = list(await api('/api/routes')).slice().sort(byKey('name'));
    renderRoutes();
  }

  function openRoute(existing) {
    const r = existing || { name: '', enabled: true, destination: '', gateway: null, interface_name: null, metric: 100, comment: null };
    const kit = formKit();
    const grid = h('div', { class: 'form-grid cols-2' },
      kit.fld('Name', kit.input('name', { type: 'text', maxlength: 64, placeholder: 'Branch office', value: r.name }), null, 'span-all'),
      kit.fld('Destination network', kit.input('destination', { type: 'text', class: 'in mono', placeholder: '10.20.0.0/16', value: r.destination }), 'CIDR, or 0.0.0.0/0 for a default route.'),
      kit.fld('Gateway', kit.input('gateway', { type: 'text', class: 'in mono', placeholder: '192.168.1.254', value: r.gateway }), 'Next-hop address.'),
      kit.fld('Interface', kit.select('interface_name', ifOptions(r.interface_name, true), r.interface_name || ''), 'Optional if a gateway is given.'),
      kit.fld('Metric', kit.input('metric', { type: 'number', min: 1, max: 9999, step: 1, value: r.metric }), 'Lower is preferred (1–9999).'),
      kit.fld('Comment', kit.input('comment', { type: 'text', maxlength: 200, placeholder: 'Optional note', value: r.comment }), null, 'span-all'),
      kit.toggle('enabled', 'Route enabled', 'A disabled route is kept but never applied.', r.enabled));
    openForm({
      title: existing ? 'Edit route' : 'Add route', grid, kit, editing: !!existing, wide: true,
      url: existing ? '/api/routes/' + encodeURIComponent(existing.id) : '/api/routes',
      collect() {
        const c = kit.c;
        const name = c.name.value.trim(), dest = c.destination.value.trim();
        if (!name) return { error: 'Enter a name for the route.', field: 'name' };
        if (!dest) return { error: 'Enter the destination network, for example 10.20.0.0/16.', field: 'destination' };
        const gw = kit.text('gateway'), ifc = c.interface_name.value || null;
        if (!gw && !ifc) return { error: 'A route needs a gateway, an interface, or both.', field: 'gateway' };
        const metric = Number(c.metric.value);
        if (!Number.isInteger(metric) || metric < 1 || metric > 9999) return { error: 'Metric must be a whole number from 1 to 9999.', field: 'metric' };
        const p = { name, enabled: c.enabled.checked, destination: dest, gateway: gw, interface_name: ifc, metric, comment: kit.text('comment') };
        if (existing) p.id = existing.id;
        return { payload: p };
      },
      done: 'Saved. Press Apply to put the route into effect.', reload: loadRoutes
    });
  }

  /* ---------------- address objects ---------------- */

  const KIND_LABEL = { host: 'Host', subnet: 'Subnet', range: 'IP range' };
  const KIND_HINT = { host: '10.0.0.5', subnet: '10.0.0.0/24', range: '10.0.0.10-10.0.0.20' };

  function renderObjects() {
    $('countObjects').textContent = String(state.objects.length);
    const body = clear($('objBody'));
    if (!state.objects.length) return emptyRow(body, 5, 'No address objects yet. Press Add address object to create one.');
    state.objects.forEach((o) => {
      body.append(h('tr', null,
        h('td', null, h('b', { text: o.name }), o.comment ? h('span', { class: 'sub', text: o.comment }) : null),
        h('td', null, badge(KIND_LABEL[o.kind] || o.kind, 'info')),
        h('td', { class: 'mono nowrap', text: o.value }),
        h('td', null, badge(o.family === 'ipv6' ? 'IPv6' : 'IPv4', 'plain')),
        actions(() => openObject(o), () => removeItem('/api/address-objects', o, 'address object', loadObjects, 'Objects used by groups or rules cannot be deleted.'))));
    });
  }

  async function loadObjects() {
    state.objects = list(await api('/api/address-objects')).slice().sort(byKey('name'));
    renderObjects();
  }

  function openObject(existing) {
    const o = existing || { name: '', kind: 'host', value: '', comment: null };
    const kit = formKit();
    const grid = h('div', { class: 'form-grid cols-2' },
      kit.fld('Name', kit.input('name', { type: 'text', maxlength: 32, placeholder: 'Web_server', value: o.name }), 'Letters, digits and underscores; must start with a letter.'),
      kit.fld('Type', kit.select('kind', [['host', 'Host'], ['subnet', 'Subnet'], ['range', 'IP range']], o.kind)),
      kit.fld('Value', kit.input('value', { type: 'text', class: 'in mono', placeholder: KIND_HINT[o.kind], value: o.value }), null, 'span-all'),
      kit.fld('Comment', kit.input('comment', { type: 'text', maxlength: 200, placeholder: 'Optional note', value: o.comment }), null, 'span-all'));
    kit.c.kind.addEventListener('change', () => kit.c.value.setAttribute('placeholder', KIND_HINT[kit.c.kind.value]));
    openForm({
      title: existing ? 'Edit address object' : 'Add address object', grid, kit, editing: !!existing,
      url: existing ? '/api/address-objects/' + encodeURIComponent(existing.id) : '/api/address-objects',
      collect() {
        const name = kit.c.name.value.trim(), value = kit.c.value.value.trim();
        if (!name) return { error: 'Enter a name.', field: 'name' };
        if (!value) return { error: 'Enter a value, for example ' + KIND_HINT[kit.c.kind.value] + '.', field: 'value' };
        const p = { name, kind: kit.c.kind.value, value, comment: kit.text('comment') };
        if (existing) p.id = existing.id;
        return { payload: p };
      },
      done: 'Saved.', reload: async () => { await loadObjects(); await loadGroups(); }
    });
  }

  /* ---------------- address groups ---------------- */

  function renderGroups() {
    $('countGroups').textContent = String(state.groups.length);
    const body = clear($('grpBody'));
    if (!state.groups.length) return emptyRow(body, 4, 'No address groups yet. Press Add address group to create one.');
    state.groups.forEach((g) => {
      const members = list(g.members);
      body.append(h('tr', null,
        h('td', null, h('b', { text: g.name }), g.comment ? h('span', { class: 'sub', text: g.comment }) : null),
        h('td', null, members.length ? members.join(', ') : h('span', { class: 'sub', text: 'No members' })),
        h('td', null, members.length ? badge(g.family === 'ipv6' ? 'IPv6' : 'IPv4', 'plain') : '–'),
        actions(() => openGroup(g), () => removeItem('/api/address-groups', g, 'address group', loadGroups, 'Groups used by rules cannot be deleted.'))));
    });
  }

  async function loadGroups() {
    state.groups = list(await api('/api/address-groups')).slice().sort(byKey('name'));
    renderGroups();
  }

  function openGroup(existing) {
    const g = existing || { name: '', comment: null, members: [] };
    const kit = formKit();
    const picks = checkList(state.objects.map((o) => [o.name, o.name + ' (' + o.value + ')']), g.members);
    const grid = h('div', { class: 'form-grid' },
      kit.fld('Name', kit.input('name', { type: 'text', maxlength: 32, placeholder: 'Office_networks', value: g.name }), 'Letters, digits and underscores; must start with a letter.'),
      kit.fld('Comment', kit.input('comment', { type: 'text', maxlength: 200, placeholder: 'Optional note', value: g.comment })),
      kit.fld('Members', picks.node, 'All members must be the same IP version.', 'span-all'));
    openForm({
      title: existing ? 'Edit address group' : 'Add address group', grid, kit, editing: !!existing, wide: true,
      url: existing ? '/api/address-groups/' + encodeURIComponent(existing.id) : '/api/address-groups',
      collect() {
        const name = kit.c.name.value.trim();
        if (!name) return { error: 'Enter a name.', field: 'name' };
        const p = { name, comment: kit.text('comment'), members: picks.values() };
        if (existing) p.id = existing.id;
        return { payload: p };
      },
      done: 'Saved.', reload: loadGroups
    });
  }

  /* ---------------- wiring ---------------- */

  $('ifApply').append(applyBar('/api/interfaces', 'port settings'));
  $('dhcpApply').append(applyBar('/api/dhcp', 'DHCP settings'));
  $('dnsApply').append(applyBar('/api/dns', 'DNS settings'));
  $('routeApply').append(applyBar('/api/routes', 'routes'));

  $('btnAddRsv').addEventListener('click', () => openReservation(null));
  $('btnAddRec').addEventListener('click', () => openRecord(null));
  $('btnAddRoute').addEventListener('click', () => openRoute(null));
  $('btnAddObj').addEventListener('click', () => openObject(null));
  $('btnAddGrp').addEventListener('click', () => openGroup(null));

  async function reloadAll() {
    const fail = (e) => toast(apiMessage(e), 'bad');
    await Promise.allSettled([loadIfaces().catch(fail), loadNet().catch(fail)]);
    await Promise.allSettled([loadPorts().catch(fail), loadPending()]);
    await Promise.allSettled([
      loadDhcpConfig().catch(fail), loadReservations().catch(fail), loadLeases().catch(fail),
      loadDnsConfig().catch(fail), loadRecords().catch(fail),
      loadRoutes().catch(fail), loadObjects().catch(fail), loadGroups().catch(fail)
    ]);
  }

  tabs($('page'), 'network');
  btnRefresh.addEventListener('click', () => busy(btnRefresh, reloadAll));

  reloadAll();
  every(loadIfaces, 5000);
  every(() => loadPorts().catch(() => {}), 10000);
  every(loadPending, 5000);
  every(loadLeases, 15000);
})();
