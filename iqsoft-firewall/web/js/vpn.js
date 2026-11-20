(function () {
  'use strict';

  const { h, icon, clear, toast, openModal, confirmBox, busy, every, tabs, live, ago, num, errorText } = Shell;

  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'vpn',
    title: 'VPN (WireGuard)',
    subtitle: 'Let devices and sites connect securely to this firewall',
    content: $('page')
  });
  if (!frame) return;

  const CONNECTED_SECONDS = 180;

  const state = {
    config: null,
    peers: [],
    status: null,
    statusError: '',
    search: ''
  };

  const btnApply = h('button', { class: 'btn primary', type: 'button', title: 'Put the saved VPN settings into effect' },
    icon('i-play'), 'Apply');
  const btnPreview = h('button', { class: 'btn', type: 'button', title: 'Show the WireGuard configuration that would be applied' },
    icon('i-eye'), 'Preview');
  const btnRollback = h('button', { class: 'btn', type: 'button', title: 'Go back to the previous VPN configuration' },
    icon('i-undo'), 'Roll back');
  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' },
    icon('i-refresh'));
  frame.tools.append(btnApply, btnPreview, btnRollback, btnRefresh);

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

  function bytes(n) {
    const v = Number(n) || 0;
    if (v >= 1073741824) return (v / 1073741824).toFixed(2) + ' GB';
    if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
    if (v >= 1024) return (v / 1024).toFixed(1) + ' KB';
    return v + ' B';
  }

  function splitList(value) {
    return String(value || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  }

  function setError(id, message) {
    const box = $(id);
    box.textContent = message || '';
    box.hidden = !message;
  }

  function statusFor(peer) {
    if (!state.status || !Array.isArray(state.status.peers)) return null;
    return state.status.peers.find((p) => p.public_key === peer.public_key) || null;
  }

  function isConnected(st) {
    if (!st || !st.latest_handshake) return false;
    const age = Math.floor(Date.now() / 1000) - Number(st.latest_handshake);
    return age >= 0 && age < CONNECTED_SECONDS;
  }

  function renderStats() {
    const running = !!(state.status && state.status.running);
    const known = !!state.status;

    $('stState').textContent = !known ? 'Unknown' : running ? 'Running' : 'Stopped';

    const on = state.peers.filter((p) => p.enabled);
    $('stPeers').textContent = on.length + ' / ' + state.peers.length;

    const connected = on.filter((p) => isConnected(statusFor(p)));
    $('stConnected').textContent = known && running ? String(connected.length) : '–';

    if (known && running) {
      const peers = state.status.peers || [];
      const rx = peers.reduce((s, p) => s + (Number(p.rx_bytes) || 0), 0);
      const tx = peers.reduce((s, p) => s + (Number(p.tx_bytes) || 0), 0);
      $('stTraffic').textContent = bytes(rx) + ' / ' + bytes(tx);
    } else {
      $('stTraffic').textContent = '–';
    }
  }

  function renderNotices() {
    const box = clear($('notice'));
    const cfg = state.config;
    const items = [];

    if (state.statusError) {
      items.push(['warn', 'VPN status is not available', state.statusError]);
    } else if (cfg && state.status) {
      if (cfg.enabled && !state.status.running) {
        items.push(['warn', 'The VPN is switched on, but the tunnel is not running', 'Press Apply to start it.']);
      } else if (!cfg.enabled && state.status.running) {
        items.push(['warn', 'The VPN is switched off, but the tunnel is still running', 'Press Apply to stop it.']);
      }
    }

    if (cfg && !cfg.endpoint) {
      items.push(['', 'No public endpoint set', 'Enter the public address of this firewall under Server settings. It is needed to create client configurations.']);
    }

    items.forEach(([kind, title, text]) => {
      box.append(h('div', { class: 'notice' + (kind ? ' ' + kind : '') },
        icon(kind === 'warn' ? 'i-alert' : 'i-info'),
        h('div', null, h('b', { text: title }), ' ', text)));
    });
  }

  function connectionCell(peer, st) {
    if (!peer.enabled) return h('span', { class: 'muted', text: 'Switched off' });
    if (!state.status || !state.status.running) return h('span', { class: 'muted', text: '–' });
    if (!st || !st.latest_handshake) return badge('Never connected', 'plain');

    const sub = h('span', { class: 'sub', text: isConnected(st) && st.endpoint ? st.endpoint : 'Last seen ' + ago(st.latest_handshake) });
    return h('div', null, isConnected(st) ? badge('Connected', 'ok') : badge('Idle', 'warn'), sub);
  }

  function renderPeers() {
    $('countPeers').textContent = String(state.peers.length);
    renderStats();

    const body = clear($('peerBody'));
    const shown = state.peers.filter((p) => {
      if (!state.search) return true;
      return [p.name, p.comment, p.public_key, (p.allowed_ips || []).join(' '), p.endpoint]
        .filter(Boolean).join(' ').toLowerCase().includes(state.search);
    });

    if (!shown.length) {
      body.append(h('tr', null, h('td', {
        class: 'empty-row',
        colspan: 8,
        text: state.peers.length ? 'No peers match the search.' : 'No peers yet. Press Add peer to create the first one.'
      })));
      return;
    }

    shown.forEach((peer) => {
      const st = statusFor(peer);
      const box = h('input', { type: 'checkbox', checked: peer.enabled, 'aria-label': 'Enable ' + peer.name });
      box.addEventListener('change', () => togglePeer(peer, box));

      body.append(h('tr', { class: peer.enabled ? '' : 'is-off' },
        h('td', null,
          h('b', { text: peer.name }),
          peer.comment ? h('span', { class: 'sub', text: peer.comment }) : null,
          peer.has_preshared_key ? h('span', { class: 'sub', text: 'Extra preshared key' }) : null),
        h('td', { class: 'mono', text: (peer.allowed_ips || []).join(', ') || '–' }),
        h('td', { class: 'mono nowrap', title: peer.public_key, text: String(peer.public_key).slice(0, 10) + '…' }),
        h('td', null, connectionCell(peer, st)),
        h('td', { class: 'num nowrap', text: st ? bytes(st.rx_bytes) : '–' }),
        h('td', { class: 'num nowrap', text: st ? bytes(st.tx_bytes) : '–' }),
        h('td', null, h('label', { class: 'switch' }, box, h('span', { class: 'slider' }))),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => openPeerForm(peer) }, icon('i-edit'), 'Edit'),
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deletePeer(peer) }, icon('i-trash'), 'Delete'))));
    });
  }

  function fillSettings() {
    const c = state.config;
    if (!c) return;

    $('sEnabled').checked = !!c.enabled;
    $('sIface').value = c.interface_name || '';
    $('sPort').value = c.listen_port === null || c.listen_port === undefined ? '' : c.listen_port;
    $('sAddress').value = c.address || '';
    $('sEndpoint').value = c.endpoint || '';
    $('sDns').value = c.dns || '';
    $('sMtu').value = c.mtu === null || c.mtu === undefined ? '' : c.mtu;
    $('sAllowed').value = (c.client_allowed_ips || []).join(', ');
    $('sPubKey').value = c.public_key || '';
    $('sRegen').checked = false;
  }

  async function loadConfig() {
    state.config = await api('/api/wireguard/config');
    fillSettings();
    renderNotices();
  }

  async function loadPeers() {
    const list = await api('/api/wireguard/peers');
    state.peers = (Array.isArray(list) ? list : []).slice()
      .sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }));
    renderPeers();
  }

  async function refreshStatus() {
    try {
      state.status = await api('/api/wireguard/status');
      state.statusError = '';
      live(true, 'Live');
    } catch (e) {
      state.status = null;
      state.statusError = apiMessage(e);
      live(e && e.status === 500, e && e.status === 500 ? 'VPN status unavailable' : 'Connection lost');
    }

    renderNotices();
    renderPeers();
  }

  async function togglePeer(peer, box) {
    const wanted = box.checked;
    box.disabled = true;

    try {
      await api('/api/wireguard/peers/' + encodeURIComponent(peer.id), {
        method: 'PUT',
        body: {
          name: peer.name,
          enabled: wanted,
          allowed_ips: peer.allowed_ips || [],
          endpoint: peer.endpoint || null,
          persistent_keepalive: peer.persistent_keepalive || 0,
          comment: peer.comment || null
        }
      });
      toast('Peer "' + peer.name + '" ' + (wanted ? 'switched on' : 'switched off') + '. Press Apply to put it into effect.', 'ok');
      await loadPeers();
    } catch (e) {
      box.checked = !wanted;
      box.disabled = false;
      toast(apiMessage(e), 'bad');
    }
  }

  async function deletePeer(peer) {
    const ok = await confirmBox('Delete the peer "' + peer.name + '"? It is disconnected after you press Apply.',
      { ok: 'Delete', danger: true, title: 'Delete peer' });
    if (!ok) return;

    try {
      await api('/api/wireguard/peers/' + encodeURIComponent(peer.id), { method: 'DELETE' });
      toast('Peer deleted. Press Apply to put it into effect.', 'ok');
      await loadPeers();
    } catch (e) {
      toast(apiMessage(e), 'bad');
    }
  }

  function showClientConfig(name, text) {
    const area = h('textarea', { class: 'in mono', rows: 14, readonly: true, spellcheck: 'false' });
    area.value = text;

    const copy = h('button', { class: 'btn', type: 'button' }, 'Copy');
    const save = h('button', { class: 'btn', type: 'button' }, icon('i-upload'), 'Download .conf');
    const done = h('button', { class: 'btn primary', type: 'button' }, 'I have saved it');

    const body = h('div', { class: 'stack' },
      h('div', { class: 'notice warn' },
        icon('i-alert'),
        h('div', null, h('b', { text: 'This is the only time you can see this configuration.' }), ' It contains the client\'s private key, which is not stored on the firewall. Copy it or download it now and give it to the user.')),
      area);

    const modal = openModal({ title: 'Client configuration for "' + name + '"', body, footer: [copy, save, done], wide: true });

    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(text);
      } catch (_) {
        area.focus();
        area.select();
        try { document.execCommand('copy'); } catch (__) {}
      }
      toast('Configuration copied.', 'ok');
    });

    save.addEventListener('click', () => {
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const link = h('a', { href: url, download: (name.replace(/[^A-Za-z0-9_-]+/g, '-') || 'client') + '.conf' });
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });

    done.addEventListener('click', modal.close);
  }

  function openPeerForm(existing) {
    const editing = !!existing;
    const peer = existing || {
      name: '', enabled: true, public_key: '', allowed_ips: [], endpoint: null, persistent_keepalive: 0, comment: null
    };

    const c = {};

    function input(name, props) {
      c[name] = h('input', Object.assign({ class: 'in', name, autocomplete: 'off', spellcheck: 'false' }, props));
      return c[name];
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

    c.mode = h('select', { class: 'in', name: 'mode' },
      [['generate', 'Create keys here and give the client a ready-made configuration'], ['own', 'The client already has keys (paste its public key)']]
        .map(([v, t]) => h('option', { value: v, text: t })));

    const modeField = fld('Setup', h('span', { class: 'select-wrap' }, c.mode), null, 'span-all');
    const keyField = fld('Client public key', input('public_key', { type: 'text', class: 'in mono', placeholder: 'Base64 key, 44 characters' }), null, 'span-all');
    const pskToggle = toggle('use_preshared_key', 'Add a preshared key', 'An extra layer of protection between this client and the firewall.', true);
    const regenToggle = toggle('regen', 'Create new keys for this peer', 'The old client configuration stops working. You get a new one to hand over.', false);
    const publicKeyShown = fld('Public key', h('input', { class: 'in mono', type: 'text', readonly: true, value: peer.public_key }), null, 'span-all');

    const grid = h('div', { class: 'form-grid cols-2' },
      fld('Peer name', input('name', { type: 'text', maxlength: 64, placeholder: 'Anna\'s laptop', value: peer.name }), null, 'span-all'),
      editing ? publicKeyShown : modeField,
      editing ? null : keyField,
      fld('Tunnel address(es)', input('allowed_ips', { type: 'text', class: 'in mono', placeholder: editing ? '10.8.0.2/32' : 'Leave empty to assign the next free address', value: (peer.allowed_ips || []).join(', ') }),
        'The address this peer uses inside the VPN. Add networks behind a site-to-site peer, separated by commas.', 'span-all'),
      fld('Endpoint (optional)', input('endpoint', { type: 'text', class: 'in mono', placeholder: 'host:port', value: peer.endpoint }), 'Only for peers with a fixed address that the firewall should connect to.'),
      fld('Keepalive (seconds)', input('persistent_keepalive', { type: 'number', min: 0, max: 65535, step: 1, value: peer.persistent_keepalive || 0 }), 'Use 25 if the peer is behind NAT and the firewall must reach it. 0 turns it off.'),
      fld('Comment', input('comment', { type: 'text', maxlength: 200, placeholder: 'Optional note', value: peer.comment }), null, 'span-all'),
      editing ? regenToggle : null,
      pskToggle,
      toggle('enabled', 'Peer enabled', 'A disabled peer is kept but cannot connect.', peer.enabled)
    );

    function generating() {
      return editing ? c.regen.checked : c.mode.value === 'generate';
    }

    function sync() {
      const gen = generating();
      if (!editing) {
        keyField.hidden = gen;
        c.public_key.disabled = gen;
      }
      pskToggle.hidden = !gen;
      c.use_preshared_key.disabled = !gen;
    }

    (editing ? c.regen : c.mode).addEventListener('change', sync);
    sync();

    const form = h('form', { novalidate: true, onSubmit: (ev) => { ev.preventDefault(); save(); } }, grid);
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const saveBtn = h('button', { class: 'btn primary', type: 'button' }, editing ? 'Save changes' : 'Add peer');

    const modal = openModal({ title: editing ? 'Edit peer' : 'Add peer', body: form, footer: [cancel, saveBtn], wide: true });

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
      if (!name) return fail('Enter a name for the peer.', 'name');

      const gen = generating();
      const ips = splitList(c.allowed_ips.value);

      if (gen && !(state.config && state.config.endpoint)) {
        return fail('Set the public endpoint under Server settings first. Client configurations need it.', 'name');
      }

      let publicKey = null;
      if (!editing && !gen) {
        publicKey = c.public_key.value.trim();
        if (!publicKey) return fail('Paste the client\'s public key.', 'public_key');
        if (!ips.length) return fail('Enter the tunnel address for this peer.', 'allowed_ips');
      }

      if (editing && !gen && !ips.length) return fail('A peer needs at least one tunnel address.', 'allowed_ips');

      const keepalive = Number(c.persistent_keepalive.value === '' ? 0 : c.persistent_keepalive.value);
      if (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65535) {
        return fail('Keepalive must be a whole number from 0 to 65535.', 'persistent_keepalive');
      }

      const endpoint = c.endpoint.value.trim();
      const comment = c.comment.value.trim();

      const payload = {
        name,
        enabled: c.enabled.checked,
        generate_keys: gen,
        use_preshared_key: gen && c.use_preshared_key.checked,
        allowed_ips: ips,
        endpoint: endpoint === '' ? null : endpoint,
        persistent_keepalive: keepalive,
        comment: comment === '' ? null : comment
      };

      if (publicKey) payload.public_key = publicKey;
      return payload;
    }

    async function save() {
      modal.setError('');
      Object.values(c).forEach((el) => el.classList.remove('invalid'));

      const payload = collect();
      if (!payload) return;

      if (editing && payload.generate_keys) {
        const ok = await confirmBox('Create new keys for "' + peer.name + '"? Its current configuration stops working.', { ok: 'Create new keys', danger: true, title: 'New keys' });
        if (!ok) return;
      }

      let res;
      try {
        res = await busy(saveBtn, () => api(editing ? '/api/wireguard/peers/' + encodeURIComponent(existing.id) : '/api/wireguard/peers', {
          method: editing ? 'PUT' : 'POST',
          body: payload
        }));
      } catch (e) {
        modal.setError(apiMessage(e));
        return;
      }

      modal.close();
      toast((editing ? 'Peer saved' : 'Peer added') + '. Press Apply to put it into effect.', 'ok');
      await loadPeers().catch((e) => toast(apiMessage(e), 'bad'));

      if (res && res.client_config) showClientConfig(payload.name, res.client_config);
    }
  }

  async function saveSettings(ev) {
    if (ev) ev.preventDefault();
    setError('settingsError', '');
    ['sIface', 'sPort', 'sAddress', 'sMtu', 'sAllowed'].forEach((id) => $(id).classList.remove('invalid'));

    function fail(message, id) {
      setError('settingsError', message);
      $(id).classList.add('invalid');
      $(id).focus();
    }

    const iface = $('sIface').value.trim();
    if (!iface) return fail('Enter the interface name, for example wg0.', 'sIface');

    const port = Number($('sPort').value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return fail('The listen port must be a number from 1 to 65535.', 'sPort');

    const address = $('sAddress').value.trim();
    if (!address) return fail('Enter the tunnel address, for example 10.8.0.1/24.', 'sAddress');

    let mtu = null;
    if ($('sMtu').value.trim() !== '') {
      mtu = Number($('sMtu').value);
      if (!Number.isInteger(mtu) || mtu < 1280 || mtu > 1500) return fail('MTU must be a number from 1280 to 1500.', 'sMtu');
    }

    const allowed = splitList($('sAllowed').value);
    if (!allowed.length) return fail('Enter at least one network that clients send through the VPN.', 'sAllowed');

    const regen = $('sRegen').checked;
    if (regen) {
      const ok = await confirmBox('Create a new server key pair? Every existing client stops working until it gets a new configuration.',
        { ok: 'Create new keys', danger: true, title: 'New server keys' });
      if (!ok) return;
    }

    const dns = $('sDns').value.trim();
    const endpoint = $('sEndpoint').value.trim();

    try {
      state.config = await busy($('btnSaveSettings'), () => api('/api/wireguard/config', {
        method: 'PUT',
        body: {
          enabled: $('sEnabled').checked,
          interface_name: iface,
          listen_port: port,
          address,
          mtu,
          dns: dns === '' ? null : dns,
          endpoint: endpoint === '' ? null : endpoint,
          client_allowed_ips: allowed,
          regenerate_keys: regen
        }
      }));
      fillSettings();
      renderNotices();
      $('settingsState').textContent = 'Saved. Press Apply to put it into effect.';
      toast('VPN settings saved. Press Apply to put them into effect.', 'ok');
    } catch (e) {
      setError('settingsError', apiMessage(e));
    }
  }

  async function applyNow() {
    try {
      const res = await busy(btnApply, () => api('/api/wireguard/commit', { method: 'POST' }));
      toast((res && res.message) || 'VPN settings applied.', 'ok');
      await refreshStatus();
    } catch (e) {
      toast(apiMessage(e), 'bad', 12000);
    }
  }

  async function rollbackNow() {
    const ok = await confirmBox('Go back to the previous VPN configuration? Settings and peers saved since then stay in the lists.',
      { ok: 'Roll back', danger: true, title: 'Roll back' });
    if (!ok) return;

    try {
      const res = await busy(btnRollback, () => api('/api/wireguard/rollback', { method: 'POST' }));
      toast((res && res.message) || 'Rolled back to the previous VPN configuration.', 'ok');
      await refreshStatus();
    } catch (e) {
      toast(apiMessage(e), 'bad', 12000);
    }
  }

  async function previewConfig() {
    try {
      const res = await busy(btnPreview, () => api('/api/wireguard/generate'));
      const close = h('button', { class: 'btn', type: 'button' }, 'Close');
      const modal = openModal({
        title: 'WireGuard configuration that would be applied',
        body: h('pre', { class: 'code mono', text: (res && res.config) || '' }),
        footer: [close],
        wide: true
      });
      close.addEventListener('click', modal.close);
    } catch (e) {
      toast(apiMessage(e), 'bad');
    }
  }

  async function reloadAll() {
    await Promise.allSettled([
      loadConfig().catch((e) => toast(apiMessage(e), 'bad')),
      loadPeers().catch((e) => toast(apiMessage(e), 'bad')),
      refreshStatus()
    ]);
  }

  tabs($('page'), 'vpn');

  $('search').addEventListener('input', (ev) => { state.search = ev.target.value.trim().toLowerCase(); renderPeers(); });
  $('btnAddPeer').addEventListener('click', () => openPeerForm(null));
  $('settingsForm').addEventListener('submit', saveSettings);
  $('sPubKey').addEventListener('focus', (ev) => ev.target.select());

  btnApply.addEventListener('click', applyNow);
  btnPreview.addEventListener('click', previewConfig);
  btnRollback.addEventListener('click', rollbackNow);
  btnRefresh.addEventListener('click', () => busy(btnRefresh, reloadAll));

  reloadAll();
  every(refreshStatus, 5000);
})();
