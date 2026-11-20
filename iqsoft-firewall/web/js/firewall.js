(function () {
  'use strict';

  const { h, icon, clear, toast, openModal, confirmBox, busy, every, live, errorText } = Shell;

  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'firewall',
    title: 'Firewall Rules',
    subtitle: 'Control which traffic is accepted, dropped or rejected',
    content: $('page')
  });
  if (!frame) return;

  const CHAINS = [['', 'All'], ['INPUT', 'Input'], ['FORWARD', 'Forward'], ['OUTPUT', 'Output']];
  const ACTION_BADGE = { accept: 'ok', drop: 'bad', reject: 'warn' };

  const state = {
    rules: [],
    chain: '',
    action: '',
    search: '',
    wasPending: false,
    confirming: false
  };

  const btnApply = h('button', { class: 'btn primary', type: 'button', title: 'Put the saved rules into effect' },
    icon('i-play'), 'Apply');
  const btnPreview = h('button', { class: 'btn', type: 'button', title: 'Show the ruleset that would be applied' },
    icon('i-eye'), 'Preview');
  const btnRollback = h('button', { class: 'btn', type: 'button', title: 'Go back to the previous ruleset' },
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

  function endpoint(ip, port) {
    const host = ip || 'Any';
    if (port === null || port === undefined) return host;
    return (String(host).includes(':') ? '[' + host + ']' : host) + ':' + port;
  }

  function nextPriority() {
    if (!state.rules.length) return 100;
    const top = Math.max.apply(null, state.rules.map((r) => Number(r.priority) || 0));
    return top + 10;
  }

  function sortRules(list) {
    return list.slice().sort((a, b) => (a.priority - b.priority) || ((a.id || 0) - (b.id || 0)));
  }

  function matches(rule) {
    if (state.chain && rule.chain_name !== state.chain) return false;
    if (state.action && rule.action !== state.action) return false;
    if (!state.search) return true;

    const haystack = [
      rule.name, rule.comment, rule.chain_name, rule.action, rule.protocol,
      rule.src_ip, rule.dst_ip, rule.src_port, rule.dst_port,
      rule.port_any ? 'any port' : '', rule.interface_name, rule.src_mac
    ].filter((v) => v !== null && v !== undefined).join(' ').toLowerCase();

    return haystack.includes(state.search);
  }

  function optionBadges(rule) {
    const out = [];
    if (rule.interface_name) out.push(badge('if: ' + rule.interface_name, 'plain'));
    if (rule.src_mac) out.push(badge('MAC ' + rule.src_mac, 'plain'));
    if (rule.rate_limit) out.push(badge('limit ' + rule.rate_limit, 'info'));
    if (rule.time_start && rule.time_end) {
      out.push(badge(rule.time_start + '–' + rule.time_end + (rule.days ? ' ' + rule.days : ''), 'info'));
    } else if (rule.days) {
      out.push(badge(rule.days, 'info'));
    }
    if (rule.log_enabled) out.push(badge('Log', 'warn'));
    return out.length ? h('div', { class: 'stack' }, out) : h('span', { class: 'muted', text: '–' });
  }

  function renderStats() {
    const enabled = state.rules.filter((r) => r.enabled);
    $('stTotal').textContent = String(state.rules.length);
    $('stEnabled').textContent = String(enabled.length);
    $('stBlocking').textContent = String(enabled.filter((r) => r.action !== 'accept').length);
  }

  function renderRules() {
    renderStats();

    const body = clear($('ruleBody'));
    const shown = state.rules.filter(matches);

    $('ruleCount').textContent = 'Showing ' + shown.length + ' of ' + state.rules.length + ' rules';

    if (!shown.length) {
      body.append(h('tr', null, h('td', {
        class: 'empty-row',
        colspan: 10,
        text: state.rules.length ? 'No rules match the current filter.' : 'No firewall rules yet. Press Add rule to create the first one.'
      })));
      return;
    }

    shown.forEach((rule) => {
      const toggle = h('input', { type: 'checkbox', checked: rule.enabled, 'aria-label': 'Enable ' + rule.name });
      toggle.addEventListener('change', () => toggleRule(rule, toggle));

      const destination = rule.port_any
        ? endpoint(rule.dst_ip) + ' (any port)'
        : endpoint(rule.dst_ip, rule.dst_port);

      body.append(h('tr', { class: rule.enabled ? '' : 'is-off' },
        h('td', { class: 'num mono', text: rule.priority }),
        h('td', null, h('b', { text: rule.name }), rule.comment ? h('span', { class: 'sub', text: rule.comment }) : null),
        h('td', { class: 'nowrap', text: rule.chain_name }),
        h('td', null, badge(rule.action.toUpperCase(), ACTION_BADGE[rule.action] || '')),
        h('td', { class: 'nowrap', text: rule.protocol.toUpperCase() }),
        h('td', { class: 'mono nowrap', text: endpoint(rule.src_ip, rule.src_port) }),
        h('td', { class: 'mono nowrap', text: destination }),
        h('td', null, optionBadges(rule)),
        h('td', null, h('label', { class: 'switch' }, toggle, h('span', { class: 'slider' }))),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => openRuleForm(rule) }, icon('i-edit'), 'Edit'),
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteRule(rule) }, icon('i-trash'), 'Delete'))));
    });
  }

  async function loadRules() {
    const list = await api('/api/rules');
    state.rules = sortRules(Array.isArray(list) ? list : []);
    renderRules();
  }

  async function loadAddressNames() {
    const list = clear($('addrList'));
    const results = await Promise.allSettled([api('/api/address-objects'), api('/api/address-groups')]);
    const names = [];

    results.forEach((r) => {
      if (r.status !== 'fulfilled' || !Array.isArray(r.value)) return;
      r.value.forEach((item) => { if (item && item.name) names.push(item.name); });
    });

    Array.from(new Set(names)).sort().forEach((name) => list.append(h('option', { value: '@' + name })));
  }

  async function toggleRule(rule, box) {
    const wanted = box.checked;
    box.disabled = true;

    try {
      await api('/api/rules/' + encodeURIComponent(rule.id), {
        method: 'PUT',
        body: Object.assign({}, rule, { enabled: wanted })
      });
      toast('Rule "' + rule.name + '" ' + (wanted ? 'enabled' : 'disabled') + '. Press Apply to put it into effect.', 'ok');
      await loadRules();
    } catch (e) {
      box.checked = !wanted;
      box.disabled = false;
      toast(apiMessage(e), 'bad');
    }
  }

  async function deleteRule(rule) {
    const ok = await confirmBox('Delete the rule "' + rule.name + '"? It stays active on the firewall until you press Apply.',
      { ok: 'Delete', danger: true, title: 'Delete rule' });
    if (!ok) return;

    try {
      await api('/api/rules/' + encodeURIComponent(rule.id), { method: 'DELETE' });
      toast('Rule deleted.', 'ok');
      await loadRules();
    } catch (e) {
      toast(apiMessage(e), 'bad');
    }
  }

  function openRuleForm(existing) {
    const editing = !!existing;
    const rule = existing || {
      name: '', enabled: true, priority: nextPriority(), chain_name: 'INPUT', action: 'accept', protocol: 'tcp',
      src_ip: null, dst_ip: null, src_port: null, dst_port: null, port_any: false, interface_name: null,
      src_mac: null, time_start: null, time_end: null, days: null, rate_limit: null, log_enabled: false, comment: null
    };

    const c = {};

    function input(name, props) {
      c[name] = h('input', Object.assign({ class: 'in', name, autocomplete: 'off', spellcheck: 'false' }, props));
      return c[name];
    }

    function select(name, options, value) {
      c[name] = h('select', { class: 'in', name },
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

    const grid = h('div', { class: 'form-grid cols-2' },
      fld('Rule name', input('name', { type: 'text', maxlength: 80, placeholder: 'Allow SSH from office', value: rule.name }), null, 'span-all'),
      fld('Chain', select('chain_name', [['INPUT', 'INPUT – to the firewall'], ['FORWARD', 'FORWARD – through the firewall'], ['OUTPUT', 'OUTPUT – from the firewall']], rule.chain_name)),
      fld('Action', select('action', [['accept', 'Accept'], ['drop', 'Drop (silently discard)'], ['reject', 'Reject (tell the sender)']], rule.action)),
      fld('Protocol', select('protocol', [['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP'], ['any', 'Any']], rule.protocol)),
      fld('Priority', input('priority', { type: 'number', min: 0, step: 1, value: rule.priority }), 'Lower numbers are checked first.'),
      fld('Source address', input('src_ip', { type: 'text', class: 'in mono', list: 'addrList', placeholder: 'Any, 10.0.0.0/24 or @name', value: rule.src_ip }), 'An IP, a CIDR network, or @name for an address object or group.'),
      fld('Destination address', input('dst_ip', { type: 'text', class: 'in mono', list: 'addrList', placeholder: 'Any, 10.0.0.5 or @name', value: rule.dst_ip }), 'Source and destination must be the same IP version.'),
      fld('Source port', input('src_port', { type: 'number', min: 1, max: 65535, step: 1, placeholder: 'Any', value: rule.src_port })),
      fld('Destination port', input('dst_port', { type: 'number', min: 1, max: 65535, step: 1, placeholder: '22', value: rule.dst_port })),
      toggle('port_any', 'Allow all ports', 'For TCP and UDP rules that should match every destination port.', rule.port_any),
      fld('Interface', input('interface_name', { type: 'text', maxlength: 15, placeholder: 'eth0', value: rule.interface_name }), 'Leave empty to match every interface.'),
      fld('Source MAC address', input('src_mac', { type: 'text', class: 'in mono', placeholder: 'aa:bb:cc:dd:ee:ff', value: rule.src_mac }), 'Only for INPUT and FORWARD rules.'),
      fld('Active from', input('time_start', { type: 'time', value: rule.time_start })),
      fld('Active until', input('time_end', { type: 'time', value: rule.time_end }), 'Set both times, or neither. A window can run past midnight.'),
      fld('Days', input('days', { type: 'text', placeholder: 'mon-fri', value: rule.days }), 'For example mon-fri, or sat,sun. Empty means every day.'),
      fld('Rate limit', input('rate_limit', { type: 'text', placeholder: '10/second', value: rule.rate_limit }), 'Use 10/second, 60/minute, 100/hour or 1000/day.'),
      fld('Comment', input('comment', { type: 'text', maxlength: 200, placeholder: 'Why this rule exists', value: rule.comment }), null, 'span-all'),
      toggle('enabled', 'Rule enabled', 'A disabled rule is kept but never applied.', rule.enabled),
      toggle('log_enabled', 'Log matching traffic', 'Writes a log entry each time this rule matches.', rule.log_enabled)
    );

    function sync() {
      const portProto = c.protocol.value === 'tcp' || c.protocol.value === 'udp';

      c.src_port.disabled = !portProto;
      c.port_any.disabled = !portProto;
      c.dst_port.disabled = !portProto || c.port_any.checked;

      if (!portProto) {
        c.src_port.value = '';
        c.dst_port.value = '';
        c.port_any.checked = false;
      } else if (c.port_any.checked) {
        c.dst_port.value = '';
      }

      const output = c.chain_name.value === 'OUTPUT';
      c.src_mac.disabled = output;
      if (output) c.src_mac.value = '';
    }

    ['protocol', 'chain_name', 'port_any'].forEach((name) => c[name].addEventListener('change', sync));
    sync();

    const form = h('form', { novalidate: true, onSubmit: (ev) => { ev.preventDefault(); save(); } }, grid);

    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const saveBtn = h('button', { class: 'btn primary', type: 'button' }, editing ? 'Save changes' : 'Add rule');

    const modal = openModal({
      title: editing ? 'Edit rule' : 'Add rule',
      body: form,
      footer: [cancel, saveBtn],
      wide: true
    });

    cancel.addEventListener('click', modal.close);
    saveBtn.addEventListener('click', save);

    function text(name) {
      const v = c[name].value.trim();
      return v === '' ? null : v;
    }

    function port(name, label) {
      const raw = c[name].value.trim();
      if (raw === '') return { value: null };
      const n = Number(raw);
      if (!Number.isInteger(n) || n < 1 || n > 65535) return { error: label + ' must be a number from 1 to 65535.' };
      return { value: n };
    }

    function collect() {
      const name = c.name.value.trim();
      if (!name) return { error: 'Enter a name for the rule.', field: 'name' };

      const priority = Number(c.priority.value);
      if (c.priority.value.trim() === '' || !Number.isInteger(priority) || priority < 0) {
        return { error: 'Priority must be a whole number, 0 or higher.', field: 'priority' };
      }

      const src = port('src_port', 'Source port');
      if (src.error) return { error: src.error, field: 'src_port' };
      const dst = port('dst_port', 'Destination port');
      if (dst.error) return { error: dst.error, field: 'dst_port' };

      const portProto = c.protocol.value === 'tcp' || c.protocol.value === 'udp';
      if (portProto && dst.value === null && !c.port_any.checked) {
        return { error: 'Enter a destination port, or switch on "Allow all ports".', field: 'dst_port' };
      }

      const from = text('time_start');
      const until = text('time_end');
      if ((from === null) !== (until === null)) {
        return { error: 'Set both "Active from" and "Active until", or leave both empty.', field: 'time_start' };
      }

      const payload = {
        name,
        enabled: c.enabled.checked,
        priority,
        chain_name: c.chain_name.value,
        action: c.action.value,
        protocol: c.protocol.value,
        src_ip: text('src_ip'),
        dst_ip: text('dst_ip'),
        src_port: portProto ? src.value : null,
        dst_port: portProto && !c.port_any.checked ? dst.value : null,
        port_any: portProto && c.port_any.checked,
        interface_name: text('interface_name'),
        src_mac: text('src_mac'),
        time_start: from,
        time_end: until,
        days: text('days'),
        rate_limit: text('rate_limit'),
        log_enabled: c.log_enabled.checked,
        comment: text('comment')
      };

      if (editing) payload.id = existing.id;
      return { payload };
    }

    async function save() {
      modal.setError('');
      Object.values(c).forEach((el) => el.classList.remove('invalid'));

      const result = collect();
      if (result.error) {
        modal.setError(result.error);
        if (c[result.field]) {
          c[result.field].classList.add('invalid');
          c[result.field].focus();
        }
        return;
      }

      try {
        await busy(saveBtn, () => api(editing ? '/api/rules/' + encodeURIComponent(existing.id) : '/api/rules', {
          method: editing ? 'PUT' : 'POST',
          body: result.payload
        }));
      } catch (e) {
        modal.setError(apiMessage(e));
        return;
      }

      modal.close();
      toast((editing ? 'Rule updated' : 'Rule added') + '. Press Apply to put it into effect.', 'ok');
      await loadRules().catch((e) => toast(apiMessage(e), 'bad'));
    }
  }

  function openApply() {
    const timer = h('select', { class: 'in' },
      [[60, '60 seconds (recommended)'], [30, '30 seconds'], [120, '2 minutes'], [300, '5 minutes'], [0, 'No timer – apply permanently']]
        .map(([v, t]) => h('option', { value: v, text: t })));

    const body = h('div', null,
      h('p', { class: 'card-sub', text: 'This replaces the active firewall ruleset with the rules saved here. With a safety timer, the firewall returns to the previous rules by itself unless you confirm that you can still reach it.' }),
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

  async function openPreview() {
    try {
      const res = await busy(btnPreview, () => api('/api/generate'));
      const close = h('button', { class: 'btn', type: 'button' }, 'Close');
      const modal = openModal({
        title: 'Ruleset that would be applied',
        body: h('pre', { class: 'code mono', text: (res && res.config) || '' }),
        footer: [close],
        wide: true
      });
      close.addEventListener('click', modal.close);
    } catch (e) {
      toast(apiMessage(e), 'bad');
    }
  }

  async function doRollback() {
    const ok = await confirmBox('Go back to the previous firewall ruleset? Rules saved since then stay in the list.',
      { ok: 'Roll back', danger: true, title: 'Roll back' });
    if (!ok) return;

    state.confirming = true;

    try {
      const res = await busy(btnRollback, () => api('/api/rollback', { method: 'POST' }));
      toast((res && res.message) || 'Rolled back to the previous rules.', 'ok');
    } catch (e) {
      toast(apiMessage(e), 'bad');
    } finally {
      state.confirming = false;
    }

    await refreshPending();
  }

  async function confirmPending(button) {
    state.confirming = true;

    try {
      const res = await busy(button, () => api('/api/commit/confirm', { method: 'POST' }));
      toast((res && res.message) || 'Change confirmed.', 'ok');
    } catch (e) {
      toast(apiMessage(e), 'bad');
    } finally {
      state.confirming = false;
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

      if (state.wasPending && !state.confirming) {
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

  function buildChainFilter() {
    const seg = $('chainSeg');

    CHAINS.forEach(([value, label]) => {
      const b = h('button', { type: 'button', class: value === state.chain ? 'on' : '', text: label });
      b.addEventListener('click', () => {
        state.chain = value;
        Array.from(seg.children).forEach((x) => x.classList.toggle('on', x === b));
        renderRules();
      });
      seg.append(b);
    });
  }

  async function reloadAll() {
    await Promise.allSettled([
      loadRules().catch((e) => toast(apiMessage(e), 'bad')),
      loadAddressNames(),
      refreshPending()
    ]);
  }

  buildChainFilter();

  $('actionFilter').addEventListener('change', (ev) => { state.action = ev.target.value; renderRules(); });
  $('search').addEventListener('input', (ev) => { state.search = ev.target.value.trim().toLowerCase(); renderRules(); });
  $('btnAdd').addEventListener('click', () => openRuleForm(null));

  btnApply.addEventListener('click', openApply);
  btnPreview.addEventListener('click', openPreview);
  btnRollback.addEventListener('click', doRollback);
  btnRefresh.addEventListener('click', () => busy(btnRefresh, reloadAll));

  reloadAll();
  every(refreshPending, 3000);
})();
