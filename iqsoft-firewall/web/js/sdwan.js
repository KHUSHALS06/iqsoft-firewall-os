(function () {
  'use strict';

  const { h, icon, clear, toast, openModal, confirmBox, every, tabs, live, ago, ms, num, errorText } = Shell;

  const $ = (id) => document.getElementById(id);
  const POLL_MS = 3000;
  const DIRTY_KEY = 'iqsoft.sdwan.dirty';

  const frame = Shell.mount({
    active: 'sdwan',
    title: 'SD-WAN',
    subtitle: 'Use several internet connections and fail over automatically',
    content: $('page')
  });
  if (!frame) return;

  const state = {
    status: null,        // last /api/sdwan/status
    links: [],           // status.links, with live health
    rules: [],
    rulesLoaded: false,
    linkKey: '',         // settings of the links as last drawn, so the table is only redrawn when they change
    tab: 'overview',
    switchBusy: false,
    dirty: false         // saved changes that a commit has not put into effect yet
  };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' },
    icon('i-refresh'));
  frame.tools.append(btnRefresh);

  /* ---------------- helpers ---------------- */

  async function lock(buttons, work) {
    const list = buttons.filter(Boolean);
    list.forEach((b) => { b.disabled = true; b.classList.add('busy'); });
    try {
      return await work();
    } finally {
      list.forEach((b) => { b.disabled = false; b.classList.remove('busy'); });
    }
  }

  function badge(text, kind) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  }

  /* Commit and rollback answer with {"status":"error","message":...}, other calls with {"error":...}. */
  function failText(e) {
    if (e && e.data && typeof e.data === 'object' && e.data.message) return String(e.data.message);
    return errorText(e);
  }

  function emptyRow(columns, text) {
    return h('tr', null, h('td', { class: 'empty-row', colspan: columns, text }));
  }

  function isIPv4(text) {
    const parts = String(text).split('.');
    return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
  }

  function isNetwork(text) {
    const [ip, prefix, extra] = String(text).split('/');
    if (extra !== undefined || !isIPv4(ip)) return false;
    if (prefix === undefined) return true;
    return /^\d{1,2}$/.test(prefix) && Number(prefix) <= 32;
  }

  /* Reads a whole number from a field, marking the field when it is wrong. */
  function readInt(el, label, min, max, problems) {
    el.classList.remove('invalid');
    const raw = el.value.trim();
    const value = Number(raw);

    if (raw === '' || !Number.isInteger(value) || value < min || value > max) {
      el.classList.add('invalid');
      problems.push(label + ' must be a whole number from ' + min + ' to ' + max + '.');
      return null;
    }

    return value;
  }

  function flag(el, bad, message, problems) {
    el.classList.toggle('invalid', !!bad);
    if (bad) problems.push(message);
  }

  /* ---------------- unsaved-commit marker ---------------- */

  function loadDirty() {
    try { return sessionStorage.getItem(DIRTY_KEY) === '1'; } catch (_) { return false; }
  }

  function setDirty(value) {
    state.dirty = value;
    try {
      if (value) sessionStorage.setItem(DIRTY_KEY, '1');
      else sessionStorage.removeItem(DIRTY_KEY);
    } catch (_) {}
    renderNotices();
  }

  state.dirty = loadDirty();

  /* ---------------- notices ---------------- */

  function renderNotices() {
    const box = clear($('notice'));
    const st = state.status;
    if (!st) return;

    const items = [];

    if (state.dirty) {
      items.push({
        kind: 'warn',
        title: 'Changes are saved but not live yet.',
        text: 'Press Commit to apply them to the firewall.',
        action: h('button', { class: 'btn sm primary', type: 'button', onClick: commit }, 'Commit now')
      });
    }

    const usable = state.links.filter((l) => l.enabled);

    if (!state.links.length) {
      items.push({ kind: '', title: 'No WAN links yet.', text: 'Start on the "WAN links" tab by adding each of your internet connections.' });
    } else if (st.enabled) {
      const down = usable.filter((l) => l.state === 'down');

      if (usable.length && down.length === usable.length) {
        items.push({ kind: 'bad', title: 'Every link is down.', text: 'No connection answers its checks, so traffic cannot leave until one comes back.' });
      } else if (down.length) {
        items.push({
          kind: 'warn',
          title: down.length === 1 ? '1 link is down.' : down.length + ' links are down.',
          text: down.map((l) => l.name).join(', ') + (down.length === 1 ? ' has' : ' have') + ' stopped answering. Traffic is using the other links.'
        });
      }
    } else {
      items.push({ kind: '', title: 'SD-WAN is switched off.', text: 'Your links are saved, but nothing is checked or routed until you turn it on and commit.' });
    }

    items.forEach((item) => {
      box.append(h('div', { class: 'notice' + (item.kind ? ' ' + item.kind : '') },
        icon(item.kind === 'bad' || item.kind === 'warn' ? 'i-alert' : 'i-info'),
        h('div', null, h('b', { text: item.title }), ' ', item.text, item.action ? h('div', { class: 'btn-row' }, item.action) : null)));
    });
  }

  /* ---------------- overview ---------------- */

  function renderStats(st) {
    $('stUp').textContent = num(st.links_up);
    $('stDown').textContent = num(st.links_down);
    $('stUnknown').textContent = num(st.links_unknown);
    $('stRules').textContent = num(st.rules_total);
  }

  function renderSwitch(st) {
    if (!state.switchBusy) $('swEnabled').checked = !!st.enabled;
    $('swHelp').textContent = st.enabled
      ? 'On. Links are checked and traffic follows your rules.'
      : 'Off. Needs at least one enabled WAN link.';
  }

  function stateBadge(link) {
    if (!link.enabled) return badge('Disabled', '');
    if (link.state === 'up') return badge('Up', 'ok');
    if (link.state === 'down') return badge('Down', 'bad');
    return badge('Not checked', '');
  }

  function renderHealth() {
    const body = clear($('healthBody'));

    if (!state.links.length) {
      body.append(emptyRow(7, 'No links yet.'));
      return;
    }

    state.links.forEach((l) => {
      const checked = l.enabled && l.last_check;

      body.append(h('tr', { class: l.enabled ? '' : 'is-off' },
        h('td', null, h('span', { class: 'state-dot ' + (l.enabled ? l.state : '') }), l.name),
        h('td', { class: 'mono nowrap', text: l.interface_name }),
        h('td', null,
          stateBadge(l),
          l.enabled && l.state === 'down' && l.last_error ? h('span', { class: 'sub', text: l.last_error }) : null),
        h('td', { class: 'num nowrap', text: checked && l.state !== 'down' ? ms(l.latency_ms) : '–' }),
        h('td', { class: 'num nowrap', text: checked && l.loss_pct !== null && l.loss_pct !== undefined ? l.loss_pct + ' %' : '–' }),
        h('td', { class: 'nowrap', text: l.enabled ? ago(l.last_check) : '–' }),
        h('td', { class: 'nowrap', text: l.last_change ? ago(l.last_change) : '–' })));
    });
  }

  /* ---------------- WAN links tab ---------------- */

  function linkConfigKey(list) {
    return JSON.stringify(list.map((l) => [
      l.id, l.name, l.interface_name, l.gateway, l.enabled, l.priority, l.weight, l.probe_target,
      l.probe_interval_secs, l.probe_timeout_secs, l.fail_threshold, l.recover_threshold, l.comment
    ]));
  }

  function renderLinks() {
    $('tabCountLinks').textContent = String(state.links.length);
    const body = clear($('linkBody'));

    if (!state.links.length) {
      body.append(emptyRow(8, 'No links yet. Press "Add link" to create the first one.'));
      return;
    }

    state.links.forEach((l) => {
      body.append(h('tr', { class: l.enabled ? '' : 'is-off' },
        h('td', null, l.name, l.comment ? h('span', { class: 'sub', text: l.comment }) : null),
        h('td', { class: 'mono nowrap', text: l.interface_name }),
        h('td', { class: 'mono nowrap', text: l.gateway || '–' }),
        h('td', { class: 'num', text: l.priority }),
        h('td', { class: 'num', text: l.weight }),
        h('td', null,
          h('span', { class: 'mono', text: l.probe_target }),
          h('span', { class: 'sub', text: 'every ' + l.probe_interval_secs + ' s · wait ' + l.probe_timeout_secs + ' s · down after ' + l.fail_threshold + ' misses' })),
        h('td', null, l.enabled ? badge('In use', 'ok') : badge('Off', '')),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => linkDialog(l) }, icon('i-edit'), 'Edit'),
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteLink(l) }, icon('i-trash'), 'Delete'))));
    });
  }

  async function deleteLink(l) {
    const ok = await confirmBox('Delete the link "' + l.name + '"? This cannot be undone.', { ok: 'Delete', danger: true, title: 'Delete link' });
    if (!ok) return;

    try {
      await api('/api/sdwan/links/' + encodeURIComponent(l.id), { method: 'DELETE' });
      toast('Link deleted. Press Commit to put it into effect.', 'ok');
      setDirty(true);
      await refresh(true);
      if (state.rulesLoaded) renderRules();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  function linkDialog(link) {
    const editing = !!link;
    const save = h('button', { class: 'btn primary', type: 'button' }, editing ? 'Save' : 'Add link');
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');

    const modal = openModal({
      title: editing ? 'Edit link: ' + link.name : 'Add WAN link',
      body: $('tplLink').content.cloneNode(true),
      footer: [cancel, save],
      wide: true
    });

    const root = modal.root;
    const f = (id) => root.querySelector('#' + id);

    const base = link || {
      name: '', interface_name: '', gateway: '', enabled: true, priority: 10, weight: 1,
      probe_target: '1.1.1.1', probe_interval_secs: 5, probe_timeout_secs: 2,
      fail_threshold: 3, recover_threshold: 2, comment: ''
    };

    f('lfName').value = base.name;
    f('lfInterface').value = base.interface_name;
    f('lfGateway').value = base.gateway || '';
    f('lfTarget').value = base.probe_target;
    f('lfPriority').value = base.priority;
    f('lfWeight').value = base.weight;
    f('lfInterval').value = base.probe_interval_secs;
    f('lfTimeout').value = base.probe_timeout_secs;
    f('lfFail').value = base.fail_threshold;
    f('lfRecover').value = base.recover_threshold;
    f('lfComment').value = base.comment || '';
    f('lfEnabled').checked = !!base.enabled;

    root.addEventListener('input', (ev) => { if (ev.target.classList) ev.target.classList.remove('invalid'); });
    root.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' && ev.target.tagName === 'INPUT' && ev.target.type !== 'checkbox') {
        ev.preventDefault();
        save.click();
      }
    });

    cancel.addEventListener('click', modal.close);

    save.addEventListener('click', async () => {
      modal.setError('');
      const problems = [];

      const name = f('lfName').value.trim();
      flag(f('lfName'), !name, 'Enter a name for the link.', problems);

      const iface = f('lfInterface').value.trim();
      flag(f('lfInterface'), !/^[A-Za-z0-9_.-]{1,15}$/.test(iface),
        'The interface name can use letters, digits, "_", "." and "-" (up to 15 characters), for example eth0.', problems);

      const gateway = f('lfGateway').value.trim();
      flag(f('lfGateway'), gateway !== '' && !isIPv4(gateway), 'The gateway must be an IPv4 address such as 203.0.113.1, or empty.', problems);

      const target = f('lfTarget').value.trim();
      flag(f('lfTarget'), !isIPv4(target), 'The address to ping must be an IPv4 address such as 1.1.1.1.', problems);

      const priority = readInt(f('lfPriority'), 'Priority', 1, 100, problems);
      const weight = readInt(f('lfWeight'), 'Weight', 1, 100, problems);
      const interval = readInt(f('lfInterval'), 'The check interval', 1, 3600, problems);
      const timeout = readInt(f('lfTimeout'), 'The reply wait', 1, 30, problems);
      const fail = readInt(f('lfFail'), 'The failed-check count', 1, 20, problems);
      const recover = readInt(f('lfRecover'), 'The good-check count', 1, 20, problems);

      if (problems.length) {
        modal.setError(problems[0]);
        return;
      }

      const comment = f('lfComment').value.trim();

      const body = {
        name,
        interface_name: iface,
        gateway: gateway || null,
        enabled: f('lfEnabled').checked,
        priority,
        weight,
        probe_target: target,
        probe_interval_secs: interval,
        probe_timeout_secs: timeout,
        fail_threshold: fail,
        recover_threshold: recover,
        comment: comment || null
      };

      try {
        await lock([save], () => api(
          editing ? '/api/sdwan/links/' + encodeURIComponent(link.id) : '/api/sdwan/links',
          { method: editing ? 'PUT' : 'POST', body }
        ));
      } catch (e) {
        modal.setError(errorText(e));
        return;
      }

      modal.close();
      toast((editing ? 'Link saved.' : 'Link added.') + ' Press Commit to put it into effect.', 'ok');
      setDirty(true);
      await refresh(true);
      if (state.rulesLoaded) renderRules();
    });
  }

  /* ---------------- traffic rules tab ---------------- */

  function linkName(id) {
    const l = state.links.find((x) => x.id === id);
    return l ? l : null;
  }

  function trafficLines(r) {
    const from = r.src_cidr || 'any source';
    const to = r.dst_cidr || 'any destination';
    const proto = r.protocol === 'any' ? 'any protocol' : String(r.protocol).toUpperCase();

    let ports = '';
    if (r.dport_start !== null && r.dport_start !== undefined && r.dport_end !== null && r.dport_end !== undefined) {
      ports = r.dport_start === r.dport_end
        ? ' · port ' + r.dport_start
        : ' · ports ' + r.dport_start + ' to ' + r.dport_end;
    }

    return [from + ' → ' + to, proto + ports];
  }

  function sendThrough(r) {
    if (r.strategy === 'link') {
      const l = linkName(r.link_id);
      return [l ? l.name : 'Unknown link', l ? l.interface_name : 'this link no longer exists'];
    }
    if (r.strategy === 'balance') return ['Best links', 'spread by weight'];
    return ['Fastest link', 'lowest delay and loss right now'];
  }

  function renderRules() {
    $('tabCountRules').textContent = String(state.rules.length);
    const body = clear($('ruleBody'));

    if (!state.rules.length) {
      body.append(emptyRow(7, 'No rules. All traffic uses the preferred links.'));
      return;
    }

    state.rules.forEach((r) => {
      const [line1, line2] = trafficLines(r);
      const [via, viaSub] = sendThrough(r);

      body.append(h('tr', { class: r.enabled ? '' : 'is-off' },
        h('td', { class: 'num', text: r.position }),
        h('td', null, r.name, r.comment ? h('span', { class: 'sub', text: r.comment }) : null),
        h('td', null, h('span', { class: 'mono', text: line1 }), h('span', { class: 'sub', text: line2 })),
        h('td', null, via, h('span', { class: 'sub', text: viaSub })),
        h('td', null, r.strategy === 'link'
          ? (r.on_link_down === 'block' ? badge('Block traffic', 'bad') : badge('Use other links', 'info'))
          : '–'),
        h('td', null, r.enabled ? badge('Active', 'ok') : badge('Off', '')),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm', type: 'button', onClick: () => ruleDialog(r) }, icon('i-edit'), 'Edit'),
          h('button', { class: 'btn sm danger', type: 'button', onClick: () => deleteRule(r) }, icon('i-trash'), 'Delete'))));
    });
  }

  async function loadRules() {
    state.rules = await api('/api/sdwan/rules');
    state.rulesLoaded = true;
    renderRules();
  }

  async function deleteRule(r) {
    const ok = await confirmBox('Delete the rule "' + r.name + '"?', { ok: 'Delete', danger: true, title: 'Delete rule' });
    if (!ok) return;

    try {
      await api('/api/sdwan/rules/' + encodeURIComponent(r.id), { method: 'DELETE' });
      toast('Rule deleted. Press Commit to put it into effect.', 'ok');
      setDirty(true);
      await Promise.all([loadRules(), refresh(true)]);
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  const STRATEGY_HELP = {
    link: 'Always use the chosen link while it is up.',
    balance: 'Spread new connections over the preferred links by their weight.',
    best_quality: 'Use whichever link has the lowest delay and packet loss at the moment.'
  };

  function ruleDialog(rule) {
    const editing = !!rule;
    const save = h('button', { class: 'btn primary', type: 'button' }, editing ? 'Save' : 'Add rule');
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');

    const modal = openModal({
      title: editing ? 'Edit rule: ' + rule.name : 'Add traffic rule',
      body: $('tplRule').content.cloneNode(true),
      footer: [cancel, save],
      wide: true
    });

    const root = modal.root;
    const f = (id) => root.querySelector('#' + id);

    const nextPosition = state.rules.length
      ? Math.min(9999, Math.max(...state.rules.map((r) => r.position)) + 10)
      : 100;

    const base = rule || {
      name: '', enabled: true, position: nextPosition, src_cidr: '', dst_cidr: '', protocol: 'any',
      dport_start: null, dport_end: null, strategy: 'link', link_id: null, on_link_down: 'fallback', comment: ''
    };

    const linkSelect = f('rfLink');
    state.links.forEach((l) => linkSelect.append(h('option', { value: String(l.id), text: l.name + ' (' + l.interface_name + ')' })));
    if (!state.links.length) {
      linkSelect.append(h('option', { value: '', text: 'No links yet' }));
      linkSelect.disabled = true;
    }

    f('rfName').value = base.name;
    f('rfPosition').value = base.position;
    f('rfSrc').value = base.src_cidr || '';
    f('rfDst').value = base.dst_cidr || '';
    f('rfProtocol').value = base.protocol;
    f('rfPortStart').value = base.dport_start === null || base.dport_start === undefined ? '' : base.dport_start;
    f('rfPortEnd').value = base.dport_end === null || base.dport_end === undefined ? '' : base.dport_end;
    f('rfStrategy').value = base.strategy;
    if (base.link_id !== null && base.link_id !== undefined) linkSelect.value = String(base.link_id);
    f('rfOnDown').value = base.on_link_down;
    f('rfComment').value = base.comment || '';
    f('rfEnabled').checked = !!base.enabled;

    function syncFields() {
      const protocol = f('rfProtocol').value;
      const strategy = f('rfStrategy').value;
      f('rfPortsBox').hidden = protocol !== 'tcp' && protocol !== 'udp';
      f('rfLinkBox').hidden = strategy !== 'link';
      f('rfDownBox').hidden = strategy !== 'link';
      f('rfStrategyHelp').textContent = STRATEGY_HELP[strategy] || '';
    }
    syncFields();

    f('rfProtocol').addEventListener('change', syncFields);
    f('rfStrategy').addEventListener('change', syncFields);
    root.addEventListener('input', (ev) => { if (ev.target.classList) ev.target.classList.remove('invalid'); });
    root.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' && ev.target.tagName === 'INPUT' && ev.target.type !== 'checkbox') {
        ev.preventDefault();
        save.click();
      }
    });

    cancel.addEventListener('click', modal.close);

    save.addEventListener('click', async () => {
      modal.setError('');
      const problems = [];

      const name = f('rfName').value.trim();
      flag(f('rfName'), !name, 'Enter a name for the rule.', problems);

      const position = readInt(f('rfPosition'), 'Position', 1, 9999, problems);

      const src = f('rfSrc').value.trim();
      flag(f('rfSrc'), src !== '' && !isNetwork(src), 'The "from" network must look like 192.168.10.0/24 (or a single address), or be empty.', problems);

      const dst = f('rfDst').value.trim();
      flag(f('rfDst'), dst !== '' && !isNetwork(dst), 'The "to" network must look like 8.8.8.0/24 (or a single address), or be empty.', problems);

      const protocol = f('rfProtocol').value;
      const strategy = f('rfStrategy').value;

      let portStart = null;
      let portEnd = null;

      if (protocol === 'tcp' || protocol === 'udp') {
        const a = f('rfPortStart').value.trim();
        const b = f('rfPortEnd').value.trim();

        f('rfPortStart').classList.remove('invalid');
        f('rfPortEnd').classList.remove('invalid');

        if (a !== '' || b !== '') {
          const ports = [Number(a), Number(b)];
          const good = a !== '' && b !== '' && ports.every((p) => Number.isInteger(p) && p >= 1 && p <= 65535);

          if (!good) {
            f('rfPortStart').classList.add('invalid');
            f('rfPortEnd').classList.add('invalid');
            problems.push('Enter both a first and a last port (1 to 65535), or leave both empty.');
          } else if (ports[0] > ports[1]) {
            f('rfPortStart').classList.add('invalid');
            problems.push('The first port cannot be higher than the last port.');
          } else {
            portStart = ports[0];
            portEnd = ports[1];
          }
        }
      }

      let linkId = null;

      if (strategy === 'link') {
        const chosen = Number(linkSelect.value);
        if (!state.links.length || !Number.isInteger(chosen) || linkSelect.value === '') {
          linkSelect.classList.add('invalid');
          problems.push('Add a WAN link first, then choose it here.');
        } else {
          linkId = chosen;
        }
      }

      if (problems.length) {
        modal.setError(problems[0]);
        return;
      }

      const comment = f('rfComment').value.trim();

      const body = {
        name,
        enabled: f('rfEnabled').checked,
        position,
        src_cidr: src || null,
        dst_cidr: dst || null,
        protocol,
        dport_start: portStart,
        dport_end: portEnd,
        strategy,
        link_id: linkId,
        on_link_down: strategy === 'link' ? f('rfOnDown').value : 'fallback',
        comment: comment || null
      };

      try {
        await lock([save], () => api(
          editing ? '/api/sdwan/rules/' + encodeURIComponent(rule.id) : '/api/sdwan/rules',
          { method: editing ? 'PUT' : 'POST', body }
        ));
      } catch (e) {
        modal.setError(errorText(e));
        return;
      }

      modal.close();
      toast((editing ? 'Rule saved.' : 'Rule added.') + ' Press Commit to put it into effect.', 'ok');
      setDirty(true);
      await Promise.all([loadRules(), refresh(true)]);
    });
  }

  /* ---------------- preview tab ---------------- */

  async function loadPreview() {
    try {
      const p = await api('/api/sdwan/generate');

      if (!p.enabled) {
        $('pvNft').textContent = 'SD-WAN is switched off, so a commit would apply nothing.';
        $('pvRouting').textContent = 'SD-WAN is switched off, so a commit would apply nothing.';
        return;
      }

      $('pvNft').textContent = p.nft && p.nft.trim() ? p.nft : '(nothing)';
      $('pvRouting').textContent = p.routing && p.routing.trim() ? p.routing : '(nothing)';
    } catch (e) {
      $('pvNft').textContent = errorText(e);
      $('pvRouting').textContent = '';
    }
  }

  /* ---------------- actions ---------------- */

  async function commit() {
    const ok = await confirmBox(
      'Apply the saved SD-WAN configuration now? Traffic routing changes immediately. If the new setup cannot be applied, the previous one is kept.',
      { ok: 'Commit', title: 'Commit SD-WAN' }
    );
    if (!ok) return;

    try {
      const result = await lock([$('btnCommit')], () => api('/api/sdwan/commit', { method: 'POST' }));
      toast(result && result.message ? result.message : 'Committed.', 'ok');
      setDirty(false);
    } catch (e) {
      toast(failText(e), 'bad');
    }

    await refresh(true);
    if (state.tab === 'preview') loadPreview();
  }

  async function rollback() {
    const ok = await confirmBox(
      'Go back to the previous committed SD-WAN configuration? This changes traffic routing immediately.',
      { ok: 'Roll back', danger: true, title: 'Roll back SD-WAN' }
    );
    if (!ok) return;

    try {
      const result = await lock([$('btnRollback')], () => api('/api/sdwan/rollback', { method: 'POST' }));
      toast(result && result.message ? result.message : 'Rolled back.', 'ok');
    } catch (e) {
      toast(failText(e), 'bad');
    }

    await Promise.all([refresh(true), loadRules().catch(() => {})]);
  }

  async function probeNow() {
    try {
      const r = await lock([$('btnProbe')], () => api('/api/sdwan/probe', { method: 'POST' }));

      if (!r.probed) {
        toast(state.status && state.status.enabled
          ? 'There are no enabled links to check.'
          : 'SD-WAN is switched off, so links are not checked. Turn it on and commit first.', 'warn');
      } else {
        toast('Checked ' + r.probed + (r.probed === 1 ? ' link.' : ' links.') + (r.changed ? ' ' + r.changed + ' changed state.' : ''), 'ok');
      }
    } catch (e) {
      toast(errorText(e), 'bad');
    }

    await refresh(true);
  }

  /* ---------------- polling ---------------- */

  function applyStatus(st, force) {
    state.status = st;
    state.links = st.links || [];

    renderStats(st);
    renderSwitch(st);
    renderHealth();
    renderNotices();

    const key = linkConfigKey(state.links);
    if (force || key !== state.linkKey) {
      state.linkKey = key;
      renderLinks();
      if (state.rulesLoaded) renderRules();
    }
  }

  async function refresh(force) {
    try {
      applyStatus(await api('/api/sdwan/status'), force === true);
      live(true, 'Live');
    } catch (e) {
      live(false, 'Connection lost');
    }
  }

  /* ---------------- wiring ---------------- */

  tabs($('page'), 'sdwan', (name) => {
    state.tab = name;
    if (name === 'preview') loadPreview();
    if (name === 'rules') loadRules().catch((e) => toast(errorText(e), 'bad'));
  });

  $('swEnabled').addEventListener('change', async () => {
    const want = $('swEnabled').checked;
    state.switchBusy = true;

    try {
      await api('/api/sdwan/settings', { method: 'PUT', body: { enabled: want } });
      toast('SD-WAN ' + (want ? 'switched on' : 'switched off') + '. Press Commit to put it into effect.', 'ok');
      setDirty(true);
    } catch (e) {
      $('swEnabled').checked = !want;
      toast(errorText(e), 'bad');
    } finally {
      state.switchBusy = false;
    }

    await refresh(true);
  });

  $('btnCommit').addEventListener('click', commit);
  $('btnRollback').addEventListener('click', rollback);
  $('btnProbe').addEventListener('click', probeNow);
  $('btnAddLink').addEventListener('click', () => linkDialog(null));
  $('btnAddRule').addEventListener('click', () => ruleDialog(null));
  $('btnPvRefresh').addEventListener('click', loadPreview);

  btnRefresh.addEventListener('click', async () => {
    btnRefresh.classList.add('spin');
    await refresh(true);
    if (state.tab === 'rules') await loadRules().catch(() => {});
    if (state.tab === 'preview') await loadPreview();
    btnRefresh.classList.remove('spin');
  });

  loadRules().catch(() => {});
  every(refresh, POLL_MS);
})();

