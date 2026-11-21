/* Page frame and helpers for the configuration pages (Intrusion Detection, SD-WAN).
   Load after /js/core/api.js. Pages call Shell.mount(...) once, then use the helpers. */
(function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const THEME_KEY = 'iqsoft.theme';

  /* ---------------- navigation (keep in step with dashboard.html) ---------------- */

  const NAV = [
    { id: 'dashboard', label: 'Dashboard', icon: 'i-home', href: '/html/dashboard.html' },
    { id: 'network', label: 'Network', icon: 'i-network', href: '/html/network.html', chev: 'down' },
    { id: 'sdwan', label: 'SD-WAN', icon: 'i-route', href: '/html/sdwan.html' },
    { id: 'firewall', label: 'Firewall Rules', icon: 'i-shield', href: '/html/firewall.html', chev: 'right' },  
    { id: 'nat', label: 'NAT / Port Forwarding', icon: 'i-swap', href: '/html/nat.html', chev: 'right' },
    { id: 'threat', label: 'Threat Intelligence', icon: 'i-target', href: '/html/threat.html', chev: 'right' },
    { id: 'ids', label: 'Intrusion Detection', icon: 'i-pulse', href: '/html/ids.html', chev: 'right' },
    { id: 'geoip', label: 'GeoIP Blocking', icon: 'i-globe', href: '/html/geoip.html', chev: 'right' },
    { id: 'antivirus', label: 'Antivirus', icon: 'i-shield-check', href: '/html/antivirus.html', chev: 'right' },
    { id: 'dnsfilter', label: 'DNS Filter', icon: 'i-globe', href: '/html/dnsfilter.html', chev: 'right' },
    { id: 'sni', label: 'App Control', icon: 'i-ban', href: '/html/sni.html', chev: 'right' },
    { id: 'vpn', label: 'VPN', icon: 'i-key', href: '/html/vpn.html', chev: 'right' },
    { id: 'monitoring', label: 'Monitoring', icon: 'i-bars', href: '/html/monitoring.html', chev: 'right' },
    { id: 'logs', label: 'Logs', icon: 'i-file', href: '/html/logs.html' },
    { id: 'reports', label: 'Reports', icon: 'i-pie', href: '/html/reports.html' },	  
    { id: 'system', label: 'System', icon: 'i-gear', href: '/html/system.html', chev: 'right' }
  ];

  /* ---------------- icons ---------------- */

  const SPRITE =
    '<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false"><defs>' +
    '<symbol id="i-home" viewBox="0 0 24 24"><path d="M3 11l9-8 9 8v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1V11z"/></symbol>' +
    '<symbol id="i-network" viewBox="0 0 24 24"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="18" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="M12 7.5v4M12 11.5l-5.5 4.5M12 11.5l5.5 4.5"/></symbol>' +
    '<symbol id="i-route" viewBox="0 0 24 24"><circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="M7.5 6H14a3 3 0 0 1 0 6h-4a3 3 0 0 0 0 6h6.5"/></symbol>' +
    '<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/></symbol>' +
    '<symbol id="i-shield-check" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></symbol>' +
    '<symbol id="i-swap" viewBox="0 0 24 24"><path d="M4 8h14l-3-3M20 16H6l3 3"/></symbol>' +
    '<symbol id="i-target" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3.5"/><path d="M12 1.5v3M12 19.5v3M1.5 12h3M19.5 12h3"/></symbol>' +
    '<symbol id="i-pulse" viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></symbol>' +
    '<symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/></symbol>' +
    '<symbol id="i-bars" viewBox="0 0 24 24"><path d="M6 20V10M12 20V4M18 20v-7"/></symbol>' +
    '<symbol id="i-file" viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h6"/></symbol>' +
    '<symbol id="i-pie" viewBox="0 0 24 24"><path d="M12 3a9 9 0 1 0 9 9h-9V3z"/><path d="M15 3.5A9 9 0 0 1 20.5 9H15z"/></symbol>' +
    '<symbol id="i-gear" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="7"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9L7 7M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1"/></symbol>' +
    '<symbol id="i-chev-right" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></symbol>' +
    '<symbol id="i-chev-down" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></symbol>' +
    '<symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M4.9 19.1l1.8-1.8M17.3 6.7l1.8-1.8"/></symbol>' +
    '<symbol id="i-moon" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/></symbol>' +
    '<symbol id="i-refresh" viewBox="0 0 24 24"><path d="M20 11a8 8 0 0 0-14.5-4M4 4v4h4M4 13a8 8 0 0 0 14.5 4M20 20v-4h-4"/></symbol>' +
    '<symbol id="i-logout" viewBox="0 0 24 24"><path d="M9 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h4M16 8l4 4-4 4M20 12H9"/></symbol>' +
    '<symbol id="i-ban" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></symbol>' +
    '<symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18h.01"/></symbol>' +
    '<symbol id="i-list" viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></symbol>' +
    '<symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3.5 3.5 3.5 14.5 0 18M12 3c-3.5 3.5-3.5 14.5 0 18"/></symbol>' +
    '<symbol id="i-crosshair" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2"/><path d="M12 1.5v4M12 18.5v4M1.5 12h4M18.5 12h4"/></symbol>' +
    '<symbol id="i-expand" viewBox="0 0 24 24"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></symbol>' +
    '<symbol id="i-menu" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></symbol>' +
    '<symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>' +
    '<symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></symbol>' +
    '<symbol id="i-trash" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6"/></symbol>' +
    '<symbol id="i-edit" viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16v4zM13 7l4 4"/></symbol>' +
    '<symbol id="i-check" viewBox="0 0 24 24"><path d="M5 12l5 5L20 7"/></symbol>' +
    '<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/></symbol>' +
    '<symbol id="i-undo" viewBox="0 0 24 24"><path d="M9 14L4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3"/></symbol>' +
    '<symbol id="i-play" viewBox="0 0 24 24"><path d="M7 4l13 8-13 8z"/></symbol>' +
    '<symbol id="i-upload" viewBox="0 0 24 24"><path d="M12 16V4M6 10l6-6 6 6M4 20h16"/></symbol>' +
    '<symbol id="i-eye" viewBox="0 0 24 24"><path d="M1.5 12S5.5 5 12 5s10.5 7 10.5 7-4 7-10.5 7S1.5 12 1.5 12z"/><circle cx="12" cy="12" r="3"/></symbol>' +
    '</defs></svg>';

  const WAVE =
    '<svg class="bg-wave" viewBox="0 0 1200 420" preserveAspectRatio="none" aria-hidden="true" focusable="false">' +
    '<defs>' +
    '<linearGradient id="bwA" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8fd0ff" stop-opacity="0.75"/><stop offset="1" stop-color="#4aa3ff" stop-opacity="0.15"/></linearGradient>' +
    '<linearGradient id="bwB" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#ffffff" stop-opacity="0"/><stop offset="1" stop-color="#7cc4ff" stop-opacity="0.55"/></linearGradient>' +
    '</defs>' +
    '<path d="M1200 0V250C1060 300 980 170 820 190C690 205 640 110 520 70C610 40 700 20 780 0Z" fill="url(#bwA)"/>' +
    '<path d="M1200 0V150C1100 190 1020 90 900 110C820 122 780 70 720 40C760 24 800 10 840 0Z" fill="url(#bwB)"/>' +
    '</svg>';

  const LOGO =
    '<div class="logo">' +
    '<svg class="logo-shield" viewBox="0 0 64 72" aria-hidden="true"><path d="M32 4 7 14v18c0 17 10.5 29.5 25 36 14.5-6.5 25-19 25-36V14L32 4Z" fill="#e8f2fe" stroke="#0a7cf5" stroke-width="5" stroke-linejoin="round"/><path d="m22 35 8 8 14-16" fill="none" stroke="#0a7cf5" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
    '<div class="logo-text"><img class="logo-img" src="/img/iqsoft-logo.png" alt="IQSOFT"><div class="logo-sub">Firewall OS</div></div>' +
    '</div>';

  const APPLIANCE =
    '<svg class="side-art" viewBox="0 0 240 186" aria-hidden="true">' +
    '<defs>' +
    '<radialGradient id="apFloor" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="#2b95ff" stop-opacity="0.45"/><stop offset="1" stop-color="#2b95ff" stop-opacity="0"/></radialGradient>' +
    '<linearGradient id="apTop" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#56637a"/><stop offset="1" stop-color="#2a3345"/></linearGradient>' +
    '<linearGradient id="apFront" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2f394b"/><stop offset="0.5" stop-color="#1c2331"/><stop offset="1" stop-color="#10151f"/></linearGradient>' +
    '<linearGradient id="apSide" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#1a2130"/><stop offset="1" stop-color="#0b0f17"/></linearGradient>' +
    '<radialGradient id="apLed" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="#e3f3ff"/><stop offset="0.45" stop-color="#4db0ff"/><stop offset="1" stop-color="#0a64d8"/></radialGradient>' +
    '<linearGradient id="apGlass" x1="0" y1="0" x2="0.8" y2="1"><stop offset="0" stop-color="#bfe2ff" stop-opacity="0.85"/><stop offset="0.55" stop-color="#4aa3ff" stop-opacity="0.6"/><stop offset="1" stop-color="#0a5fd6" stop-opacity="0.75"/></linearGradient>' +
    '<linearGradient id="apSheen" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffffff" stop-opacity="0.65"/><stop offset="1" stop-color="#ffffff" stop-opacity="0"/></linearGradient>' +
    '<radialGradient id="apGlow" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="#4db0ff" stop-opacity="0.7"/><stop offset="1" stop-color="#4db0ff" stop-opacity="0"/></radialGradient>' +
    '</defs>' +
    '<ellipse cx="120" cy="166" rx="104" ry="13" fill="url(#apFloor)"/>' +
    '<ellipse cx="116" cy="164" rx="78" ry="6" fill="#0a1a33" opacity="0.28"/>' +
    '<polygon points="40,122 200,122 216,108 56,108" fill="url(#apTop)"/>' +
    '<polygon points="200,122 216,108 216,146 200,160" fill="url(#apSide)"/>' +
    '<rect x="40" y="122" width="160" height="38" rx="2" fill="url(#apFront)"/>' +
    '<line x1="40" y1="122.5" x2="200" y2="122.5" stroke="#9fb4d1" stroke-opacity="0.7" stroke-width="1"/>' +
    '<line x1="200" y1="122" x2="216" y2="108" stroke="#9fb4d1" stroke-opacity="0.35" stroke-width="1"/>' +
    '<rect x="48" y="160" width="14" height="4" rx="1" fill="#0b0f17"/>' +
    '<rect x="178" y="160" width="14" height="4" rx="1" fill="#0b0f17"/>' +
    '<ellipse cx="128" cy="115" rx="52" ry="6" fill="url(#apGlow)"/>' +
    '<text x="52" y="145" font-family="Arial, Helvetica, sans-serif" font-size="12" font-weight="700" letter-spacing="1.2" fill="#d6e8ff">IQSOFT</text>' +
    '<g fill="#0a0e15" stroke="#4a586f" stroke-width="0.8"><rect x="108" y="133" width="9" height="9" rx="1"/><rect x="119" y="133" width="9" height="9" rx="1"/><rect x="130" y="133" width="9" height="9" rx="1"/><rect x="141" y="133" width="9" height="9" rx="1"/></g>' +
    '<g class="led-halo" fill="#3aa0ff" opacity="0.3"><circle cx="164" cy="138" r="4.6"/><circle cx="173" cy="138" r="4.6"/><circle cx="182" cy="138" r="4.6"/><circle cx="191" cy="138" r="4.6"/></g>' +
    '<g fill="url(#apLed)"><circle cx="164" cy="138" r="2.8"/><circle cx="173" cy="138" r="2.8"/><circle cx="182" cy="138" r="2.8"/><circle cx="191" cy="138" r="2.8"/></g>' +
    '<g class="shield-float">' +
    '<ellipse cx="120" cy="104" rx="30" ry="4.5" fill="#4db0ff" opacity="0.35"/>' +
    '<path d="M120 10 L162 25 V52 C162 75 145 90 120 99 C95 90 78 75 78 52 V25 Z" fill="url(#apGlass)" stroke="#ffffff" stroke-opacity="0.9" stroke-width="2.2" stroke-linejoin="round"/>' +
    '<path d="M120 19 L153 31 V52 C153 70 140 82 120 90 C100 82 87 70 87 52 V31 Z" fill="none" stroke="#ffffff" stroke-opacity="0.4" stroke-width="1.5"/>' +
    '<path d="M86 30 L120 17 V58 C104 56 90 48 86 30 Z" fill="url(#apSheen)" opacity="0.55"/>' +
    '<path d="M102 54 L115 67 L141 39" fill="none" stroke="#ffffff" stroke-width="7.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</g></svg>';

  /* ---------------- small DOM helpers ---------------- */

  function icon(name, cls) {
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'ic' + (cls ? ' ' + cls : ''));
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(NS, 'use');
    use.setAttribute('href', '#' + name);
    svg.append(use);
    return svg;
  }

  /* h('div', { class: 'x', onClick: fn }, child, 'text') builds an element without innerHTML,
     so anything that came from the server is shown as plain text. */
  function h(tag, props, ...kids) {
    const e = document.createElement(tag);

    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null || value === false) continue;

        if (key === 'class') e.className = value;
        else if (key === 'text') e.textContent = value;
        else if (key === 'value') e.value = value;
        else if (key === 'checked' || key === 'disabled' || key === 'hidden' || key === 'selected') e[key] = !!value;
        else if (key.length > 2 && key.startsWith('on') && typeof value === 'function') {
          e.addEventListener(key.slice(2).toLowerCase(), value);
        } else e.setAttribute(key, value === true ? '' : String(value));
      }
    }

    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }

    return e;
  }

  function clear(node) {
    node.replaceChildren();
    return node;
  }

  function store(key, value) {
    try { localStorage.setItem(key, value); } catch (_) {}
  }

  function load(key) {
    try { return localStorage.getItem(key); } catch (_) { return null; }
  }

  /* ---------------- formatting ---------------- */

  function toDate(ts) {
    return new Date(ts > 1e12 ? ts : ts * 1000);
  }

  function fmtTime(ts) {
    if (!ts) return '–';
    return toDate(ts).toLocaleString();
  }

  function fmtClock(ts) {
    if (!ts) return '–';
    return toDate(ts).toTimeString().slice(0, 8);
  }

  function ago(ts) {
    if (!ts) return 'never';
    const s = Math.floor(Date.now() / 1000) - Math.floor(ts > 1e12 ? ts / 1000 : ts);
    if (s < 0) return fmtTime(ts);
    if (s < 5) return 'just now';
    if (s < 60) return s + ' s ago';
    if (s < 3600) return Math.floor(s / 60) + ' min ago';
    if (s < 86400) return Math.floor(s / 3600) + ' h ago';
    return Math.floor(s / 86400) + ' d ago';
  }

  function num(n) {
    if (n === null || n === undefined || n === '') return '–';
    const v = Number(n);
    return Number.isFinite(v) ? v.toLocaleString() : '–';
  }

  function ms(n) {
    if (n === null || n === undefined) return '–';
    const v = Number(n);
    return Number.isFinite(v) ? v.toFixed(1) + ' ms' : '–';
  }

  function errorText(e) {
    return e && e.message ? e.message : String(e);
  }

  /* ---------------- messages ---------------- */

  function toast(message, kind, duration) {
    const box = document.getElementById('toasts');
    if (!box) return;

    const kindName = kind || 'info';
    const t = h('div', { class: 'toast ' + kindName, role: kindName === 'bad' ? 'alert' : 'status' }, String(message));
    box.append(t);

    const life = duration || (kindName === 'bad' ? 9000 : 4500);
    const remove = () => t.remove();
    t.addEventListener('click', remove);
    setTimeout(remove, life);
  }

  /* ---------------- dialogs ---------------- */

  /* openModal({ title, body: Node, footer: [Node], wide }) -> { root, close, setError } */
  function openModal(opts) {
    const previous = document.activeElement;
    const back = h('div', { class: 'modal-back', role: 'dialog', 'aria-modal': 'true' });
    const box = h('div', { class: 'modal' + (opts.wide ? ' wide' : '') });
    const closeBtn = h('button', { class: 'modal-x', type: 'button', 'aria-label': 'Close' }, icon('i-x'));
    let errorBox = null;

    box.append(h('div', { class: 'modal-h' }, h('h3', { text: opts.title || '' }), closeBtn));
    if (opts.body) box.append(opts.body);
    if (opts.footer && opts.footer.length) box.append(h('div', { class: 'modal-foot' }, opts.footer));
    back.append(box);
    document.body.append(back);

    function onKey(ev) {
      if (ev.key === 'Escape') close();
    }

    function close() {
      document.removeEventListener('keydown', onKey);
      back.remove();
      if (previous && previous.focus) previous.focus();
      if (opts.onClose) opts.onClose();
    }

    function setError(message) {
      if (errorBox) errorBox.remove();
      errorBox = null;
      if (!message) return;
      errorBox = h('div', { class: 'form-error', role: 'alert', text: message });
      const foot = box.querySelector('.modal-foot');
      if (foot) box.insertBefore(errorBox, foot);
      else box.append(errorBox);
      errorBox.scrollIntoView({ block: 'nearest' });
    }

    closeBtn.addEventListener('click', close);
    document.addEventListener('keydown', onKey);

    const first = box.querySelector('input:not([type=hidden]):not(:disabled), select:not(:disabled), textarea:not(:disabled)');
    if (first) first.focus();

    return { root: box, close, setError };
  }

  /* confirmBox('Delete this?', { ok: 'Delete', danger: true }) -> Promise<boolean> */
  function confirmBox(message, opts) {
    const o = opts || {};

    return new Promise((resolve) => {
      let answered = false;
      const done = (value) => {
        if (answered) return;
        answered = true;
        modal.close();
        resolve(value);
      };

      const yes = h('button', { class: 'btn ' + (o.danger ? 'danger' : 'primary'), type: 'button', onClick: () => done(true) }, o.ok || 'OK');
      const no = h('button', { class: 'btn', type: 'button', onClick: () => done(false) }, 'Cancel');

      const modal = openModal({
        title: o.title || 'Please confirm',
        body: h('p', { class: 'card-sub', text: message }),
        footer: [no, yes],
        onClose: () => { if (!answered) { answered = true; resolve(false); } }
      });

      yes.focus();
    });
  }

  /* ---------------- buttons and polling ---------------- */

  /* Shows a spinner on the button while the work runs, and always restores it. */
  async function busy(button, work) {
    if (button) {
      button.classList.add('busy');
      button.disabled = true;
    }
    try {
      return await work();
    } finally {
      if (button) {
        button.classList.remove('busy');
        button.disabled = false;
      }
    }
  }

  /* Runs the function now and then every `ms` milliseconds, but not while the tab is hidden. */
  function every(fn, ms) {
    let running = false;

    async function tick() {
      if (running || document.hidden) return;
      running = true;
      try { await fn(); } catch (_) {} finally { running = false; }
    }

    tick();
    const timer = setInterval(tick, ms);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });

    return () => clearInterval(timer);
  }

  /* Tabs: buttons <button class="tab" data-tab="x"> and panels <section class="tab-panel" data-panel="x"> */
  function tabs(root, key, onChange) {
    const buttons = Array.from(root.querySelectorAll('.tab[data-tab]'));
    const panels = Array.from(root.querySelectorAll('.tab-panel[data-panel]'));
    const storeKey = 'iqsoft.tab.' + key;

    function show(name) {
      buttons.forEach((b) => b.classList.toggle('on', b.dataset.tab === name));
      panels.forEach((p) => { p.hidden = p.dataset.panel !== name; });
      store(storeKey, name);
      if (onChange) onChange(name);
    }

    buttons.forEach((b) => b.addEventListener('click', () => show(b.dataset.tab)));

    const saved = load(storeKey);
    const start = buttons.some((b) => b.dataset.tab === saved) ? saved : (buttons[0] && buttons[0].dataset.tab);
    if (start) show(start);

    return { show };
  }

  /* The "live" light in the page header. */
  function live(ok, text) {
    const dot = document.getElementById('liveDot');
    const label = document.getElementById('liveText');
    if (dot) dot.className = 'dot ' + (ok ? 'ok' : 'bad');
    if (label) label.textContent = text;
  }

  /* ---------------- theme ---------------- */

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  applyTheme(load(THEME_KEY) === 'dark' ? 'dark' : 'light');

  /* ---------------- the page frame ---------------- */

  function buildNav(active) {
    const nav = h('nav', { class: 'nav' });

    NAV.forEach((item) => {
      const link = h('a', { class: 'nav-item' + (item.id === active ? ' active' : ''), href: item.href || '#' },
        icon(item.icon), h('span', { text: item.label }));

      if (item.chev) link.append(icon(item.chev === 'down' ? 'i-chev-down' : 'i-chev-right', 'chev'));

      if (!item.href) {
        link.title = 'Coming soon';
        link.addEventListener('click', (ev) => ev.preventDefault());
      } else {
        link.addEventListener('click', () => document.body.classList.remove('nav-open'));
      }

      nav.append(link);
    });

    return nav;
  }

  async function loadUser() {
    try {
      const me = await api('/api/auth/me');
      if (!me || !me.username) return;
      const role = String(me.role || '');
      document.querySelector('.user-text b').textContent = me.username;
      document.querySelector('.user-text span').textContent = role.charAt(0).toUpperCase() + role.slice(1);
      document.querySelector('.avatar').textContent = me.username.charAt(0).toUpperCase();
    } catch (_) {}
  }

  /* mount({ active, title, subtitle, content }) -> { tools } or null when not signed in.
     `content` is an element that is moved under the page heading. */
  function mount(opts) {
    if (!Auth.guard()) return null;

    document.body.classList.add('dash-body');
    document.body.insertAdjacentHTML('afterbegin', WAVE + SPRITE);

    const app = h('div', { class: 'app' });

    const side = h('aside', { class: 'sidebar' });
    side.insertAdjacentHTML('afterbegin', LOGO);
    side.append(buildNav(opts.active));

    const foot = h('div', { class: 'side-foot' });
    foot.insertAdjacentHTML('afterbegin', APPLIANCE);
    foot.append(h('div', { class: 'side-name', text: 'IQSOFT Firewall OS' }), h('div', { class: 'side-ver', text: 'v1.0.0' }));
    side.append(foot);

    const menuBtn = h('button', { class: 'icon-round menu-btn', type: 'button', 'aria-label': 'Open menu' }, icon('i-menu'));
    const fsBtn = h('button', { class: 'icon-round', type: 'button', 'aria-label': 'Enter full screen', title: 'Full screen' }, icon('i-expand'));
    const themeBtn = h('button', { class: 'icon-round', type: 'button', 'aria-label': 'Switch light or dark theme' }, icon('i-sun', 'theme-sun'), icon('i-moon', 'theme-moon'));
    const logoutBtn = h('button', { class: 'icon-plain', type: 'button', 'aria-label': 'Sign out', title: 'Sign out' }, icon('i-logout'));

    const topbar = h('header', { class: 'topbar' },
      menuBtn,
      h('div', { class: 'top-actions' },
        fsBtn,
        themeBtn,
        h('div', { class: 'user' },
          h('div', { class: 'avatar', text: 'A' }),
          h('div', { class: 'user-text' }, h('b', { text: 'admin' }), h('span', { text: 'Administrator' })),
          logoutBtn)));

    const tools = h('div', { class: 'head-tools' },
      h('div', { class: 'live' }, h('span', { id: 'liveDot', class: 'dot' }), h('span', { id: 'liveText', text: 'Connecting…' })));

    const head = h('div', { class: 'head' },
      h('div', { class: 'head-title' }, h('h1', { text: opts.title }), h('p', { text: opts.subtitle || '' })),
      tools);

    const main = h('main', { class: 'main' }, topbar, head);

    if (opts.content) {
      opts.content.hidden = false;
      main.append(opts.content);
    }

    app.append(side, main);

    const scrim = h('div', { id: 'navScrim', class: 'scrim' });
    document.body.append(app, scrim, h('div', { id: 'toasts', class: 'toasts', 'aria-live': 'polite' }));

    document.title = opts.title + ' | IQSOFT Firewall OS';

    themeBtn.addEventListener('click', () => {
      const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      store(THEME_KEY, next);
    });

    logoutBtn.addEventListener('click', logout);

    if (document.fullscreenEnabled) {
      fsBtn.addEventListener('click', () => {
        if (document.fullscreenElement) document.exitFullscreen();
        else document.documentElement.requestFullscreen().catch(() => {});
      });
      document.addEventListener('fullscreenchange', () => {
        const on = !!document.fullscreenElement;
        fsBtn.setAttribute('aria-label', on ? 'Exit full screen' : 'Enter full screen');
        fsBtn.title = on ? 'Exit full screen' : 'Full screen';
      });
    } else {
      fsBtn.hidden = true;
    }

    const closeNav = () => document.body.classList.remove('nav-open');
    menuBtn.addEventListener('click', () => document.body.classList.toggle('nav-open'));
    scrim.addEventListener('click', closeNav);
    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeNav(); });

    loadUser();

    return { tools };
  }

  window.Shell = {
    mount, h, icon, clear, toast, openModal, confirmBox, busy, every, tabs, live,
    fmtTime, fmtClock, ago, num, ms, errorText
  };
})()
