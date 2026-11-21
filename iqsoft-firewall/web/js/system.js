(function () {
  'use strict';

  const { h, icon, clear, toast, confirmBox, busy, every, tabs, live, errorText, fmtTime } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'system',
    title: 'System',
    subtitle: 'Version, account, backup and restore, power',
    content: $('page')
  });
  if (!frame) return;

  const MIN_PASSWORD = 10;

  const state = { info: null, me: null, forbidden: false, uptime: null };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' }, icon('i-refresh'));
  frame.tools.append(btnRefresh);

  const has = (v) => v !== null && v !== undefined && v !== '';

  function apiMessage(e) {
    if (e && e.data && typeof e.data === 'object') {
      if (e.data.message) return e.data.message;
      if (e.data.error) return e.data.error;
    }
    return errorText(e);
  }

  function showNotice(box, kind, text) {
    clear(box);
    if (text) box.append(h('div', { class: 'notice ' + kind }, text));
  }

  function fmtBytes(n) {
    let v = Number(n) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + ' ' + u[i];
  }

  function fmtUptime(sec) {
    if (!has(sec)) return '–';
    const d = Math.floor(sec / 86400);
    const hr = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + 'd ' + hr + 'h ' + m + 'm';
    if (hr > 0) return hr + 'h ' + m + 'm';
    return m + 'm';
  }

  function stamp() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
  }

  async function authed(path, options) {
    const opts = options || {};
    const headers = Object.assign({}, opts.headers || {}, { Authorization: 'Bearer ' + (Auth.token() || '') });
    const res = await fetch(path, { method: opts.method || 'GET', headers, body: opts.body });

    if (res.status === 401) {
      Auth.clear();
      location.replace('/html/login.html');
      throw new Error('Authentication required');
    }

    return res;
  }

  async function failure(res) {
    let message = 'Request failed (' + res.status + ')';
    try {
      const data = await res.json();
      if (data && data.error) message = data.error;
    } catch (_) {}
    const err = new Error(message);
    err.status = res.status;
    return err;
  }

  function renderInfo() {
    const body = clear($('infoBody'));
    const i = state.info;

    if (!i) {
      body.append(h('tr', null, h('td', { class: 'empty-row', text: state.forbidden ? 'Only administrators can read system information.' : 'System information is not available.' })));
      return;
    }

    const rows = [
      ['Product', i.product],
      ['Version', i.version],
      ['Host name', i.hostname],
      ['Operating system', i.os],
      ['Kernel', i.kernel],
      ['Architecture', i.arch],
      ['Uptime', fmtUptime(state.uptime)],
      ['System time', has(i.server_time) ? fmtTime(i.server_time) : null],
      ['Configuration database', has(i.database_bytes) ? fmtBytes(i.database_bytes) : null],
      ['Signed in as', state.me ? state.me.username + ' (' + state.me.role + ')' : null]
    ];

    rows.forEach(([label, value]) => {
      body.append(h('tr', null,
        h('td', null, h('b', { text: label })),
        h('td', { class: 'mono', text: has(value) ? String(value) : '–' })));
    });
  }

  async function loadInfo() {
    try {
      state.info = await api('/api/system/info');
      state.forbidden = false;
      showNotice($('pageNotice'), 'warn', '');
    } catch (e) {
      state.info = null;
      if (e && e.status === 403) {
        state.forbidden = true;
        showNotice($('pageNotice'), 'warn', 'Only administrators can use the system tools.');
      } else {
        live(false, 'Connection lost');
        throw e;
      }
    }

    try {
      const sys = await api('/api/monitor/system');
      state.uptime = sys ? sys.uptime_seconds : null;
    } catch (_) {}

    try {
      state.me = await api('/api/auth/me');
    } catch (_) {}

    live(true, 'Live');
    renderInfo();
    renderRestoreNotice();
  }

  function buildPasswordForm() {
    const box = clear($('pwForm'));

    const mk = (name, autocomplete) => h('input', { class: 'in', type: 'password', name, autocomplete, spellcheck: 'false' });
    const current = mk('current_password', 'current-password');
    const next = mk('new_password', 'new-password');
    const confirm = mk('confirm_password', 'new-password');

    const fld = (label, control, help) => h('label', { class: 'fld' }, h('span', { text: label }), control, help ? h('small', { text: help }) : null);

    const errorBox = h('div', { class: 'form-error', role: 'alert' });
    const save = h('button', { class: 'btn primary', type: 'submit' }, 'Change password');

    const form = h('form', { novalidate: true },
      h('div', { class: 'form-grid cols-2' },
        fld('Current password', current),
        h('span'),
        fld('New password', next, 'At least ' + MIN_PASSWORD + ' characters.'),
        fld('Repeat new password', confirm)),
      errorBox,
      h('div', { class: 'btn-row end' }, save));

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      [current, next, confirm].forEach((el) => el.classList.remove('invalid'));
      errorBox.textContent = '';

      if (!current.value) { current.classList.add('invalid'); current.focus(); errorBox.textContent = 'Enter your current password.'; return; }
      if (next.value.length < MIN_PASSWORD) { next.classList.add('invalid'); next.focus(); errorBox.textContent = 'The new password must be at least ' + MIN_PASSWORD + ' characters.'; return; }
      if (next.value !== confirm.value) { confirm.classList.add('invalid'); confirm.focus(); errorBox.textContent = 'The two new passwords do not match.'; return; }
      if (next.value === current.value) { next.classList.add('invalid'); next.focus(); errorBox.textContent = 'The new password must be different from the current one.'; return; }

      try {
        const r = await busy(save, () => api('/api/auth/change-password', {
          method: 'POST',
          body: { current_password: current.value, new_password: next.value }
        }));
        toast((r && r.message) || 'Password changed. Please sign in again.', 'ok', 6000);
        setTimeout(() => logout(), 1800);
      } catch (e) {
        errorBox.textContent = apiMessage(e);
      }
    });

    box.append(form);
  }

  function renderRestoreNotice() {
    const box = clear($('restoreNotice'));
    if (!state.info || !state.info.restore_pending) return;

    const cancel = h('button', { class: 'btn sm', type: 'button' }, 'Cancel restore');
    const reboot = h('button', { class: 'btn sm primary', type: 'button' }, 'Reboot now');

    cancel.addEventListener('click', async () => {
      try {
        const r = await busy(cancel, () => api('/api/system/restore', { method: 'DELETE' }));
        toast((r && r.message) || 'Pending restore cancelled.', 'ok');
        await loadInfo();
      } catch (e) {
        toast(apiMessage(e), 'bad');
      }
    });

    reboot.addEventListener('click', () => doReboot(reboot));

    box.append(h('div', { class: 'notice warn' },
      h('b', { text: 'A restore is waiting. ' }),
      'The uploaded backup replaces the current configuration the next time the firewall service starts. ',
      h('span', { class: 'btn-row' }, cancel, reboot)));
  }

  function buildBackupActions() {
    const btn = h('button', { class: 'btn primary', type: 'button' }, icon('i-file'), 'Download backup');

    btn.addEventListener('click', () => busy(btn, async () => {
      try {
        const res = await authed('/api/system/backup');
        if (!res.ok) throw await failure(res);

        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const link = h('a', { href: url, download: 'iqsoft-firewall-backup-' + stamp() + '.db' });
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);

        toast('Backup downloaded (' + fmtBytes(blob.size) + ').', 'ok');
      } catch (e) {
        toast(apiMessage(e), 'bad');
      }
    }));

    clear($('backupActions')).append(btn);
  }

  function buildRestoreForm() {
    const file = h('input', { class: 'in', type: 'file', accept: '.db,.sqlite,application/octet-stream', 'aria-label': 'Backup file' });
    const errorBox = h('div', { class: 'form-error', role: 'alert' });
    const upload = h('button', { class: 'btn danger', type: 'button' }, 'Check and stage restore');

    upload.addEventListener('click', async () => {
      errorBox.textContent = '';
      const chosen = file.files && file.files[0];

      if (!chosen) { errorBox.textContent = 'Choose a backup file first.'; return; }

      const ok = await confirmBox(
        'Stage "' + chosen.name + '" (' + fmtBytes(chosen.size) + ') as the new configuration? It takes effect when the firewall service next starts and replaces all current settings and user accounts.',
        { ok: 'Stage restore', danger: true, title: 'Restore from backup' });
      if (!ok) return;

      try {
        const r = await busy(upload, async () => {
          const res = await authed('/api/system/restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/octet-stream' },
            body: chosen
          });
          if (!res.ok) throw await failure(res);
          return res.json();
        });

        file.value = '';
        toast((r && r.message) || 'Backup staged.', 'ok', 9000);
        await loadInfo();
      } catch (e) {
        errorBox.textContent = apiMessage(e);
      }
    });

    clear($('restoreForm')).append(
      h('div', { class: 'form-grid' }, h('label', { class: 'fld span-all' }, h('span', { text: 'Backup file' }), file)),
      errorBox,
      h('div', { class: 'btn-row end' }, upload));
  }

  async function waitForReturn() {
    live(false, 'Rebooting…');
    const started = Date.now();
    let wentDown = false;

    const timer = setInterval(async () => {
      let up = false;
      try {
        const res = await fetch('/health', { cache: 'no-store' });
        up = res.ok;
      } catch (_) {}

      if (!up) wentDown = true;

      if (up && (wentDown || Date.now() - started > 90000)) {
        clearInterval(timer);
        toast('The firewall is back online.', 'ok');
        setTimeout(() => location.reload(), 1200);
      } else if (Date.now() - started > 600000) {
        clearInterval(timer);
        live(false, 'No response');
      }
    }, 3000);
  }

  async function doReboot(button) {
    const ok = await confirmBox('Reboot this firewall now? Traffic through it will stop for a minute or two.', { ok: 'Reboot', danger: true, title: 'Reboot' });
    if (!ok) return;

    try {
      const r = await busy(button, () => api('/api/system/reboot', { method: 'POST' }));
      toast((r && r.message) || 'Rebooting.', 'info', 8000);
      waitForReturn();
    } catch (e) {
      toast(apiMessage(e), 'bad');
    }
  }

  function buildPower() {
    const reboot = h('button', { class: 'btn danger', type: 'button' }, icon('i-refresh'), 'Reboot');
    reboot.addEventListener('click', () => doReboot(reboot));
    clear($('rebootActions')).append(reboot);

    const off = h('button', { class: 'btn danger', type: 'button' }, icon('i-ban'), 'Shut down');
    off.addEventListener('click', async () => {
      const ok = await confirmBox('Shut this firewall down? It will not come back until someone powers it on again.', { ok: 'Shut down', danger: true, title: 'Shut down' });
      if (!ok) return;

      try {
        const r = await busy(off, () => api('/api/system/shutdown', { method: 'POST' }));
        toast((r && r.message) || 'Shutting down.', 'info', 8000);
        live(false, 'Shutting down…');
      } catch (e) {
        toast(apiMessage(e), 'bad');
      }
    });
    clear($('shutdownActions')).append(off);
  }

  buildPasswordForm();
  buildBackupActions();
  buildRestoreForm();
  buildPower();

  tabs($('page'), 'system');

  btnRefresh.addEventListener('click', () => busy(btnRefresh, async () => { await loadInfo(); }));

  every(loadInfo, 15000);
})();
