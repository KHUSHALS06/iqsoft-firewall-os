(function () {
  'use strict';

  const { h, icon, clear, toast, openModal, confirmBox, tabs, fmtTime, errorText } = Shell;
  const $ = (id) => document.getElementById(id);

  const frame = Shell.mount({
    active: 'users',
    title: 'Users',
    subtitle: 'Accounts, roles, and what each role may see and change',
    content: $('page')
  });
  if (!frame) return;

  const ACTIONS = ['view', 'create', 'edit', 'delete'];
  const ACTION_LABEL = { view: 'View', create: 'Create', edit: 'Edit', delete: 'Delete' };
  const MIN_PASSWORD = 10;

  const state = { users: [], roles: [], features: [] };

  const btnRefresh = h('button', { class: 'icon-square', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now' }, icon('i-refresh'));
  frame.tools.append(btnRefresh);

  /* ---------------- what the signed-in person may do (the server checks again) ---------------- */

  const can = (p) => Access.can(p);
  const meNow = () => Access.me() || {};
  const isSuper = () => meNow().is_super_admin === true;

  /* Mirrors the server: may I put somebody into, or manage somebody who is in, this role? */
  function holdsAll(role) {
    return isSuper() || role.permissions.every((p) => can(p));
  }

  function manageable(role) {
    if (role.name === 'super_admin' && !isSuper()) return false;
    return holdsAll(role);
  }

  function roleName(role) {
    return role.is_system ? Access.roleLabel(role.name) : role.name;
  }

  function totalPermissions() {
    return state.features.reduce((n, f) => n + f.actions.length, 0);
  }

  /* ---------------- small builders ---------------- */

  function badge(text, kind) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : ''), text });
  }

  function field(label, input, hint) {
    return h('label', { class: 'fld' }, h('span', { text: label }), input, hint ? h('small', { text: hint }) : null);
  }

  function toggleRow(box, title, text) {
    return h('div', { class: 'switch-row' },
      h('label', { class: 'switch' }, box, h('span', { class: 'slider' })),
      h('div', { class: 'switch-text' }, h('b', { text: title }), h('span', { text })));
  }

  function select(options, value) {
    const el = h('select', { class: 'in' });
    options.forEach((o) => el.append(h('option', { value: String(o.value), text: o.text, disabled: o.disabled })));
    if (value !== undefined && value !== null) el.value = String(value);
    return h('span', { class: 'select-wrap' }, el);
  }

  function actionButton(label, ic, kind, onClick, tip) {
    return h('button', { class: 'btn sm' + (kind ? ' ' + kind : ''), type: 'button', title: tip || null, onClick }, icon(ic), label);
  }

  function rowMessage(body, cols, text) {
    clear(body).append(h('tr', null, h('td', { class: 'empty-row', colspan: cols, text })));
  }

  /* ---------------- loading ---------------- */

  async function loadRoles() {
    state.roles = await api('/api/roles');
    $('tabCountRoles').textContent = String(state.roles.length);
  }

  async function loadUsers() {
    state.users = await api('/api/users');
    $('tabCountUsers').textContent = String(state.users.length);
  }

  async function loadCatalog() {
    if (state.features.length) return;
    const data = await api('/api/permissions');
    state.features = data.features;
  }

  async function refresh() {
    btnRefresh.classList.add('spin');
    try {
      // Roles come first: the users table shows them, and the role table needs the user counts.
      if (can('users.view') || can('roles.view')) await loadRoles();
      if (can('roles.view')) await loadCatalog();
      if (can('users.view')) await loadUsers();

      renderUsers();
      renderRoles();
      Shell.live(true, 'Up to date');
    } catch (e) {
      Shell.live(false, 'Error');
      toast(errorText(e), 'bad');
    } finally {
      btnRefresh.classList.remove('spin');
    }
  }

  /* ---------------- users ---------------- */

  function renderUsers() {
    if (!can('users.view')) return;

    const body = clear($('userBody'));
    if (!state.users.length) return rowMessage($('userBody'), 5, 'No users yet.');

    const role = (id) => state.roles.find((r) => r.id === id);

    state.users.forEach((u) => {
      const self = u.username === meNow().username;
      const r = role(u.role_id);
      const ok = r ? manageable(r) : false;

      const actions = h('td', { class: 'actions' });
      if (self) {
        actions.append(h('span', { class: 'muted', text: '–' }));
      } else {
        if (can('users.edit') && ok) actions.append(actionButton('Edit', 'i-edit', '', () => userDialog(u)), ' ');
        if (can('users.delete') && ok) actions.append(actionButton('Delete', 'i-trash', 'danger', () => deleteUser(u)));
        if (!actions.childNodes.length) actions.append(h('span', { class: 'muted', text: '–' }));
      }

      body.append(h('tr', null,
        h('td', null, h('b', { text: u.username }), self ? ' ' : null, self ? badge('You', 'info') : null),
        h('td', null, badge(r ? roleName(r) : Access.roleLabel(u.role), u.role === 'super_admin' ? 'warn' : 'info')),
        h('td', null, u.enabled ? badge('Active', 'ok') : badge('Disabled', 'bad')),
        h('td', { class: 'nowrap', text: fmtTime(u.created_at) }),
        actions));
    });
  }

  function roleOptions(current) {
    return state.roles.map((r) => ({
      value: r.id,
      text: roleName(r) + (manageable(r) || r.id === current ? '' : ' (not allowed)'),
      disabled: !manageable(r)
    }));
  }

  function userDialog(user) {
    const editing = !!user;

    if (!state.roles.some(manageable)) {
      toast('There is no role you are allowed to give. Ask a Super Admin.', 'bad');
      return;
    }

    const nameIn = h('input', { class: 'in', type: 'text', autocomplete: 'off', maxlength: 32, value: editing ? user.username : '', disabled: editing });
    const passIn = h('input', { class: 'in', type: 'password', autocomplete: 'new-password', maxlength: 128 });
    const roleSel = select(roleOptions(editing ? user.role_id : null), editing ? user.role_id : (state.roles.find(manageable) || {}).id);
    const enabledBox = h('input', { type: 'checkbox', checked: editing ? user.enabled : true });

    const body = h('div', { class: 'stack' },
      h('div', { class: 'form-grid cols-2' },
        field('User name', nameIn, editing ? 'The user name cannot be changed.' : 'Letters, numbers, dots, dashes and underscores (3 to 32).'),
        field('Role', roleSel, 'Decides what this person can see and do.')),
      field(editing ? 'New password' : 'Password', passIn,
        editing ? 'Leave empty to keep the current password. Setting one signs the user out.' : 'At least ' + MIN_PASSWORD + ' characters.'),
      toggleRow(enabledBox, 'Account is active', 'A disabled account cannot sign in and is signed out at once.'));

    const save = h('button', { class: 'btn primary', type: 'button' }, editing ? 'Save' : 'Add user');
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const modal = openModal({ title: editing ? 'Edit user: ' + user.username : 'Add user', body, footer: [cancel, save] });
    cancel.addEventListener('click', modal.close);

    const roleEl = roleSel.querySelector('select');

    save.addEventListener('click', async () => {
      modal.setError('');
      const username = nameIn.value.trim();
      const password = passIn.value;

      if (!editing && !username) return modal.setError('Enter a user name.');
      if ((!editing || password) && password.length < MIN_PASSWORD) {
        return modal.setError('The password must be at least ' + MIN_PASSWORD + ' characters.');
      }

      try {
        await Shell.busy(save, async () => {
          if (editing) {
            const req = { role_id: Number(roleEl.value), enabled: enabledBox.checked };
            if (password) req.password = password;
            await api('/api/users/' + encodeURIComponent(user.id), { method: 'PUT', body: req });
          } else {
            await api('/api/users', {
              method: 'POST',
              body: { username, password, role_id: Number(roleEl.value), enabled: enabledBox.checked }
            });
          }
        });
        modal.close();
        toast(editing ? 'User saved.' : 'User added.', 'ok');
        await refresh();
      } catch (e) {
        modal.setError(errorText(e));
      }
    });
  }

  async function deleteUser(u) {
    const ok = await confirmBox('Delete the user "' + u.username + '"? They are signed out at once. This cannot be undone.',
      { ok: 'Delete', danger: true, title: 'Delete user' });
    if (!ok) return;

    try {
      await api('/api/users/' + encodeURIComponent(u.id), { method: 'DELETE' });
      toast('User deleted.', 'ok');
      await refresh();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  /* ---------------- roles ---------------- */

  function renderRoles() {
    if (!can('roles.view')) return;

    const body = clear($('roleBody'));
    const total = totalPermissions();

    state.roles.forEach((r) => {
      const frozen = r.name === 'super_admin';
      const mayEdit = can('roles.edit') && !frozen && manageable(r) && (!r.is_system || isSuper());

      const actions = h('td', { class: 'actions' },
        mayEdit
          ? actionButton('Edit', 'i-edit', '', () => roleDialog(r))
          : actionButton('View', 'i-eye', '', () => roleDialog(r)));

      if (can('roles.delete') && !r.is_system && manageable(r)) {
        const del = actionButton('Delete', 'i-trash', 'danger', () => deleteRole(r),
          r.user_count > 0 ? 'Move its users to another role first' : null);
        del.disabled = r.user_count > 0;
        actions.append(' ', del);
      }

      body.append(h('tr', null,
        h('td', null, h('b', { text: roleName(r) }), ' ', r.is_system ? badge('Built-in', 'plain') : null),
        h('td', { class: 'wide', text: r.description || '–' }),
        h('td', { class: 'mono nowrap', text: String(r.user_count) }),
        h('td', { class: 'nowrap' }, badge(r.permissions.length + ' of ' + total, frozen ? 'warn' : 'info')),
        actions));
    });
  }

  /* The ticks: one row per feature, one column per action. Returns the table and a reader. */
  function matrix(selected, readOnly) {
    const boxes = new Map(); // "feature.action" -> checkbox
    const countEl = h('span', { class: 'muted perm-count' });

    const allowed = (perm) => isSuper() || can(perm);

    function update() {
      const n = Array.from(boxes.values()).filter((b) => b.checked).length;
      countEl.textContent = n + ' of ' + boxes.size + ' selected';
    }

    function setRow(feature, on) {
      feature.actions.forEach((a) => {
        const b = boxes.get(feature.id + '.' + a);
        if (b && !b.disabled) b.checked = on;
      });
    }

    const head = h('tr', null, h('th', { text: 'Feature' }),
      ACTIONS.map((a) => h('th', { text: ACTION_LABEL[a] })), h('th', { text: 'All' }));
    const tbody = h('tbody');

    state.features.forEach((f) => {
      const cells = ACTIONS.map((a) => {
        if (!f.actions.includes(a)) return h('td', { class: 'na', text: '–' });

        const perm = f.id + '.' + a;
        const box = h('input', {
          type: 'checkbox',
          checked: selected.has(perm),
          disabled: readOnly || !allowed(perm),
          'aria-label': f.label + ': ' + ACTION_LABEL[a],
          title: !readOnly && !allowed(perm) ? 'You do not have this permission yourself' : null
        });

        box.addEventListener('change', () => {
          const view = boxes.get(f.id + '.view');
          // You cannot change what you cannot see.
          if (a !== 'view' && box.checked && view && !view.disabled) view.checked = true;
          if (a === 'view' && !box.checked) setRow(f, false);
          syncRow(f);
          update();
        });

        boxes.set(perm, box);
        return h('td', null, box);
      });

      const all = h('input', { type: 'checkbox', disabled: readOnly, 'aria-label': f.label + ': everything' });
      all.addEventListener('change', () => { setRow(f, all.checked); syncRow(f); update(); });

      function syncRow(feature) {
        const mine = feature.actions.map((x) => boxes.get(feature.id + '.' + x)).filter(Boolean);
        all.checked = mine.length > 0 && mine.every((b) => b.checked);
        all.disabled = readOnly || mine.every((b) => b.disabled);
      }
      f._sync = () => syncRow(f);

      tbody.append(h('tr', null, h('td', null, h('b', { text: f.label })), cells, h('td', null, all)));
    });

    state.features.forEach((f) => f._sync());
    update();

    const tools = h('div', { class: 'perm-tools' },
      readOnly ? null : h('button', { class: 'btn sm', type: 'button', onClick: () => { state.features.forEach((f) => { setRow(f, true); f._sync(); }); update(); } }, 'Select all'),
      readOnly ? null : h('button', { class: 'btn sm', type: 'button', onClick: () => { state.features.forEach((f) => { setRow(f, false); f._sync(); }); update(); } }, 'Clear all'),
      countEl);

    return {
      node: h('div', null, tools, h('div', { class: 'perm-scroll' }, h('table', { class: 'perm-matrix' }, h('thead', null, head), tbody))),
      get: () => Array.from(boxes.entries()).filter(([, b]) => b.checked).map(([p]) => p)
    };
  }

  function roleDialog(role) {
    const editing = !!role;
    const frozen = editing && role.name === 'super_admin';
    const readOnly = editing && (frozen || !can('roles.edit') || !manageable(role) || (role.is_system && !isSuper()));

    const nameIn = h('input', { class: 'in', type: 'text', autocomplete: 'off', maxlength: 40, value: editing ? roleName(role) : '', disabled: readOnly || (editing && role.is_system) });
    const descIn = h('input', { class: 'in', type: 'text', autocomplete: 'off', maxlength: 200, value: editing ? (role.description || '') : '', disabled: readOnly });
    const grid = matrix(new Set(editing ? role.permissions : []), readOnly);

    const notice = frozen
      ? 'The Super Admin role always has every permission and cannot be changed.'
      : (readOnly ? 'You can look at this role but not change it.'
        : (editing && role.is_system ? 'This is a built-in role: you can change its permissions but not its name.' : null));

    const body = h('div', { class: 'stack' },
      notice ? h('div', { class: 'notice info', text: notice }) : null,
      h('div', { class: 'form-grid cols-2' },
        field('Role name', nameIn, 'Letters, numbers, spaces, dots, dashes and underscores.'),
        field('Description', descIn, 'Optional. Shown in the list.')),
      grid.node);

    const cancel = h('button', { class: 'btn', type: 'button' }, readOnly ? 'Close' : 'Cancel');
    const save = h('button', { class: 'btn primary', type: 'button' }, editing ? 'Save' : 'Create role');
    const modal = openModal({
      title: editing ? (readOnly ? 'Role: ' : 'Edit role: ') + roleName(role) : 'Create role',
      body,
      footer: readOnly ? [cancel] : [cancel, save],
      wide: true
    });
    cancel.addEventListener('click', modal.close);

    save.addEventListener('click', async () => {
      modal.setError('');
      const payload = {
        name: editing && role.is_system ? role.name : nameIn.value.trim(),
        description: descIn.value.trim() || null,
        permissions: grid.get()
      };

      if (!payload.name) return modal.setError('Enter a name for the role.');

      try {
        await Shell.busy(save, () => api(editing ? '/api/roles/' + encodeURIComponent(role.id) : '/api/roles', {
          method: editing ? 'PUT' : 'POST',
          body: payload
        }));
        modal.close();
        toast(editing ? 'Role saved. It applies to its users straight away.' : 'Role created.', 'ok');
        // The role may be the one this person holds, so read their rights again.
        try { await Access.refresh(); } catch (_) {}
        await refresh();
      } catch (e) {
        modal.setError(errorText(e));
      }
    });
  }

  async function deleteRole(r) {
    const ok = await confirmBox('Delete the role "' + r.name + '"? This cannot be undone.',
      { ok: 'Delete', danger: true, title: 'Delete role' });
    if (!ok) return;

    try {
      await api('/api/roles/' + encodeURIComponent(r.id), { method: 'DELETE' });
      toast('Role deleted.', 'ok');
      await refresh();
    } catch (e) {
      toast(errorText(e), 'bad');
    }
  }

  /* ---------------- start ---------------- */

  async function start() {
    // The tabs and buttons depend on the role, so know it before drawing them.
    if (!Access.me()) {
      try { await Access.refresh(); } catch (_) {}
    }

    // Only the tabs this role may open.
    const showUsers = can('users.view');
    const showRoles = can('roles.view');
    if (!showUsers) { document.querySelector('[data-tab="users"]').remove(); document.querySelector('[data-panel="users"]').remove(); }
    if (!showRoles) { document.querySelector('[data-tab="roles"]').remove(); document.querySelector('[data-panel="roles"]').remove(); }

    if (can('users.create') && showUsers) {
      $('userTools').append(h('button', { class: 'btn primary sm', type: 'button', onClick: () => userDialog(null) }, icon('i-plus'), 'Add user'));
    }
    if (can('roles.create') && showRoles) {
      $('roleTools').append(h('button', { class: 'btn primary sm', type: 'button', onClick: () => roleDialog(null) }, icon('i-plus'), 'Create role'));
    }

    tabs($('page'), 'users');
    btnRefresh.addEventListener('click', refresh);
    refresh();
  }

  start();
})();
