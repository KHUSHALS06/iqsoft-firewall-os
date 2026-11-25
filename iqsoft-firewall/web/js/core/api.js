const Auth = {
  tokenKey: 'iqsoft.token',
  expiresKey: 'iqsoft.expires',

  token() {
    try { return sessionStorage.getItem(this.tokenKey); } catch (_) { return null; }
  },

  expires() {
    try { return Number(sessionStorage.getItem(this.expiresKey)) || 0; } catch (_) { return 0; }
  },

  set(token, expiresAt) {
    try {
      sessionStorage.setItem(this.tokenKey, token);
      sessionStorage.setItem(this.expiresKey, String(expiresAt));
    } catch (_) {}
  },

  clear() {
    try {
      sessionStorage.removeItem(this.tokenKey);
      sessionStorage.removeItem(this.expiresKey);
      sessionStorage.removeItem('iqsoft.me');
    } catch (_) {}
  },

  valid() {
    return !!this.token() && this.expires() > Math.floor(Date.now() / 1000);
  },

  guard() {
    if (!this.valid()) {
      this.clear();
      location.replace('/html/login.html');
      return false;
    }
    const ms = (this.expires() - Math.floor(Date.now() / 1000)) * 1000;
    setTimeout(() => {
      this.clear();
      location.replace('/html/login.html');
    }, Math.min(ms, 2147483000));
    return true;
  }
};

class ApiError extends Error {
  constructor(status, message, data) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  const token = Auth.token();
  if (token) headers['Authorization'] = 'Bearer ' + token;

  let body = options.body;
  if (body !== undefined && typeof body !== 'string') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  const res = await fetch(path, {
    method: options.method || 'GET',
    headers,
    body
  });

  let data = null;
  const text = await res.text();
  if (text) {
    try { data = JSON.parse(text); } catch (_) { data = text; }
  }

  if (res.status === 401) {
    Auth.clear();
    location.replace('/html/login.html');
    throw new ApiError(401, 'Authentication required', data);
  }

  if (!res.ok) {
    const message = data && data.error ? data.error : 'Request failed (' + res.status + ')';
    throw new ApiError(res.status, message, data);
  }

  return data;
}

async function logout() {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + (Auth.token() || '') }
    });
  } catch (_) {}
  Auth.clear();
  location.replace('/html/login.html');
}

/* Who is signed in and what their role allows. This only decides what the pages show:
   the server checks every request again, so editing this in the browser gains nothing. */
const Access = {
  key: 'iqsoft.me',

  /* [page id, feature it needs, address], in menu order. Keep in step with the menus. */
  PAGES: [
    ['dashboard', 'dashboard', '/html/dashboard.html'],
    ['network', 'network', '/html/network.html'],
    ['sdwan', 'sdwan', '/html/sdwan.html'],
    ['firewall', 'firewall', '/html/firewall.html'],
    ['nat', 'nat', '/html/nat.html'],
    ['threat', 'threat', '/html/threat.html'],
    ['ids', 'ids', '/html/ids.html'],
    ['geoip', 'geoip', '/html/geoip.html'],
    ['antivirus', 'antivirus', '/html/antivirus.html'],
    ['dnsfilter', 'dnsfilter', '/html/dnsfilter.html'],
    ['sni', 'appcontrol', '/html/sni.html'],
    ['vpn', 'vpn', '/html/vpn.html'],
    ['monitoring', 'monitoring', '/html/monitoring.html'],
    ['logs', 'logs', '/html/logs.html'],
    ['reports', 'reports', '/html/reports.html'],
    ['system', 'system', '/html/system.html'],
    ['users', 'users', '/html/users.html']
  ],

  me() {
    try { return JSON.parse(sessionStorage.getItem(this.key)); } catch (_) { return null; }
  },

  save(me) {
    try { sessionStorage.setItem(this.key, JSON.stringify(me)); } catch (_) {}
  },

  async refresh() {
    const me = await api('/api/auth/me');
    this.save(me);
    return me;
  },

  can(permission) {
    const me = this.me();
    return !!me && (me.is_super_admin === true || (me.permissions || []).includes(permission));
  },

  canAny(list) {
    return list.some((p) => this.can(p));
  },

  /* The Users page holds two tabs, so either right opens it. */
  canView(pageId) {
    const page = this.PAGES.find((p) => p[0] === pageId);
    if (!page) return true;
    if (pageId === 'users') return this.canAny(['users.view', 'roles.view']);
    return this.can(page[1] + '.view');
  },

  landing() {
    const page = this.PAGES.find((p) => this.canView(p[0]));
    return page ? page[2] : null;
  },

  /* "super_admin" -> "Super Admin" */
  roleLabel(role) {
    return String(role || '').replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }
};
