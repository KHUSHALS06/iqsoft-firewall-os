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
