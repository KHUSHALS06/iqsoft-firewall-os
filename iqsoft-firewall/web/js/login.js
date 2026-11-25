(function () {
  if (Auth.valid()) {
    location.replace('/html/dashboard.html');
    return;
  }

  const form = document.getElementById('loginForm');
  const userInput = document.getElementById('username');
  const passInput = document.getElementById('password');
  const submitBtn = document.getElementById('submitBtn');
  const btnLabel = submitBtn.querySelector('.btn-label');
  const errorBox = document.getElementById('formError');
  const toggleBtn = document.getElementById('togglePassword');
  const eyeOpen = toggleBtn.querySelector('.eye-open');
  const eyeClosed = toggleBtn.querySelector('.eye-closed');
  const welcomeUser = document.getElementById('welcomeUser');

  userInput.addEventListener('input', () => {
    welcomeUser.textContent = userInput.value.trim();
  });

  let lockTimer = null;

  function showError(message, warn) {
    errorBox.textContent = message;
    errorBox.classList.toggle('warn', !!warn);
    errorBox.hidden = false;
  }

  function clearError() {
    errorBox.hidden = true;
    errorBox.textContent = '';
  }

  function setBusy(busy) {
    submitBtn.disabled = busy;
    submitBtn.classList.toggle('is-busy', busy);
    userInput.disabled = busy;
    passInput.disabled = busy;
  }

  function formatTime(seconds) {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return m + ':' + String(s).padStart(2, '0');
  }

  function lockFor(seconds) {
    clearInterval(lockTimer);
    let left = Math.max(1, Math.floor(seconds));

    setBusy(true);
    submitBtn.classList.remove('is-busy');
    btnLabel.textContent = 'Locked';

    const tick = () => {
      showError('Too many failed attempts. Try again in ' + formatTime(left) + '.', true);
      if (left <= 0) {
        clearInterval(lockTimer);
        clearError();
        btnLabel.textContent = 'Sign in';
        setBusy(false);
        passInput.focus();
        return;
      }
      left -= 1;
    };

    tick();
    lockTimer = setInterval(tick, 1000);
  }

  toggleBtn.addEventListener('click', () => {
    const show = passInput.type === 'password';
    passInput.type = show ? 'text' : 'password';
    eyeOpen.hidden = show;
    eyeClosed.hidden = !show;
    toggleBtn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    passInput.focus();
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearError();

    const username = userInput.value.trim();
    const password = passInput.value;

    if (!username || !password) {
      showError('Enter your username and password.');
      (username ? passInput : userInput).focus();
      return;
    }

    setBusy(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      let data = {};
      try { data = await res.json(); } catch (_) {}

      if (res.ok && data.token) {
        Auth.set(data.token, data.expires_at);
        passInput.value = '';
        let target = '/html/dashboard.html';
        try {
          await Access.refresh();
          target = Access.landing() || target;
        } catch (_) {}
        location.replace(target);
        return;
      }

      setBusy(false);

      if (res.status === 429) {
        passInput.value = '';
        lockFor(data.retry_after_seconds || 60);
        return;
      }

      if (res.status === 401) {
        showError('Invalid username or password.');
      } else {
        showError(data.error || 'Sign in failed (' + res.status + ').');
      }

      passInput.value = '';
      passInput.focus();
    } catch (_) {
      setBusy(false);
      showError('Cannot reach the firewall API. Check the connection and try again.');
    }
  });

})();

