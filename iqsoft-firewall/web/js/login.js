(function () {
  if (Auth.valid()) {
    location.replace('/html/dashboard.html');
    return;
  }

  const form = document.getElementById('loginForm');
  const card = document.getElementById('loginCard');
  const panel = document.getElementById('loginPanel');
  const userInput = document.getElementById('username');
  const passInput = document.getElementById('password');
  const submitBtn = document.getElementById('submitBtn');
  const btnLabel = submitBtn.querySelector('.btn-label');
  const errorBox = document.getElementById('formError');
  const toggleBtn = document.getElementById('togglePassword');
  const eyeOpen = toggleBtn.querySelector('.eye-open');
  const eyeClosed = toggleBtn.querySelector('.eye-closed');
  const welcomeUser = document.getElementById('welcomeUser');
  const capsHint = document.getElementById('capsHint');
  const calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const touch = window.matchMedia('(pointer: coarse)').matches;

  userInput.addEventListener('input', () => {
    welcomeUser.textContent = userInput.value.trim();
  });

  if (!calm && !touch) {
    panel.addEventListener('mousemove', (e) => {
      const p = panel.getBoundingClientRect();
      panel.style.setProperty('--mx', (e.clientX - p.left) + 'px');
      panel.style.setProperty('--my', (e.clientY - p.top) + 'px');
      if (card.classList.contains('is-ok')) return;
      const r = card.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - 0.5;
      const y = (e.clientY - r.top) / r.height - 0.5;
      card.style.transform = 'perspective(900px) rotateY(' + (x * 9) + 'deg) rotateX(' + (-y * 9) + 'deg)';
    });
    panel.addEventListener('mouseleave', () => {
      card.style.transform = '';
    });
  }

  submitBtn.addEventListener('pointerdown', (e) => {
    if (submitBtn.disabled) return;
    const r = submitBtn.getBoundingClientRect();
    const ripple = document.createElement('span');
    ripple.className = 'rip';
    ripple.style.left = (e.clientX - r.left) + 'px';
    ripple.style.top = (e.clientY - r.top) + 'px';
    submitBtn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 650);
  });

  function onKey(e) {
    if (typeof e.getModifierState !== 'function') return;
    capsHint.hidden = !e.getModifierState('CapsLock');
  }
  passInput.addEventListener('keydown', onKey);
  passInput.addEventListener('keyup', onKey);
  passInput.addEventListener('blur', () => { capsHint.hidden = true; });

  card.addEventListener('animationend', (e) => {
    if (e.animationName === 'shake') card.classList.remove('shake');
  });

  let lockTimer = null;

  function shake() {
    card.classList.remove('shake');
    void card.offsetWidth;
    card.classList.add('shake');
  }

  function showError(message, warn) {
    errorBox.textContent = message;
    errorBox.classList.toggle('warn', !!warn);
    errorBox.hidden = false;
    if (!warn) shake();
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
        submitBtn.classList.remove('is-busy');
        submitBtn.classList.add('is-ok');
        card.style.transform = '';
        card.classList.add('is-ok');
        let target = '/html/dashboard.html';
        try {
          await Access.refresh();
          target = Access.landing() || target;
        } catch (_) {}
        setTimeout(() => location.replace(target), calm ? 0 : 750);
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
