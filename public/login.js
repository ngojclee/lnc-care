'use strict';
(() => {
  const errEl = document.getElementById('err');
  const mount = document.getElementById('login-methods');
  const subEl = document.getElementById('login-sub');

  const OIDC_ERRORS = {
    oidc_denied: 'SSO sign-in was cancelled or denied.',
    oidc_state: 'SSO session expired or state mismatch. Please try again.',
    oidc_user_not_allowed: 'Your SSO account is not authorized to access LNC Care.',
    oidc_exchange_failed: 'Could not complete SSO token exchange with Keycloak.',
    oidc_unavailable: 'LNC SSO is temporarily unavailable. Use break-glass management key if configured.',
    generic: 'Sign-in failed. Please try again.'
  };

  const showError = msg => {
    if (!errEl) return;
    errEl.textContent = msg;
    errEl.hidden = false;
  };

  const params = new URLSearchParams(location.search);
  const errCode = params.get('error');
  if (errCode) {
    showError(OIDC_ERRORS[errCode] || OIDC_ERRORS.generic);
  }

  function renderMethods(status) {
    if (!mount) return;
    const oidcEnabled = Boolean(status && status.oidc_enabled);
    const mgmtConfigured = status ? status.management_configured !== false : true;
    if (subEl) {
      subEl.textContent = oidcEnabled
        ? 'Owned social care, AI triage & forensic evidence console. Sign in with LNC SSO to continue.'
        : 'Owned social care, AI triage & forensic evidence console. Enter the management key to continue.';
    }

    mount.textContent = '';

    if (oidcEnabled) {
      const ssoLink = document.createElement('a');
      ssoLink.className = 'login-sso-primary';
      ssoLink.href = '/api/auth/oidc/login';
      ssoLink.textContent = 'Sign in with LNC SSO';
      mount.appendChild(ssoLink);
    }

    const details = document.createElement('details');
    details.className = 'login-breakglass';
    if (!oidcEnabled) details.open = true;

    const summary = document.createElement('summary');
    summary.textContent = 'Break-glass management key sign-in';
    details.appendChild(summary);

    const wrap = document.createElement('div');
    wrap.className = 'bg-form';

    if (!mgmtConfigured && oidcEnabled) {
      const note = document.createElement('p');
      note.className = 'hint';
      note.style.margin = '0';
      note.textContent = 'Break-glass management key is not configured on this instance.';
      wrap.appendChild(note);
      details.appendChild(wrap);
      mount.appendChild(details);
      return;
    }

    const form = document.createElement('form');
    form.id = 'login-form';
    form.autocomplete = 'off';

    const label = document.createElement('label');
    label.className = 'field';
    label.setAttribute('for', 'key');

    const labelText = document.createElement('span');
    labelText.className = 'field-label';
    labelText.textContent = 'Management key';

    const inputWrap = document.createElement('div');
    inputWrap.className = 'input-wrap';

    const keyInput = document.createElement('input');
    keyInput.id = 'key';
    keyInput.name = 'key';
    keyInput.type = 'password';
    keyInput.autocomplete = 'current-password';
    keyInput.placeholder = 'Enter management key';
    keyInput.required = true;

    const eyeBtn = document.createElement('button');
    eyeBtn.type = 'button';
    eyeBtn.className = 'btn btn-icon btn-ghost';
    eyeBtn.id = 'eye';
    eyeBtn.setAttribute('aria-label', 'Show key');
    eyeBtn.tabIndex = -1;
    eyeBtn.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>';

    inputWrap.appendChild(keyInput);
    inputWrap.appendChild(eyeBtn);
    label.appendChild(labelText);
    label.appendChild(inputWrap);

    const submitBtn = document.createElement('button');
    submitBtn.className = 'btn btn-primary';
    submitBtn.id = 'signin';
    submitBtn.type = 'submit';
    submitBtn.disabled = true;
    submitBtn.textContent = 'Sign in';

    form.appendChild(label);
    form.appendChild(submitBtn);
    wrap.appendChild(form);
    details.appendChild(wrap);
    mount.appendChild(details);

    let pending = false;
    const syncBtn = () => {
      submitBtn.disabled = pending || !keyInput.value.trim();
    };

    keyInput.addEventListener('input', syncBtn);
    eyeBtn.addEventListener('click', () => {
      const on = keyInput.type === 'password';
      keyInput.type = on ? 'text' : 'password';
      eyeBtn.setAttribute('aria-label', on ? 'Hide key' : 'Show key');
      keyInput.focus();
    });

    details.addEventListener('toggle', () => {
      if (details.open) keyInput.focus();
    });

    form.addEventListener('submit', async ev => {
      ev.preventDefault();
      if (!keyInput.value.trim() || pending) return;
      pending = true;
      syncBtn();
      if (errEl) errEl.hidden = true;
      const submitted = keyInput.value;
      keyInput.value = '';
      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: JSON.stringify({ key: submitted })
        });
        if (res.ok) {
          location.assign('/admin/#overview');
          return;
        }
        const j = await res.json().catch(() => ({}));
        throw new Error(
          res.status === 429
            ? 'Too many attempts. Wait 5 minutes and try again.'
            : res.status === 401
              ? 'Wrong management key.'
              : (j.detail || j.error || 'Sign-in failed.')
        );
      } catch (err) {
        pending = false;
        showError(err.message || 'Sign-in failed.');
        syncBtn();
        keyInput.focus();
      }
    });

    if (!oidcEnabled) keyInput.focus();
    syncBtn();
  }

  fetch('/api/auth/status', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(s => {
      if (s && s.authenticated) {
        location.replace('/admin/#overview');
        return;
      }
      renderMethods(s);
    })
    .catch(() => {
      renderMethods({ oidc_enabled: false, management_configured: true });
    });
})();
