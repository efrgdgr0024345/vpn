'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const loginView = $('login-view');
  const consoleView = $('console-view');
  const loginForm = $('login-form');
  const passwordInput = $('admin-password');
  const loginButton = $('login-button');
  const loginError = $('login-error');
  const refreshButton = $('refresh-button');
  const logoutButton = $('logout-button');
  const pollDelay = 5000;
  const requestTimeout = 8000;
  let csrfToken = '';
  let signedIn = false;
  let signingOut = false;
  let generation = 0;
  let pollTimer = null;
  let statusController = null;
  let lastStatus = null;
  let signoutFailure = false;
  let statusReceivedAt = 0;
  let authorizationTimer = null;
  let lastRenderedCurrent = false;
  let deviceBadges = [];

  const services = [
    { unit: 'openvpn-server@vpn-lab.service', name: 'OpenVPN', description: 'Encrypted VPN transport', icon: '⌁' },
    { unit: 'vpn-lab-broker.service', name: 'Session broker', description: 'Single-session authorization', icon: '⇄' },
    { unit: 'unbound.service', name: 'Private DNS', description: 'VPN resolver service', icon: '◎' }
  ];
  const deviceNames = { kali: 'Kali', iphone: 'iPhone', android: 'Android' };
  const stateLabels = {
    active: 'Active', inactive: 'Inactive', failed: 'Failed', activating: 'Starting',
    deactivating: 'Stopping', reloading: 'Reloading', maintenance: 'Maintenance'
  };

  function text(id, value) {
    const node = $(id);
    if (node.textContent !== value) node.textContent = value;
  }

  function element(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  }

  function validDate(value) {
    if (typeof value !== 'string') return null;
    const result = new Date(value);
    return Number.isFinite(result.getTime()) ? result : null;
  }

  function timestamp(value, withDate = false) {
    const date = validDate(value);
    if (!date) return 'Time unavailable';
    return new Intl.DateTimeFormat(undefined, withDate
      ? { dateStyle: 'medium', timeStyle: 'medium' }
      : { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(date);
  }

  function shortAddress(value) {
    if (typeof value !== 'string') return null;
    const parts = value.split('.');
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
      ? value : null;
  }

  function badge(label, kind = 'neutral') {
    return element('span', `badge badge-${kind}`, label);
  }

  function stateLabel(state) {
    return Object.prototype.hasOwnProperty.call(stateLabels, state) ? stateLabels[state] : 'Unknown';
  }

  function stateKind(state, current) {
    if (!current) return 'neutral';
    if (state === 'active') return 'good';
    if (state === 'failed') return 'bad';
    if (['activating', 'deactivating', 'reloading'].includes(state)) return 'warn';
    return 'neutral';
  }

  function metric(id, value, kind = 'muted') {
    const node = $(id);
    node.textContent = value;
    node.classList.remove('value-good', 'value-muted', 'value-warn');
    node.classList.add(`value-${kind}`);
  }

  function stopPolling() {
    window.clearTimeout(pollTimer);
    window.clearInterval(authorizationTimer);
    authorizationTimer = null;
    pollTimer = null;
    if (statusController) statusController.abort();
    statusController = null;
  }

  function showLogin(message = '') {
    generation += 1;
    signedIn = false;
    signingOut = false;
    csrfToken = '';
    lastStatus = null;
    signoutFailure = false;
    stopPolling();
    consoleView.hidden = true;
    loginView.hidden = false;
    document.title = 'VPN Desk · Private console';
    loginError.hidden = !message;
    loginError.textContent = message;
    passwordInput.value = '';
    loginButton.disabled = false;
    logoutButton.disabled = false;
  }

  function showConsole() {
    signedIn = true;
    loginView.hidden = true;
    consoleView.hidden = false;
    passwordInput.value = '';
    loginError.hidden = true;
    document.title = 'VPN Desk · Overview';
  }

  function renderServices(snapshot, current) {
    const list = $('service-list');
    list.replaceChildren();
    const observations = Array.isArray(snapshot.services) ? snapshot.services : [];
    for (const service of services) {
      const row = observations.find((item) => item && item.unit === service.unit) || {};
      const identity = element('div', 'service-identity');
      const icon = element('span', 'service-icon', service.icon);
      icon.setAttribute('aria-hidden', 'true');
      const copy = element('div');
      copy.append(element('div', 'service-name', service.name));
      let detail = service.description;
      if (Number.isInteger(row.restarts) && row.restarts >= 0) {
        detail += ` · ${row.restarts} restart${row.restarts === 1 ? '' : 's'}`;
      }
      if (!current && row.active_state) detail = `Last reported: ${stateLabel(row.active_state)}`;
      copy.append(element('div', 'service-description', detail));
      identity.append(icon, copy);
      const item = element('div', 'service-row');
      item.append(identity, badge(current ? stateLabel(row.active_state) : 'Unknown', stateKind(row.active_state, current)));
      list.append(item);
    }
  }

  function authorizationObservation(status, current) {
    const value = status?.snapshot?.authorization;
    const age = Number.isInteger(status?.age_ms) && status.age_ms >= 0
      ? status.age_ms + Math.max(0, performance.now() - statusReceivedAt) : null;
    const count = value?.element_count;
    const entries = Array.isArray(value?.addresses) ? value.addresses : [];
    const known = current && age !== null && Number.isInteger(count) && count >= 0 && count <= 1
      && entries.length === count && entries.every((entry) => shortAddress(entry?.ipv4)
        && Number.isInteger(entry.expires_ms) && entry.expires_ms > age);
    return { known, count, addresses: known ? new Set(entries.map((entry) => entry.ipv4)) : new Set() };
  }

  function updateDeviceBadge(node, device, current, authorization) {
    let label = 'Unknown';
    let kind = 'neutral';
    if (current && device.enabled === false) label = 'Disabled';
    else if (current && device.enabled === true) {
      if (!authorization.known) label = 'Enabled';
      else if (authorization.addresses.has(device.address)) { label = 'Forwarding'; kind = 'good'; }
      else label = 'Ready';
    }
    if (node.textContent !== label) node.textContent = label;
    node.className = `badge badge-${kind}`;
  }

  function renderAuthorization(status, current) {
    const observation = authorizationObservation(status, current);
    metric('grant-value', observation.known ? String(observation.count) : '—', observation.known && observation.count === 1 ? 'good' : 'muted');
    text('grant-detail', observation.known ? observation.count === 1 ? 'One authorized VPN address observed' : 'No forwarding grant observed' : 'A newer authorization observation is needed');
    for (const item of deviceBadges) updateDeviceBadge(item.node, item.device, current, observation);
  }

  function renderDevices(snapshot, current, authorization) {
    const list = $('device-list');
    list.replaceChildren();
    deviceBadges = [];
    const rows = Array.isArray(snapshot.devices) ? snapshot.devices.slice(0, 3) : [];
    text('device-count', `${rows.length} registered`);
    if (!rows.length) {
      list.append(element('p', 'empty-state', 'Registered devices are not available.'));
      return;
    }
    for (const device of rows) {
      if (!device || typeof device !== 'object') continue;
      const name = Object.prototype.hasOwnProperty.call(deviceNames, device.name) ? deviceNames[device.name] : 'Unknown device';
      const address = shortAddress(device.address);
      const copy = element('div');
      copy.append(element('div', 'device-name', name));
      copy.append(element('div', 'device-address mono', address || 'Address unavailable'));
      const icon = element('span', 'device-icon', device.name === 'kali' ? '▰' : '▯');
      icon.setAttribute('aria-hidden', 'true');
      const identity = element('div', 'device-identity');
      identity.append(icon, copy);
      const main = element('div', 'device-main');
      const accessBadge = badge('Unknown');
      updateDeviceBadge(accessBadge, device, current, authorization);
      deviceBadges.push({ node: accessBadge, device });
      main.append(identity, accessBadge);
      const row = element('div', 'device-row');
      row.append(main);
      const fingerprint = typeof device.certificate_sha256 === 'string' ? device.certificate_sha256 : '';
      if (/^[a-fA-F0-9]{64}$/.test(fingerprint)) {
        const fingerprintLabel = element('p', 'device-fingerprint mono', `Certificate ${fingerprint.slice(0, 12)}…${fingerprint.slice(-8)}`);
        fingerprintLabel.title = `Public certificate SHA256: ${fingerprint}`;
        row.append(fingerprintLabel);
      }
      list.append(row);
    }
  }

  function eventDescription(event) {
    const service = services.find((item) => item.unit === event.unit)?.name || 'Service';
    switch (event.code) {
      case 'snapshot_ready': return 'Server observation available';
      case 'service_state_changed': return `${service} changed to ${stateLabel(event.state).toLowerCase()}`;
      case 'authorization_granted': return 'Forwarding authorization granted';
      case 'authorization_released': return 'Forwarding authorization released';
      case 'ipv6_state_changed': return 'IPv6 state changed';
      case 'collector_error': return 'Server observation interrupted';
      default: return 'System update';
    }
  }

  function renderEvents(snapshot) {
    const list = $('activity-list');
    list.replaceChildren();
    const events = Array.isArray(snapshot.events) ? snapshot.events.slice(-40).reverse() : [];
    if (!events.length) {
      list.append(element('li', 'empty-state', 'No recent changes have been recorded.'));
      return;
    }
    for (const event of events) {
      if (!event || typeof event !== 'object') continue;
      const item = element('li', 'activity-row');
      const icon = element('span', 'event-icon', event.code === 'collector_error' ? '!' : '·');
      icon.setAttribute('aria-hidden', 'true');
      const content = element('div', 'event-content');
      content.append(element('div', 'event-title', eventDescription(event)));
      const address = shortAddress(event.address);
      if (address) content.append(element('div', 'event-subtitle mono', address));
      const time = element('time', 'event-time', timestamp(event.utc));
      const date = validDate(event.utc);
      if (date) time.dateTime = date.toISOString();
      time.title = timestamp(event.utc, true);
      item.append(icon, content, time);
      list.append(item);
    }
  }

  function render(status, transportError = false) {
    const snapshot = status?.snapshot && typeof status.snapshot === 'object' ? status.snapshot : {};
    const current = !transportError && status?.available === true && status?.stale === false && Boolean(status?.snapshot);
    const serviceRows = Array.isArray(snapshot.services) ? snapshot.services : [];
    const vpn = serviceRows.find((item) => item?.unit === services[0].unit);
    const dns = serviceRows.find((item) => item?.unit === services[2].unit);
    const broker = serviceRows.find((item) => item?.unit === services[1].unit);
    lastRenderedCurrent = current;
    const authorization = authorizationObservation(status, current);
    const ipv6 = snapshot.ipv6 || {};
    const allServicesActive = [vpn, dns, broker].every((service) => service?.active_state === 'active');
    const probe = snapshot.dns_probe || {};
    const dnsHealthy = current && probe.status === 'ok' && probe.rcode === 0 && Number.isInteger(probe.answer_count) && probe.answer_count > 0;
    const banner = $('status-banner');
    const freshnessBadge = $('freshness-badge');
    banner.classList.toggle('notice-good', current && allServicesActive && dnsHealthy && !signoutFailure);
    freshnessBadge.className = `badge badge-${current ? 'good' : 'neutral'}`;
    text('freshness-label', current ? 'Current observation' : transportError ? 'Update unavailable' : 'Awaiting update');
    if (signoutFailure) text('status-message', 'Sign-out could not be confirmed. Retry before leaving this device.');
    else if (transportError) text('status-message', 'The console could not refresh. Values below are last known observations; current health is unknown.');
    else if (!current && status?.stale === true) text('status-message', 'The server observation is out of date. Refreshing automatically; current health is unknown.');
    else if (!current) text('status-message', 'Waiting for a current server observation. Health and authorization have not been confirmed.');
    else if (allServicesActive && dnsHealthy) text('status-message', 'VPN services report active and the server’s private DNS lookup succeeded. Device forwarding is shown separately below.');
    else if (allServicesActive) text('status-message', 'VPN services report active. Review the private DNS check and device forwarding below.');
    else text('status-message', 'A current observation is available. Review the service states below.');

    metric('vpn-value', current ? stateLabel(vpn?.active_state) : 'Unknown', current && vpn?.active_state === 'active' ? 'good' : 'muted');
    text('vpn-detail', current ? 'OpenVPN transport service' : 'No current service confirmation');
    const dnsFailures = ['servfail', 'refused', 'rcode_error', 'invalid', 'no_answer', 'truncated', 'transport_error'];
    const dnsValue = !current ? 'Unknown' : dnsHealthy ? 'Responding' : probe.status === 'timeout' ? 'Timed out' : probe.status === 'not_attempted' ? 'Not tested' : dnsFailures.includes(probe.status) ? 'Failed' : 'Unknown';
    metric('dns-value', dnsValue, dnsHealthy ? 'good' : current && (probe.status === 'timeout' || dnsFailures.includes(probe.status)) ? 'warn' : 'muted');
    const dnsLatency = Number.isInteger(probe.elapsed_ms) && probe.elapsed_ms >= 0 ? ` · ${probe.elapsed_ms} ms` : '';
    text('dns-detail', current ? dnsHealthy ? `Server-side lookup succeeded${dnsLatency}` : 'Server-side resolver check; see service state below' : 'No current resolver confirmation');
    const ipv6Disabled = current && ipv6.kernel_disabled === true;
    metric('ipv6-value', current ? ipv6.kernel_disabled === true ? 'Disabled' : ipv6.kernel_disabled === false ? 'Enabled' : 'Unknown' : 'Unknown', ipv6Disabled ? 'good' : current && ipv6.kernel_disabled === false ? 'warn' : 'muted');
    text('ipv6-detail', current && ipv6.boot_argument_active === true ? 'Kernel boot argument is active' : current ? 'Boot argument not confirmed active' : 'No current kernel confirmation');

    renderServices(snapshot, current);
    renderDevices(snapshot, current, authorization);
    renderAuthorization(status, current);
    renderEvents(snapshot);
    const tunnelUp = snapshot.tunnel?.present === true && snapshot.tunnel?.up === true;
    const tunnelBadge = $('tunnel-badge');
    tunnelBadge.className = `badge badge-${current && tunnelUp ? 'good' : 'neutral'}`;
    tunnelBadge.textContent = current ? tunnelUp ? 'Up' : snapshot.tunnel?.present === false ? 'Absent' : 'Unknown' : 'Unknown';
    const addresses = Array.isArray(snapshot.tunnel?.ipv4) ? snapshot.tunnel.ipv4 : [];
    const address = addresses.find((value) => typeof value === 'string' && /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(value));
    text('tunnel-address', address || '—');
    text('updated-at', validDate(snapshot.generated_at) ? `Observed ${timestamp(snapshot.generated_at, true)}` : 'No server observation available');
  }

  function schedulePoll() {
    window.clearTimeout(pollTimer);
    if (signedIn && !signingOut && !document.hidden) {
      pollTimer = window.setTimeout(() => fetchStatus(), pollDelay);
      if (authorizationTimer === null) authorizationTimer = window.setInterval(() => renderAuthorization(lastStatus, lastRenderedCurrent), 1000);
    }
  }

  async function fetchStatus(initial = false) {
    if (signingOut) return;
    if (document.hidden && !initial) return;
    if (statusController) statusController.abort();
    const controller = new AbortController();
    statusController = controller;
    const version = generation;
    const startedAt = performance.now();
    const timeout = window.setTimeout(() => controller.abort(), requestTimeout);
    refreshButton.disabled = true;
    try {
      const response = await fetch('/api/status', { credentials: 'same-origin', cache: 'no-store', signal: controller.signal });
      if (version !== generation) return;
      if (response.status === 401) {
        showLogin(initial ? '' : 'Your session has ended. Sign in again.');
        return;
      }
      if (!response.ok) throw new Error('Status unavailable');
      const status = await response.json();
      if (version !== generation || controller.signal.aborted) return;
      if (!status || status.version !== 1 || typeof status.available !== 'boolean' || typeof status.stale !== 'boolean') {
        throw new Error('Status unavailable');
      }
      if (typeof status.csrf_token === 'string' && status.csrf_token.length <= 256) csrfToken = status.csrf_token;
      showConsole();
      lastStatus = status;
      statusReceivedAt = startedAt;
      render(status);
    } catch (error) {
      if (version !== generation || document.hidden || statusController !== controller) return;
      if (initial && !signedIn) showLogin('Console status is unavailable. Sign in to try again.');
      else render(lastStatus, true);
    } finally {
      window.clearTimeout(timeout);
      if (statusController === controller) statusController = null;
      refreshButton.disabled = false;
      if (version === generation) schedulePoll();
    }
  }

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (loginButton.disabled) return;
    loginButton.disabled = true;
    loginError.hidden = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), requestTimeout);
    try {
      const response = await fetch('/api/login', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: passwordInput.value }), signal: controller.signal
      });
      passwordInput.value = '';
      if (!response.ok) {
        if (response.status === 429) throw new Error('Please wait before trying to sign in again.');
        if (response.status === 401 || response.status === 403) throw new Error('Sign-in failed. Check the administrator password.');
        throw new Error('Sign-in is unavailable. Please try again shortly.');
      }
      const result = await response.json();
      if (result.authenticated !== true || typeof result.csrf_token !== 'string' || result.csrf_token.length > 256) {
        throw new Error('Sign-in could not be confirmed. Please try again.');
      }
      generation += 1;
      csrfToken = result.csrf_token;
      showConsole();
      render(null);
      await fetchStatus();
    } catch (error) {
      passwordInput.value = '';
      const messages = new Set(['Please wait before trying to sign in again.', 'Sign-in failed. Check the administrator password.', 'Sign-in is unavailable. Please try again shortly.', 'Sign-in could not be confirmed. Please try again.']);
      loginError.textContent = error.name === 'AbortError' ? 'Sign-in timed out. Please try again.' : messages.has(error.message) ? error.message : 'Sign-in could not be confirmed. Please try again.';
      loginError.hidden = false;
      passwordInput.focus();
    } finally {
      window.clearTimeout(timeout);
      loginButton.disabled = false;
    }
  });

  logoutButton.addEventListener('click', async () => {
    logoutButton.disabled = true;
    signingOut = true;
    stopPolling();
    renderAuthorization(lastStatus, false);
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), requestTimeout);
    try {
      const response = await fetch('/api/logout', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'X-CSRF-Token': csrfToken }, signal: controller.signal
      });
      if (!response.ok && response.status !== 401) throw new Error('Sign-out unavailable');
      showLogin();
      passwordInput.focus();
    } catch (error) {
      logoutButton.disabled = false;
      signingOut = false;
      signoutFailure = true;
      render(lastStatus);
      schedulePoll();
    } finally {
      window.clearTimeout(timeout);
    }
  });

  refreshButton.addEventListener('click', () => fetchStatus());
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stopPolling();
    else if (signedIn) {
      render(lastStatus ? { ...lastStatus, stale: true } : null);
      fetchStatus();
    }
  });
  for (const link of document.querySelectorAll('.nav-link')) {
    link.addEventListener('click', () => {
      document.querySelectorAll('.nav-link').forEach((item) => item.classList.toggle('active', item === link));
    });
  }
  fetchStatus(true);
})();
