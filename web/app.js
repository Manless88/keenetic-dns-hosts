const state = {
  clients: [],
  hosts: [],
  daemon: null,
  auth: false,
  busy: false,
  autoRefreshFailures: 0,
  pollTimer: null,
  pollIntervalMs: 5000,
};

const $ = (selector) => document.querySelector(selector);

async function api(cmd, body = {}) {
  const response = await fetch('/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cmd, ...body }),
  });
  const data = await response.json();
  if (!response.ok || data.status === 1) {
    const error = new Error(data.error || 'Запрос не выполнен');
    error.httpStatus = response.status;
    throw error;
  }
  return data;
}

function setAuthenticated(auth) {
  state.auth = auth;
  $('#loginHeader').classList.toggle('is-hidden', auth);
  $('#loginPanel').classList.toggle('is-hidden', auth);
  $('#appPanel').classList.toggle('is-hidden', !auth);
  if (!auth) {
    stopAutoRefresh();
  }
}

function handleUnauthorized() {
  state.clients = [];
  state.hosts = [];
  state.daemon = null;
  setAuthenticated(false);
  $('#loginMessage').textContent = 'Сеанс завершен. Войдите в панель еще раз.';
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function renderClients() {
  $('#macInput').innerHTML = state.clients
    .filter((client) => client.mac)
    .map(
      (client) => `
        <option value="${escapeHtml(client.mac)}">
          ${escapeHtml(client.name)} (${escapeHtml(client.ip)})
        </option>
      `,
    )
    .join('');
}

function renderHostsLoading(message = 'Загружаем hostname-алиасы с роутера...') {
  $('#hostsBody').innerHTML = `
    <tr>
      <td colspan="5" class="loading-cell">
        <span class="loader" aria-hidden="true"></span>
        <span>${escapeHtml(message)}</span>
      </td>
    </tr>
  `;
}

function renderDaemonStatus() {
  const daemon = state.daemon || {};
  const sync = daemon.sync || {};
  const result = sync.lastResult || {};
  const controlAvailable = daemon.controlAvailable !== false;
  const syncRunning = daemon.syncControl === 'running';
  const syncText = sync.running
    ? 'идет сейчас'
    : syncRunning
      ? `каждые ${daemon.syncInterval || 30} сек.`
      : 'остановлена';
  const details = [];
  if (typeof result.updated === 'number') {
    details.push(`обновлено: ${result.updated}`);
  }
  if (typeof result.missing === 'number' && result.missing > 0) {
    details.push(`не найдено клиентов: ${result.missing}`);
  }

  $('#daemonState').innerHTML = `<span class="daemon-badge ${syncRunning ? 'is-running' : 'is-stopped'}">${syncRunning ? 'работает' : 'остановлен'}</span>`;
  $('#daemonPid').textContent = daemon.pid || '-';
  $('#headerVersion').textContent = daemon.version ? `v${daemon.version}` : '';
  $('#syncState').textContent = syncText;
  $('#syncLastRun').textContent = sync.lastRun || '-';
  $('#serviceMessage').textContent = sync.lastError
    ? `Ошибка синхронизации: ${sync.lastError}`
    : details.length
      ? `Последний результат: ${details.join(', ')}.`
      : controlAvailable
        ? 'Панель работает. Кнопки управляют только фоновой синхронизацией.'
        : 'Управление синхронизацией недоступно.';

  $('#serviceToggleBtn').textContent = syncRunning ? 'Стоп' : 'Старт';
  $('#serviceToggleBtn').dataset.action = syncRunning ? 'stop' : 'start';
  $('#serviceToggleBtn').disabled = !controlAvailable;
}

function sourceLabel(source, mode) {
  const labels = {
    router: 'Keenetic',
    app: 'Панель',
    manual: 'Вручную',
    client: 'Клиент',
    'reverse-dns': 'Reverse DNS',
    'name-fallback': 'Имя клиента',
  };
  return labels[source] || labels[mode] || source || mode || 'Неизвестно';
}

function hostsFingerprint(hosts) {
  return JSON.stringify(
    hosts.map((host) => ({
      hostname: host.hostname,
      mode: host.mode,
      currentIp: host.currentIp,
      lastIp: host.lastIp,
      source: host.source,
      status: host.status,
      editable: host.editable,
    })),
  );
}

function clientsFingerprint(clients) {
  return JSON.stringify(
    clients.map((client) => ({
      name: client.name,
      ip: client.ip,
      mac: client.mac,
      active: client.active,
    })),
  );
}

function setBusy(busy) {
  state.busy = busy;
}

function setAutoRefreshMessage(message) {
  const element = $('#routerMessage');
  if (!element) {
    return;
  }
  element.textContent = message;
  element.dataset.autoRefreshMessage = message ? '1' : '';
}

function clearAutoRefreshMessage() {
  const element = $('#routerMessage');
  if (element?.dataset.autoRefreshMessage === '1') {
    setAutoRefreshMessage('');
  }
}

function renderHosts() {
  $('#hostsBody').innerHTML = state.hosts
    .map((host) => {
      const target =
        host.mode === 'client'
          ? `${host.clientName || host.mac} -> ${host.currentIp || 'нет IP'}`
          : host.currentIp;
      const statusText =
        host.status === 'missing-client'
          ? 'клиент не зарегистрирован'
          : host.status === 'ip-changed'
            ? 'IP изменился'
            : host.status === 'in-sync'
              ? 'актуально'
              : host.status;
      const deleteCell = host.editable
        ? `<button class="danger" data-delete="${escapeHtml(host.hostname)}">Удалить</button>`
        : '';
      return `
        <tr>
          <td class="mono" data-label="Hostname">${escapeHtml(host.hostname)}</td>
          <td data-label="IP-адрес">${escapeHtml(target)}</td>
          <td data-label="Источник">${escapeHtml(sourceLabel(host.source, host.mode))}</td>
          <td data-label="Состояние"><span class="status ${escapeHtml(host.status)}">${escapeHtml(statusText)}</span></td>
          <td data-label="Действие">${deleteCell}</td>
        </tr>
      `;
    })
    .join('');

  if (!state.hosts.length) {
    $('#hostsBody').innerHTML = `
      <tr>
        <td colspan="5">Ручных алиасов пока нет.</td>
      </tr>
    `;
  }

  document.querySelectorAll('[data-delete]').forEach((button) => {
    button.addEventListener('click', async () => {
      setBusy(true);
      renderHostsLoading('Удаляем алиас и обновляем список...');
      try {
        const data = await api('delete-host', { hostname: button.dataset.delete });
        await load();
        $('#routerMessage').textContent = data.message || 'Алиас удален из Keenetic.';
      } catch (error) {
        renderHosts();
        $('#routerMessage').textContent = error.message;
      } finally {
        setBusy(false);
      }
    });
  });
}

async function refreshHostsQuietly() {
  if (!state.auth || state.busy) {
    return;
  }
  try {
    const [clients, data, daemon] = await Promise.all([api('clients'), api('hosts'), api('service-status')]);
    if (clientsFingerprint(clients.clients) !== clientsFingerprint(state.clients)) {
      state.clients = clients.clients;
      renderClients();
    }
    state.daemon = daemon.daemon;
    renderDaemonStatus();
    if (hostsFingerprint(data.hosts) !== hostsFingerprint(state.hosts)) {
      state.hosts = data.hosts;
      renderHosts();
    }
    state.autoRefreshFailures = 0;
    clearAutoRefreshMessage();
  } catch (error) {
    if (error.httpStatus === 401) {
      handleUnauthorized();
      return;
    }
    state.autoRefreshFailures += 1;
    if (state.autoRefreshFailures >= 3) {
      setAutoRefreshMessage(`Связь с панелью временно потеряна: ${error.message}`);
    }
  }
}

function startAutoRefresh() {
  if (state.pollTimer) {
    return;
  }
  state.pollTimer = window.setInterval(refreshHostsQuietly, state.pollIntervalMs);
}

function stopAutoRefresh() {
  if (!state.pollTimer) {
    return;
  }
  window.clearInterval(state.pollTimer);
  state.pollTimer = null;
}

async function load({ silent = false } = {}) {
  setBusy(true);
  try {
    if (!silent) {
      renderHostsLoading();
    }
    const [status, clients, hosts, daemon] = await Promise.all([api('status'), api('clients'), api('hosts'), api('service-status')]);
    setAuthenticated(Boolean(status.auth));
    state.clients = clients.clients;
    state.hosts = hosts.hosts;
    state.daemon = daemon.daemon;
    renderClients();
    renderHosts();
    renderDaemonStatus();
    if (clients.source === 'cache' && clients.warning) {
      $('#routerMessage').textContent = `Клиенты показаны из кэша: ${clients.warning}`;
    }
    if (state.auth) {
      startAutoRefresh();
    }
  } finally {
    setBusy(false);
  }
}

async function checkStatus() {
  const status = await api('status');
  setAuthenticated(Boolean(status.auth));
  if (status.auth) {
    await load();
  }
}

async function login(event) {
  event.preventDefault();
  try {
    const data = await api('login', {
      user: $('#loginUserInput').value,
      password: $('#loginPasswordInput').value,
    });
    setAuthenticated(Boolean(data.auth));
    $('#loginMessage').textContent = '';
    await load();
  } catch (error) {
    $('#loginMessage').textContent = error.message;
  }
}

async function logout() {
  try {
    await api('logout');
  } finally {
    state.clients = [];
    state.hosts = [];
    state.daemon = null;
    setAuthenticated(false);
    $('#loginPasswordInput').value = '';
  }
}

async function syncNow() {
  const button = $('#syncNowBtn');
  setBusy(true);
  button.disabled = true;
  $('#serviceMessage').textContent = 'Синхронизируем client-алиасы по MAC...';
  renderHostsLoading('Синхронизируем алиасы и обновляем список...');
  try {
    const data = await api('sync-now');
    state.daemon = data.daemon;
    state.hosts = data.hosts;
    renderDaemonStatus();
    renderHosts();
  } catch (error) {
    renderHosts();
    $('#serviceMessage').textContent = error.message;
  } finally {
    button.disabled = false;
    setBusy(false);
  }
}

async function serviceControl(action) {
  const labels = {
    start: 'Запускаем синхронизацию...',
    stop: 'Останавливаем синхронизацию...',
  };
  $('#serviceMessage').textContent = labels[action] || 'Выполняем команду синхронизации...';
  try {
    const data = await api('service-control', { action });
    state.daemon = data.daemon;
    renderDaemonStatus();
  } catch (error) {
    try {
      const status = await api('service-status');
      state.daemon = status.daemon;
      renderDaemonStatus();
    } catch (_) {
      // Keep the visible service error if status refresh is unavailable.
    }
    $('#serviceMessage').textContent = error.message;
  }
}

function updateModeFields() {
  const mode = $('#modeInput').value;
  $('#clientField').classList.toggle('is-hidden', mode !== 'client');
  $('#ipField').classList.toggle('is-hidden', mode !== 'manual');
  $('#macInput').disabled = mode !== 'client';
  $('#ipInput').disabled = mode !== 'manual';
}

async function submitHost(event) {
  event.preventDefault();
  const mode = $('#modeInput').value;
  const payload = {
    hostname: $('#hostnameInput').value,
    mode,
    mac: $('#macInput').value,
    ip: $('#ipInput').value,
  };
  try {
    setBusy(true);
    renderHostsLoading('Сохраняем алиас и обновляем список...');
    await api('add-host', payload);
    $('#formMessage').textContent = 'Алиас записан в Keenetic.';
    event.target.reset();
    updateModeFields();
    await load();
  } catch (error) {
    renderHosts();
    $('#formMessage').textContent = error.message;
  } finally {
    setBusy(false);
  }
}

$('#logoutBtn').addEventListener('click', logout);
$('#syncNowBtn').addEventListener('click', syncNow);
$('#serviceToggleBtn').addEventListener('click', () => serviceControl($('#serviceToggleBtn').dataset.action || 'start'));
$('#modeInput').addEventListener('change', updateModeFields);
$('#hostForm').addEventListener('submit', submitHost);
$('#loginForm').addEventListener('submit', login);

updateModeFields();
checkStatus().catch((error) => {
  document.body.innerHTML = `<main class="shell"><div class="panel">Не удалось загрузить интерфейс: ${escapeHtml(error.message)}</div></main>`;
});
