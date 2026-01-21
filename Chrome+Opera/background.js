// === НАСТРОЙКИ ===
const SCAN_TIMEOUT = 1200; // Чуть увеличим до 1.2 сек для надежности SSL рукопожатия

// === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isTargetIp(hostname) {
  // Проверка на валидность IPv4
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return false;

  const longIp = ipToLong(hostname);

  // Range 1: 100.60.0.0 - 100.80.0.0
  const r1Start = ipToLong('100.60.0.0');
  const r1End = ipToLong('100.80.0.0');

  // Range 2: 5.197.0.0/16
  const r2Start = ipToLong('5.197.0.0');
  const r2End = ipToLong('5.197.255.255');

  return (longIp >= r1Start && longIp <= r1End) || (longIp >= r2Start && longIp <= r2End);
}

/**
 * Проверяет доступность порта.
 * Возвращает объект с статусом и приоритетом.
 */
async function checkPort(hostname, port, protocol) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), SCAN_TIMEOUT);
  const targetUrl = `${protocol}//${hostname}:${port}`;

  try {
    await fetch(targetUrl, {
      method: 'HEAD',
      mode: 'no-cors', // Важно: игнорируем CORS
      cache: 'no-cache',
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    // Если fetch прошел (даже 404/403/500) - порт открыт и протокол верный
    return { url: targetUrl, protocol, port, status: 'OPEN' };
  } catch (error) {
    clearTimeout(timeoutId);
    
    // Таймаут = порт закрыт или фильтруется
    if (error.name === 'AbortError') {
      return { url: targetUrl, protocol, port, status: 'CLOSED' };
    }

    // TypeError часто означает ошибку SSL (Self-Signed Certificate).
    // Это значит, что порт ОТКРЫТ и это HTTPS. Это наш клиент.
    if (protocol === 'https:') {
        return { url: targetUrl, protocol, port, status: 'PROBABLY_OPEN_SSL' };
    }

    // Остальные ошибки для HTTP считаем закрытыми (например, ERR_CONNECTION_RESET)
    return { url: targetUrl, protocol, port, status: 'CLOSED' };
  }
}

// Кэш для предотвращения циклических редиректов
const processedTabs = new Set();

// === ОСНОВНАЯ ЛОГИКА ===

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  try {
    const url = new URL(details.url);
    const hostname = url.hostname;

    if (!isTargetIp(hostname)) return;

    // ... (Логика isDefaultScheme и LockKey остается без изменений)
    const isDefaultScheme = (url.protocol === 'http:' && (url.port === '' || url.port === '80'));
    const lockKey = `${details.tabId}-${hostname}`;
    
    if (processedTabs.has(lockKey)) {
        setTimeout(() => processedTabs.delete(lockKey), 5000); 
        return;
    }

    // Если не дефолтная схема и не HTTP (например, уже ввели https://IP:8888) - не мешаем
    if (!isDefaultScheme && url.protocol !== 'http:') return;

    console.log(`Scanning interfaces for ${hostname}...`);

    // Список проверок (остается тот же)
    const checks = [
      checkPort(hostname, 443, 'https:'),
      checkPort(hostname, 8080, 'https:'), 
      checkPort(hostname, 8888, 'https:'), 
      checkPort(hostname, 8080, 'http:'),
      checkPort(hostname, 8888, 'http:')
    ];

    const results = await Promise.all(checks);

    // Фильтруем только живые
    const activePorts = results.filter(r => r.status === 'OPEN' || r.status === 'PROBABLY_OPEN_SSL');

    if (activePorts.length === 0) {
        console.log('No active interfaces found.');
        return;
    }

    // === ИСПРАВЛЕННАЯ СОРТИРОВКА ПРИОРИТЕТОВ ===
    activePorts.sort((a, b) => {
        // Присваиваем веса для сортировки
        const getWeight = (item) => {
            let weight = 0;
            
            // 1. Наивысший приоритет: Порты, которые дали чистый, открытый ответ (OPEN)
            if (item.status === 'OPEN') {
                weight += 100;
            } 
            // 2. Второй приоритет: Порты, которые дали ошибку SSL, но живы (PROBABLY_OPEN_SSL)
            else if (item.status === 'PROBABLY_OPEN_SSL') {
                weight += 50;
            }

            // 3. Дополнительный вес за протокол (HTTPS всегда лучше, если статус равен)
            if (item.protocol === 'https:') {
                weight += 10;
            }

            // 4. Дополнительный вес за порт (443 > 8080 > 8888)
            const portPriority = { '443': 3, '8080': 2, '8888': 1 };
            weight += (portPriority[item.port] || 0);

            return weight;
        };

        return getWeight(b) - getWeight(a); // Сортировка по убыванию веса
    });

    const bestTarget = activePorts[0];

    // Если мы уже на правильном URL - стоп
    if (details.url.startsWith(bestTarget.url)) return;

    console.log(`Redirecting to best interface: ${bestTarget.url} (Status: ${bestTarget.status})`);
    
    processedTabs.add(lockKey);
    
    chrome.tabs.update(details.tabId, { url: bestTarget.url });

  } catch (e) {
    console.error(e);
  }
});