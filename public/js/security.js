// Loads recent security events for admins. Uses textContent so event data is never parsed as HTML.
async function loadEvents() {
  const status = document.getElementById('status');
  const body = document.getElementById('rows');
  status.textContent = 'Loading...';
  try {
    const res = await fetch('/api/security-events?limit=200', { credentials: 'same-origin' });
    if (!res.ok) { status.textContent = 'Could not load events (' + res.status + ').'; return; }
    const data = await res.json();
    body.replaceChildren();
    data.events.forEach(function (e) {
      const tr = document.createElement('tr');
      if (e.type && e.type.indexOf('alert.') === 0) tr.style.fontWeight = 'bold';
      [e.time, e.type, e.severity, e.ip, e.email || (e.userId !== undefined ? 'user ' + e.userId : ''), e.detail || ''].forEach(function (v) {
        const td = document.createElement('td');
        td.textContent = v === undefined || v === null ? '' : String(v);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    status.textContent = data.events.length + ' event(s).';
  } catch (err) {
    status.textContent = 'Could not load events.';
  }
}
document.getElementById('refresh').addEventListener('click', loadEvents);
loadEvents();
