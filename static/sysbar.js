// Widget thong so may: fetch /api/pm/sysinfo moi 5s, hien goc phai.
(function () {
  if (document.getElementById('sysbar')) return;
  var css = document.createElement('link');
  css.rel = 'stylesheet'; css.href = 'static/sysbar.css';
  document.head.appendChild(css);
  var bar = document.createElement('div');
  bar.id = 'sysbar'; bar.className = 'sysbar';
  bar.textContent = '…';
  document.body.appendChild(bar);
  function fmtUp(s) {
    s = s | 0;
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return (d ? d + 'd' : '') + (h ? h + 'h' : '') + m + 'm';
  }
  async function tick() {
    try {
      var r = await fetch('/api/pm/sysinfo', {cache: 'no-store'});
      var d = await r.json();
      if (!d || !d.ok) { bar.textContent = 'máy: ?'; return; }
      var t = d.temp_c, tc = t == null ? '—' : (t >= 75 ? 'hot' : t >= 60 ? 'warm' : 'ok');
      var c = d.cpu_pct, cc = c == null ? '—' : (c >= 85 ? 'hot' : c >= 60 ? 'warm' : 'ok');
      var m = (d.mem || {}).pct, mc = m == null ? '—' : (m >= 90 ? 'hot' : m >= 75 ? 'warm' : 'ok');
      var dk = (d.disks && d.disks[0]) || {}, dp = dk.pct, dc = dp == null ? '—' : (dp >= 90 ? 'hot' : dp >= 80 ? 'warm' : 'ok');
      bar.innerHTML = '🌡 <b class="' + tc + '">' + (t == null ? '—' : t + '°C') + '</b><span class="sep">|</span>'
        + 'CPU <b class="' + cc + '">' + (c == null ? '—' : c + '%') + '</b><span class="sep">|</span>'
        + 'RAM <b class="' + mc + '">' + (m == null ? '—' : m + '%') + '</b><span class="sep">|</span>'
        + 'Disk <b class="' + dc + '">' + (dp == null ? '—' : dp + '%') + '</b><span class="sep">|</span>'
        + '⏱ ' + fmtUp(d.uptime_s || 0);
      bar.title = 'CPU: ' + (c == null ? '—' : c + '% x' + (d.cpu_count || '?'))
        + ' | RAM: ' + ((d.mem || {}).used_mb || '?') + '/' + ((d.mem || {}).total_mb || '?') + 'MB'
        + ' | Disk: ' + (dk.used_gb != null ? dk.used_gb + '/' + dk.total_gb + 'GB (' + dk.mount + ')' : '—')
        + ' | Load: ' + ((d.load || []).join(' ') || '—')
        + ' | Uptime: ' + fmtUp(d.uptime_s || 0);
    } catch (e) { bar.textContent = 'máy: ?'; }
  }
  tick();
  setInterval(tick, 5000);
})();
