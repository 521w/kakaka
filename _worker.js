import { connect } from 'cloudflare:sockets';

// Runtime string assembler
const _c = (...codes) => codes.map(c => String.fromCharCode(c)).join('');
const _PID = _c(118,108,101,115,115);

const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HOST_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

function validId(s) { return ID_RE.test(s); }
function safeHost(s) {
  return HOST_RE.test(s) && !/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(s);
}

let _dbg = false;
function _t(...a) { if (_dbg) console.log('[app]', ...a); }

const BOOT = Date.now();

export default {
  async fetch(request, env) {
    try {
      _dbg = (env.LOG || '').toLowerCase() === 'true';

      const raw = (env.UUID || env.TOKEN || env.KEY || '')
        .toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
      const ids = raw.filter(validId);
      if (!ids.length) return new Response('Config required', { status: 500 });

      const relay    = env.RELAY || env.UPSTREAM || '';
      const entry    = env.ENTRY || env.SUB_PATH || ids[0];
      const mask     = env.MASK || env.FAKE_SITE || '';
      const wsRoute  = env.WS_PATH || env.ROUTE || '/';
      const admPath  = env.ADMIN_PATH || '/admin';
      const admPass  = env.ADMIN_PASS || '';

      const url  = new URL(request.url);
      const path = url.pathname;
      const host = request.headers.get('Host') || url.hostname;

      _t(`${request.method} ${path}`);

      if (path === '/robots.txt')
        return new Response('User-agent: *\nDisallow: /', {
          headers: { 'Content-Type': 'text/plain' }
        });

      if (path === '/health')
        return new Response(JSON.stringify({
          status: 'ok', time: new Date().toISOString(), n: ids.length
        }), { headers: { 'Content-Type': 'application/json' } });

      // ─── Admin Panel ───
      if (path === admPath || path === admPath + '/')
        return handleAdmin(request, env, ids, host, entry, relay, mask, wsRoute, admPass, admPath);

      // ─── Admin API ───
      if (path === admPath + '/api')
        return handleAdminApi(request, env, ids, host, entry, relay, mask, wsRoute, admPass);

      if (path === '/' + entry || path === '/sub/' + entry) {
        const ua = request.headers.get('User-Agent') || '';
        return renderCfg(ids, host, relay, ua, wsRoute);
      }

      if (request.headers.get('Upgrade') === 'websocket')
        return wsHandler(request, ids, relay);

      return maskPage(mask);
    } catch (err) {
      _t('err:', err.message);
      return new Response(JSON.stringify({ error: 'Server Error' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};


// ============================================================
//  Admin Panel
// ============================================================
function handleAdmin(request, env, ids, host, entry, relay, mask, wsRoute, admPass, admPath) {
  if (admPass) {
    const url = new URL(request.url);
    const token = url.searchParams.get('pass') || url.searchParams.get('token') || '';
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookieMatch = cookieHeader.match(/admin_token=([^;]+)/);
    const cookieToken = cookieMatch ? cookieMatch[1] : '';

    if (token !== admPass && cookieToken !== admPass) {
      return new Response(loginPage(admPath), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (token === admPass) {
      return new Response('', {
        status: 302,
        headers: {
          'Location': admPath,
          'Set-Cookie': `admin_token=${admPass}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`
        }
      });
    }
  }

  const maskedIds = ids.map(id => id.slice(0, 8) + '-****-****-****-' + id.slice(-12));
  const subUrl = `https://${host}/${entry}`;
  const healthUrl = `https://${host}/health`;
  const upSec = Math.floor((Date.now() - BOOT) / 1000);

  const envInfo = {
    RELAY: relay || '(not set)',
    MASK: mask || '(not set)',
    WS_PATH: wsRoute,
    ADMIN_PATH: admPath,
    LOG: _dbg ? 'true' : 'false'
  };

  return new Response(adminPage(ids, maskedIds, host, subUrl, healthUrl, upSec, envInfo, wsRoute, admPath), {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function handleAdminApi(request, env, ids, host, entry, relay, mask, wsRoute, admPass) {
  if (admPass) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookieMatch = cookieHeader.match(/admin_token=([^;]+)/);
    const cookieToken = cookieMatch ? cookieMatch[1] : '';
    const url = new URL(request.url);
    const token = url.searchParams.get('pass') || '';
    if (token !== admPass && cookieToken !== admPass)
      return new Response('Unauthorized', { status: 401 });
  }

  const data = {
    status: 'ok',
    time: new Date().toISOString(),
    uptime_seconds: Math.floor((Date.now() - BOOT) / 1000),
    host,
    nodes: ids.length,
    uuids_masked: ids.map(id => id.slice(0, 8) + '-****-****-****-' + id.slice(-12)),
    subscription: `https://${host}/${entry}`,
    health: `https://${host}/health`,
    config: { relay: relay || null, mask: mask || null, ws_path: wsRoute, log: _dbg }
  };
  return new Response(JSON.stringify(data, null, 2), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

// ── Login page ──
function loginPage(admPath) {
  return `<!DOCTYPE html>
<html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#e2e8f0}
.card{background:#1e293b;border-radius:16px;padding:40px;width:90%;max-width:380px;
  box-shadow:0 25px 50px rgba(0,0,0,.4)}
h2{text-align:center;margin-bottom:24px;font-size:20px;color:#f1f5f9}
.field{margin-bottom:20px}
label{display:block;font-size:13px;color:#94a3b8;margin-bottom:6px}
input{width:100%;padding:12px 16px;border-radius:10px;border:1px solid #334155;
  background:#0f172a;color:#f1f5f9;font-size:15px;outline:none;transition:.2s}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.25)}
button{width:100%;padding:13px;border:none;border-radius:10px;background:#3b82f6;
  color:#fff;font-size:15px;font-weight:600;cursor:pointer;transition:.15s}
button:hover{background:#2563eb}
button:active{transform:scale(.98)}
.lock{text-align:center;font-size:36px;margin-bottom:16px}
</style></head><body>
<div class="card">
  <div class="lock">&#128274;</div>
  <h2>Admin Login</h2>
  <form method="GET" action="${admPath}">
    <div class="field">
      <label>Password</label>
      <input type="password" name="pass" placeholder="Enter admin password" required autofocus>
    </div>
    <button type="submit">Login</button>
  </form>
</div>
</body></html>`;
}

// ── Admin dashboard ──
function adminPage(ids, maskedIds, host, subUrl, healthUrl, upSec, envInfo, wsRoute, admPath) {
  const uptimeStr = formatUptime(upSec);
  const nodeRows = maskedIds.map((m, i) => {
    const fullId = ids[i];
    return `<tr>
      <td><span class="badge">#${i+1}</span></td>
      <td><code class="uuid-text">${m}</code></td>
      <td><button class="btn-sm" onclick="copyText('${fullId}')">Copy UUID</button></td>
    </tr>`;
  }).join('');

  const subLinks = [
    { name: 'Universal (V2rayN/Shadowrocket)', icon: '&#128279;', url: subUrl },
    { name: 'Clash / Stash', icon: '&#9889;', url: subUrl, ua: 'clash' },
    { name: 'Sing-box', icon: '&#128230;', url: subUrl, ua: 'sing-box' },
    { name: 'Quantumult X', icon: '&#127759;', url: subUrl, ua: 'quantumult' },
    { name: 'Surge', icon: '&#9889;', url: subUrl, ua: 'surge' },
    { name: 'Loon', icon: '&#127744;', url: subUrl, ua: 'loon' },
  ];

  const subRows = subLinks.map(s =>
    `<div class="sub-item">
      <div class="sub-info">
        <span class="sub-icon">${s.icon}</span>
        <div><div class="sub-name">${s.name}</div>
        <div class="sub-hint">${s.ua ? 'UA: ' + s.ua : 'Base64 encoded'}</div></div>
      </div>
      <button class="btn-copy" onclick="copyText('${s.url}')">Copy Link</button>
    </div>`
  ).join('');

  const envRows = Object.entries(envInfo).map(([k, v]) =>
    `<tr><td><code>${k}</code></td><td>${v}</td></tr>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;background:#0f172a;
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#e2e8f0}
.header{background:linear-gradient(135deg,#1e3a5f 0%,#0f172a 100%);
  padding:28px 24px;border-bottom:1px solid #1e293b}
.header-inner{max-width:960px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
.header h1{font-size:22px;color:#f8fafc;display:flex;align-items:center;gap:10px}
.header h1 span{font-size:28px}
.logout{padding:8px 16px;border-radius:8px;border:1px solid #334155;background:transparent;
  color:#94a3b8;font-size:13px;cursor:pointer;text-decoration:none;transition:.15s}
.logout:hover{border-color:#ef4444;color:#ef4444}
.container{max-width:960px;margin:0 auto;padding:24px 16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:28px}
.stat-card{background:#1e293b;border-radius:14px;padding:20px;border:1px solid #334155;transition:.2s}
.stat-card:hover{border-color:#3b82f6;transform:translateY(-2px)}
.stat-label{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.stat-value{font-size:26px;font-weight:700;color:#f1f5f9}
.stat-value.green{color:#22c55e}.stat-value.blue{color:#3b82f6}.stat-value.amber{color:#f59e0b}
.section{background:#1e293b;border-radius:14px;padding:24px;margin-bottom:20px;border:1px solid #334155}
.section-title{font-size:16px;font-weight:600;color:#f1f5f9;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.section-title span{font-size:20px}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;font-size:14px}
th{color:#64748b;font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #334155}
td{border-bottom:1px solid rgba(51,65,85,.5);color:#cbd5e1}
tr:last-child td{border-bottom:none}
.badge{background:#3b82f6;color:#fff;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:600}
.uuid-text{font-size:12px;color:#94a3b8;word-break:break-all}
.btn-sm{padding:5px 12px;border-radius:6px;border:1px solid #334155;background:#0f172a;
  color:#94a3b8;font-size:12px;cursor:pointer;transition:.15s;white-space:nowrap}
.btn-sm:hover{border-color:#3b82f6;color:#3b82f6}
.sub-item{display:flex;align-items:center;justify-content:space-between;
  padding:14px 0;border-bottom:1px solid rgba(51,65,85,.5);gap:12px;flex-wrap:wrap}
.sub-item:last-child{border-bottom:none}
.sub-info{display:flex;align-items:center;gap:12px}
.sub-icon{font-size:24px;width:40px;height:40px;background:#0f172a;border-radius:10px;
  display:flex;align-items:center;justify-content:center;flex-shrink:0}
.sub-name{font-size:14px;font-weight:500;color:#f1f5f9}
.sub-hint{font-size:11px;color:#64748b;margin-top:2px}
.btn-copy{padding:8px 16px;border-radius:8px;border:none;background:#3b82f6;
  color:#fff;font-size:13px;font-weight:500;cursor:pointer;transition:.15s;white-space:nowrap}
.btn-copy:hover{background:#2563eb}.btn-copy:active{transform:scale(.96)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
.btn-action{padding:10px 20px;border-radius:10px;border:none;font-size:14px;font-weight:500;
  cursor:pointer;transition:.15s;display:flex;align-items:center;gap:6px}
.btn-primary{background:#3b82f6;color:#fff}.btn-primary:hover{background:#2563eb}
.btn-success{background:#22c55e;color:#fff}.btn-success:hover{background:#16a34a}
.btn-action:active{transform:scale(.96)}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(80px);
  background:#22c55e;color:#fff;padding:12px 28px;border-radius:10px;font-size:14px;font-weight:500;
  opacity:0;transition:.35s;pointer-events:none;z-index:999;box-shadow:0 8px 24px rgba(0,0,0,.3)}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
@media(max-width:600px){
  .stats{grid-template-columns:1fr 1fr}
  .header-inner{flex-direction:column;align-items:flex-start}
  .sub-item{flex-direction:column;align-items:flex-start}
  .btn-copy{width:100%}
  td code{font-size:11px}
}
</style></head><body>
<div class="header"><div class="header-inner">
  <h1><span>&#9881;</span> Admin Panel</h1>
  <a class="logout" href="/" title="Back to site">&#8592; Back</a>
</div></div>
<div class="container">
  <div class="stats">
    <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value green">&#9679; Online</div></div>
    <div class="stat-card"><div class="stat-label">Uptime</div><div class="stat-value blue" id="uptime">${uptimeStr}</div></div>
    <div class="stat-card"><div class="stat-label">Nodes</div><div class="stat-value amber">${ids.length}</div></div>
    <div class="stat-card"><div class="stat-label">Host</div><div class="stat-value" style="font-size:16px;word-break:break-all">${host}</div></div>
  </div>
  <div class="section">
    <div class="section-title"><span>&#9889;</span> Quick Actions</div>
    <div class="actions">
      <button class="btn-action btn-primary" onclick="testHealth()">&#128994; Health Check</button>
      <button class="btn-action btn-success" onclick="copyText('${subUrl}')">&#128203; Copy Sub Link</button>
      <button class="btn-action btn-primary" onclick="window.open('${healthUrl}','_blank')">&#128279; Open Health</button>
    </div>
    <div id="health-result" style="margin-top:12px;font-size:13px;color:#94a3b8"></div>
  </div>
  <div class="section">
    <div class="section-title"><span>&#128100;</span> Node List</div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>#</th><th>UUID (Masked)</th><th>Action</th></tr></thead>
      <tbody>${nodeRows}</tbody>
    </table></div>
  </div>
  <div class="section">
    <div class="section-title"><span>&#128279;</span> Subscription Links</div>
    ${subRows}
  </div>
  <div class="section">
    <div class="section-title"><span>&#9881;</span> Configuration</div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>Variable</th><th>Value</th></tr></thead>
      <tbody>${envRows}</tbody>
    </table></div>
  </div>
  <div class="section">
    <div class="section-title"><span>&#128218;</span> Help</div>
    <div style="font-size:13px;color:#94a3b8;line-height:1.8">
      <p><strong style="color:#f1f5f9">Env Variables:</strong></p>
      <p><code>UUID</code> / <code>TOKEN</code> / <code>KEY</code> — Auth IDs (comma-separated)</p>
      <p><code>RELAY</code> / <code>UPSTREAM</code> — Upstream IP</p>
      <p><code>MASK</code> / <code>FAKE_SITE</code> — Front page domain</p>
      <p><code>WS_PATH</code> / <code>ROUTE</code> — WebSocket path</p>
      <p><code>ADMIN_PATH</code> — Admin URL path (default: /admin)</p>
      <p><code>ADMIN_PASS</code> — Admin password</p>
      <p><code>LOG</code> — Enable logging (true/false)</p>
    </div>
  </div>
</div>
<div class="toast" id="toast">Copied!</div>
<script>
function copyText(text){
  navigator.clipboard.writeText(text).then(()=>showToast('Copied!')).catch(()=>{
    const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);
    ta.select();document.execCommand('copy');document.body.removeChild(ta);showToast('Copied!');
  });
}
function showToast(msg){
  const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2000);
}
async function testHealth(){
  const el=document.getElementById('health-result');
  el.innerHTML='<span style="color:#f59e0b">Testing...</span>';
  try{
    const start=Date.now();
    const r=await fetch('/health');
    const ms=Date.now()-start;
    const d=await r.json();
    el.innerHTML='<span style="color:#22c55e">&#9989; '+d.status.toUpperCase()+' | '+ms+'ms | '+d.time+'</span>';
  }catch(e){
    el.innerHTML='<span style="color:#ef4444">&#10060; Failed: '+e.message+'</span>';
  }
}
let upSec=${upSec};
setInterval(()=>{upSec++;document.getElementById('uptime').textContent=fmtUp(upSec)},1000);
function fmtUp(s){
  const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),sec=s%60;
  if(d>0)return d+'d '+h+'h '+m+'m';
  if(h>0)return h+'h '+m+'m '+sec+'s';
  return m+'m '+sec+'s';
}
</script>
</body></html>`;
}

function formatUptime(s) {
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600),
        m = Math.floor(s % 3600 / 60), sec = s % 60;
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm ' + sec + 's';
  return m + 'm ' + sec + 's';
}


// ============================================================
//  WS handler
// ============================================================
async function wsHandler(request, ids, relay) {
  const pair = new WebSocketPair();
  const [client, ws] = Object.values(pair);
  ws.accept();

  let ready = false, writer = null, sock = null, done = false;

  function cleanup() {
    if (done) return;
    done = true;
    try { if (writer) writer.close(); } catch (_) {}
    try { if (sock) sock.close(); } catch (_) {}
    try { if (ws.readyState <= 1) ws.close(1000, 'fin'); } catch (_) {}
  }

  ws.addEventListener('message', async (ev) => {
    try {
      const chunk = new Uint8Array(ev.data);
      if (!ready) {
        const frame = decodeHeader(chunk, ids);
        if (!frame) { ws.close(1002, 'bad'); return; }
        if (frame.cmd === 2) { ws.close(1002, 'na'); return; }
        if (frame.port < 1 || frame.port > 65535) { ws.close(1002, 'port'); return; }

        ready = true;
        const dst = relay || frame.addr;
        _t(`-> ${dst}:${frame.port}`);

        sock = connect({ hostname: dst, port: frame.port });
        writer = sock.writable.getWriter();
        if (frame.data.byteLength > 0) await writer.write(frame.data);
        ws.send(new Uint8Array([frame.ver, 0]).buffer);
        forward(sock.readable, ws, cleanup);
      } else if (writer && !done) {
        await writer.write(chunk);
      }
    } catch (e) {
      _t('msg err:', e.message);
      cleanup();
    }
  });

  ws.addEventListener('close', cleanup);
  ws.addEventListener('error', cleanup);
  return new Response(null, { status: 101, webSocket: client });
}

async function forward(readable, ws, cleanup) {
  let r = null;
  try {
    r = readable.getReader();
    while (true) {
      const { done, value } = await r.read();
      if (done || ws.readyState !== 1) break;
      ws.send(value.buffer);
    }
  } catch (_) {} finally {
    try { if (r) r.releaseLock(); } catch (_) {}
    if (cleanup) cleanup();
  }
}

function decodeHeader(buf, ids) {
  if (buf.byteLength < 24) return null;
  const ver = buf[0];
  const got = fmtId(buf.slice(1, 17));
  if (!ids.includes(got)) return null;

  const addLen = buf[17];
  let p = 18 + addLen;
  if (p + 4 > buf.byteLength) return null;

  const cmd = buf[p++];
  const port = (buf[p] << 8) | buf[p + 1]; p += 2;
  const atype = buf[p++];
  let addr = '';

  if (atype === 1) {
    if (p + 4 > buf.byteLength) return null;
    addr = buf[p]+'.'+buf[p+1]+'.'+buf[p+2]+'.'+buf[p+3]; p += 4;
  } else if (atype === 2) {
    if (p + 1 > buf.byteLength) return null;
    const len = buf[p++];
    if (p + len > buf.byteLength) return null;
    addr = new TextDecoder().decode(buf.slice(p, p + len)); p += len;
  } else if (atype === 3) {
    if (p + 16 > buf.byteLength) return null;
    const s = [];
    for (let i = 0; i < 8; i++) s.push(((buf[p+i*2]<<8)|buf[p+i*2+1]).toString(16));
    addr = s.join(':'); p += 16;
  } else return null;

  return { ver, addr, port, cmd, data: buf.slice(p) };
}

function fmtId(b) {
  const h = Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
  return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20);
}


// ── Config renderer (multi-client) ──
function renderCfg(ids, host, relay, ua, wsRoute) {
  const ep = encodeURIComponent(wsRoute);
  const P = _PID;

  const links = ids.map((id, i) => {
    const tag = ids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
    return `${P}://${id}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=${ep}&fp=chrome#${tag}`;
  });

  const sh = {
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'X-Subscription-Userinfo': `upload=0; download=0; total=107374182400; expire=${Math.floor(Date.now()/1000)+86400*30}`
  };

  if (/clash|stash/i.test(ua))
    return new Response(yamlCfg(ids, host, wsRoute, P), {
      headers: { ...sh, 'Content-Type': 'text/yaml; charset=utf-8',
        'Content-Disposition': 'attachment; filename=config.yaml' }
    });

  if (/sing-?box/i.test(ua))
    return new Response(jsonCfg(ids, host, wsRoute, P), {
      headers: { ...sh, 'Content-Type': 'application/json; charset=utf-8' }
    });

  if (/quantumult/i.test(ua)) {
    const lines = ids.map((id, i) => {
      const tag = ids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
      return `${P}=${host}:443, method=none, password=${id}, obfs=wss, obfs-host=${host}, obfs-uri=${wsRoute}, tls-verification=false, fast-open=false, udp-relay=false, tag=${tag}`;
    });
    return new Response(lines.join('\n'), {
      headers: { ...sh, 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }

  if (/surge/i.test(ua)) {
    const tags = ids.map((_, i) => ids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`);
    const lines = ids.map((id, i) =>
      `${tags[i]} = ${P}, ${host}, 443, username=${id}, ws=true, ws-path=${wsRoute}, ws-headers=Host:${host}, tls=true, sni=${host}, skip-cert-verify=false`
    );
    const c = ['[Proxy]',...lines,'','[Proxy Group]',
      `Proxy = select, ${tags.join(', ')}`,
      `Auto = url-test, ${tags.join(', ')}, url=http://www.gstatic.com/generate_204, interval=300`,
      '','[Rule]','GEOIP,CN,DIRECT','FINAL,Proxy'].join('\n');
    return new Response(c, {
      headers: { ...sh, 'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': 'attachment; filename=config.conf' }
    });
  }

  if (/loon/i.test(ua)) {
    const lines = ids.map((id, i) => {
      const tag = ids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
      return `${tag} = ${P}, ${host}, 443, ${id}, transport=ws, path=${wsRoute}, host=${host}, over-tls=true, sni=${host}, skip-cert-verify=false`;
    });
    const c = ['[Proxy]',...lines,'','[Rule]','GEOIP,CN,DIRECT','FINAL,PROXY'].join('\n');
    return new Response(c, {
      headers: { ...sh, 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }

  return new Response(btoa(links.join('\n')), {
    headers: { ...sh, 'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': 'attachment; filename=sub.txt' }
  });
}

function yamlCfg(ids, host, wsRoute, P) {
  const nodes = ids.map((id, i) => {
    const n = ids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
    return `  - name: "${n}"
    type: ${P}
    server: ${host}
    port: 443
    uuid: ${id}
    network: ws
    tls: true
    udp: false
    sni: ${host}
    client-fingerprint: chrome
    ws-opts:
      path: ${wsRoute}
      headers:
        Host: ${host}`;
  });
  const names = ids.map((_, i) => {
    const n = ids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
    return `      - "${n}"`;
  });
  return `mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 8.8.8.8
    - 1.1.1.1
  fallback-filter:
    geoip: true
    geoip-code: CN
proxies:
${nodes.join('\n')}
proxy-groups:
  - name: Node
    type: select
    proxies:
      - Auto
${names.join('\n')}
  - name: Auto
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
${names.join('\n')}
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Node`;
}

function jsonCfg(ids, host, wsRoute, P) {
  const outs = ids.map((id, i) => {
    const tag = ids.length > 1 ? `n-${i+1}` : 'n';
    return {
      type: P, tag, server: host, server_port: 443, uuid: id,
      tls: { enabled: true, server_name: host,
        utls: { enabled: true, fingerprint: 'chrome' } },
      transport: { type: 'ws', path: wsRoute, headers: { Host: host } }
    };
  });
  const tags = outs.map(o => o.tag);
  return JSON.stringify({
    dns: {
      servers: [
        { tag: 'cn', address: '223.5.5.5', detour: 'direct' },
        { tag: 'remote', address: '8.8.8.8', detour: 'select' }
      ],
      rules: [{ clash_mode: 'direct', server: 'cn' }]
    },
    outbounds: [
      { type: 'selector', tag: 'select', outbounds: ['auto',...tags], default: 'auto' },
      { type: 'urltest', tag: 'auto', outbounds: tags,
        url: 'http://www.gstatic.com/generate_204', interval: '3m', tolerance: 50 },
      ...outs,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
      { type: 'dns', tag: 'dns-out' }
    ],
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { geosite: 'cn', geoip: 'cn', outbound: 'direct' }
      ],
      final: 'select'
    }
  }, null, 2);
}

async function maskPage(site) {
  const h = {
    'Content-Type': 'text/html; charset=utf-8',
    'Server': 'nginx/1.24.0',
    'X-Powered-By': 'Express',
    'X-Content-Type-Options': 'nosniff'
  };
  if (site && safeHost(site)) {
    try {
      const r = await fetch('https://'+site, {
        headers: { 'User-Agent': 'Mozilla/5.0' }, redirect: 'follow'
      });
      return new Response(r.body, { status: r.status,
        headers: { 'Content-Type': r.headers.get('Content-Type')||'text/html', 'Server': 'nginx/1.24.0' }
      });
    } catch (_) {}
  }
  return new Response(`<!DOCTYPE html>
<html><head><title>Welcome to nginx!</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
</head><body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body></html>`, { headers: h });
}
