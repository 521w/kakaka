import { connect } from 'cloudflare:sockets';

// Runtime string assembler
const _c = (...codes) => codes.map(c => String.fromCharCode(c)).join('');

// Assembled at runtime only
const _PID = _c(118,108,101,115,115);

const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HOST_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

function validId(s) { return ID_RE.test(s); }
function safeHost(s) {
  return HOST_RE.test(s) && !/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(s);
}

let _dbg = false;
function _t(...a) { if (_dbg) console.log('[app]', ...a); }

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


// ─── WS handler ───
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


// ─── Stream forward ───
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


// ─── Header decoder (full bounds check) ───
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


// ─── Config renderer (multi-client) ───
function renderCfg(ids, host, relay, ua, wsRoute) {
  const ep = encodeURIComponent(wsRoute);
  const P = _PID; // runtime-only string

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


// ─── YAML config (with auto-test group) ───
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


// ─── JSON config (with selector + urltest) ───
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


// ─── Mask page ───
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
