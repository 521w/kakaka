// ============================================================
//  kakaka — Cloudflare Workers VLESS Proxy (Enhanced Edition)
//  原仓库: https://github.com/521w/kakaka
//  改进: 安全修复 / 资源管理 / 多UUID / 多客户端订阅 / 健康检查
// ============================================================

import { connect } from 'cloudflare:sockets';

// ───── UUID 正则严格校验 ─────
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUuid(str) {
  return UUID_RE.test(str);
}

// ───── SSRF 防护: 仅允许合法域名 ─────
const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

function isSafeDomain(str) {
  return DOMAIN_RE.test(str) && !str.match(/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i);
}

// ───── 日志工具 ─────
let LOG_ENABLED = false;
function log(...args) {
  if (LOG_ENABLED) console.log(`[kakaka]`, ...args);
}

// ============================================================
//  主入口
// ============================================================
export default {
  async fetch(request, env) {
    try {
      // ─── 环境变量读取 ───
      LOG_ENABLED = (env.LOG || '').toLowerCase() === 'true';

      // 多 UUID 支持: 逗号分隔
      const rawUuids = (env.UUID || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
      const uuids = rawUuids.filter(isValidUuid);
      if (uuids.length === 0) {
        return new Response('请设置环境变量 UUID（支持逗号分隔多个）', { status: 500 });
      }

      const proxyIP   = env.PROXYIP || '';
      const subPath   = env.SUB_PATH || uuids[0];
      const fakeSite  = env.FAKE_SITE || '';
      const wsPath    = env.WS_PATH || '/';   // 可配置 WS 路径

      const url  = new URL(request.url);
      const path = url.pathname;
      const host = request.headers.get('Host') || url.hostname;

      log(`${request.method} ${path}`);

      // ─── robots.txt 屏蔽爬虫 ───
      if (path === '/robots.txt') {
        return new Response('User-agent: *\nDisallow: /', {
          headers: { 'Content-Type': 'text/plain' }
        });
      }

      // ─── 健康检查端点 ───
      if (path === '/health') {
        return new Response(JSON.stringify({
          status: 'ok',
          time: new Date().toISOString(),
          nodes: uuids.length
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // ─── 订阅链接 ───
      if (path === '/' + subPath || path === '/sub/' + subPath) {
        const ua = request.headers.get('User-Agent') || '';
        return generateSubscription(uuids, host, proxyIP, ua, wsPath);
      }

      // ─── WebSocket 升级 — VLESS 代理 ───
      if (request.headers.get('Upgrade') === 'websocket') {
        return handleVless(request, uuids, proxyIP, wsPath);
      }

      // ─── 首页伪装 ───
      return getDisguise(fakeSite);

    } catch (err) {
      log('入口异常:', err.message);
      return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};


// ============================================================
//  VLESS 代理核心
// ============================================================
async function handleVless(request, uuids, proxyIP, wsPath) {
  const pair = new WebSocketPair();
  const [client, ws] = Object.values(pair);
  ws.accept();

  let parsed = false;
  let writer = null;
  let socket = null;
  let connectionClosed = false;  // 防重复关闭

  // ─── 统一清理函数 ───
  function cleanup() {
    if (connectionClosed) return;
    connectionClosed = true;
    try { if (writer) writer.close(); } catch (e) {}
    try { if (socket) socket.close(); } catch (e) {}
    try { if (ws.readyState <= 1) ws.close(1000, 'done'); } catch (e) {}
    log('连接已清理');
  }

  ws.addEventListener('message', async (event) => {
    try {
      const chunk = new Uint8Array(event.data);
      if (!parsed) {
        const header = parseVless(chunk, uuids);
        if (!header) {
          ws.close(1002, 'bad header');
          return;
        }

        // ─── 拦截 UDP ───
        if (header.cmd === 2) {
          log('拒绝 UDP 请求');
          ws.close(1002, 'UDP not supported');
          return;
        }

        // ─── 端口校验 ───
        if (header.port < 1 || header.port > 65535) {
          ws.close(1002, 'invalid port');
          return;
        }

        parsed = true;
        const target = proxyIP || header.addr;
        log(`连接 → ${target}:${header.port}`);

        socket = connect({ hostname: target, port: header.port });
        writer = socket.writable.getWriter();

        if (header.payload.byteLength > 0) {
          await writer.write(header.payload);
        }

        // VLESS 响应头
        ws.send(new Uint8Array([header.ver, 0]).buffer);

        // TCP → WS 转发
        relay(socket.readable, ws, cleanup);

      } else if (writer && !connectionClosed) {
        await writer.write(chunk);
      }
    } catch (e) {
      log('消息处理异常:', e.message);
      cleanup();
    }
  });

  ws.addEventListener('close', cleanup);
  ws.addEventListener('error', cleanup);

  return new Response(null, { status: 101, webSocket: client });
}


// ───── TCP → WS 转发（修复资源泄漏）─────
async function relay(readable, ws, cleanup) {
  let reader = null;
  try {
    reader = readable.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done || ws.readyState !== 1) break;
      ws.send(value.buffer);
    }
  } catch (e) {
    /* 连接已关闭 */
  } finally {
    try { if (reader) reader.releaseLock(); } catch (e) {}
    if (cleanup) cleanup();
  }
}


// ============================================================
//  VLESS 协议解析（全程边界检查）
// ============================================================
function parseVless(buf, uuids) {
  // 最小长度检查: 1(ver) + 16(uuid) + 1(附加长度) + 1(cmd) + 2(port) + 1(atype) + 1(最小地址) = 23
  if (buf.byteLength < 24) return null;

  const ver = buf[0];

  // UUID 校验 (字节 1-16)
  const got = fmtUuid(buf.slice(1, 17));
  if (!uuids.includes(got)) return null;

  // 附加信息
  const addLen = buf[17];
  let pos = 18 + addLen;

  // 边界检查: cmd + port + atype 至少需要 4 字节
  if (pos + 4 > buf.byteLength) return null;

  // 命令 1=TCP 2=UDP
  const cmd = buf[pos++];

  // 端口 (大端序)
  const port = (buf[pos] << 8) | buf[pos + 1];
  pos += 2;

  // 地址类型
  const atype = buf[pos++];
  let addr = '';

  if (atype === 1) {
    // IPv4 — 需要 4 字节
    if (pos + 4 > buf.byteLength) return null;
    addr = buf[pos] + '.' + buf[pos+1] + '.' + buf[pos+2] + '.' + buf[pos+3];
    pos += 4;

  } else if (atype === 2) {
    // 域名 — 需要 1(长度) + len 字节
    if (pos + 1 > buf.byteLength) return null;
    const len = buf[pos++];
    if (pos + len > buf.byteLength) return null;
    addr = new TextDecoder().decode(buf.slice(pos, pos + len));
    pos += len;

  } else if (atype === 3) {
    // IPv6 — 需要 16 字节
    if (pos + 16 > buf.byteLength) return null;
    const s = [];
    for (let i = 0; i < 8; i++) {
      s.push(((buf[pos + i*2] << 8) | buf[pos + i*2 + 1]).toString(16));
    }
    addr = s.join(':');
    pos += 16;

  } else {
    return null;
  }

  return { ver, addr, port, cmd, payload: buf.slice(pos) };
}

function fmtUuid(b) {
  const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20);
}


// ============================================================
//  订阅生成（多客户端 + 多 UUID）
// ============================================================
function generateSubscription(uuids, host, proxyIP, ua, wsPath) {
  const encodedPath = encodeURIComponent(wsPath);

  // 生成所有节点的 vless:// 链接
  const nodes = uuids.map((uuid, i) => {
    const tag = uuids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
    return `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=${encodedPath}&fp=chrome#${tag}`;
  });

  // 通用订阅响应头
  const subHeaders = {
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'X-Subscription-Userinfo': `upload=0; download=0; total=107374182400; expire=${Math.floor(Date.now()/1000) + 86400 * 30}`
  };

  // ─── Clash / Stash ───
  if (/clash|stash/i.test(ua)) {
    return new Response(clashYaml(uuids, host, wsPath), {
      headers: {
        ...subHeaders,
        'Content-Type': 'text/yaml; charset=utf-8',
        'Content-Disposition': 'attachment; filename=clash-config.yaml'
      }
    });
  }

  // ─── Sing-box ───
  if (/sing-?box/i.test(ua)) {
    return new Response(singboxJson(uuids, host, wsPath), {
      headers: {
        ...subHeaders,
        'Content-Type': 'application/json; charset=utf-8'
      }
    });
  }

  // ─── Quantumult X ───
  if (/quantumult/i.test(ua)) {
    const qxLines = uuids.map((uuid, i) => {
      const tag = uuids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
      return `vless=${host}:443, method=none, password=${uuid}, obfs=wss, obfs-host=${host}, obfs-uri=${wsPath}, tls-verification=false, fast-open=false, udp-relay=false, tag=${tag}`;
    });
    return new Response(qxLines.join('\n'), {
      headers: {
        ...subHeaders,
        'Content-Type': 'text/plain; charset=utf-8'
      }
    });
  }

  // ─── Surge ───
  if (/surge/i.test(ua)) {
    const surgeLines = uuids.map((uuid, i) => {
      const tag = uuids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
      return `${tag} = vless, ${host}, 443, username=${uuid}, ws=true, ws-path=${wsPath}, ws-headers=Host:${host}, tls=true, sni=${host}, skip-cert-verify=false`;
    });
    const surgeConfig = [
      '[Proxy]',
      ...surgeLines,
      '',
      '[Proxy Group]',
      `Proxy = select, ${uuids.map((_, i) => uuids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`).join(', ')}`,
      `Auto = url-test, ${uuids.map((_, i) => uuids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`).join(', ')}, url=http://www.gstatic.com/generate_204, interval=300`,
      '',
      '[Rule]',
      'GEOIP,CN,DIRECT',
      'FINAL,Proxy'
    ].join('\n');
    return new Response(surgeConfig, {
      headers: {
        ...subHeaders,
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': 'attachment; filename=surge.conf'
      }
    });
  }

  // ─── Loon ───
  if (/loon/i.test(ua)) {
    const loonLines = uuids.map((uuid, i) => {
      const tag = uuids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
      return `${tag} = vless, ${host}, 443, ${uuid}, transport=ws, path=${wsPath}, host=${host}, over-tls=true, sni=${host}, skip-cert-verify=false`;
    });
    const loonConfig = [
      '[Proxy]',
      ...loonLines,
      '',
      '[Rule]',
      'GEOIP,CN,DIRECT',
      'FINAL,PROXY'
    ].join('\n');
    return new Response(loonConfig, {
      headers: {
        ...subHeaders,
        'Content-Type': 'text/plain; charset=utf-8'
      }
    });
  }

  // ─── 通用 (V2rayN / Shadowrocket 等) base64 ───
  return new Response(btoa(nodes.join('\n')), {
    headers: {
      ...subHeaders,
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': 'attachment; filename=sub.txt'
    }
  });
}


// ───── Clash 配置（含自动测速组）─────
function clashYaml(uuids, host, wsPath) {
  const proxies = uuids.map((uuid, i) => {
    const name = uuids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
    return `  - name: "${name}"
    type: vless
    server: ${host}
    port: 443
    uuid: ${uuid}
    network: ws
    tls: true
    udp: false
    sni: ${host}
    client-fingerprint: chrome
    ws-opts:
      path: ${wsPath}
      headers:
        Host: ${host}`;
  });

  const names = uuids.map((_, i) => {
    const name = uuids.length > 1 ? `CF-${host}-${i+1}` : `CF-${host}`;
    return `      - "${name}"`;
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
${proxies.join('\n')}

proxy-groups:
  - name: Proxy
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
  - MATCH,Proxy`;
}


// ───── Sing-box 配置（含 selector + urltest）─────
function singboxJson(uuids, host, wsPath) {
  const outbounds = uuids.map((uuid, i) => {
    const tag = uuids.length > 1 ? `cf-${i+1}` : 'proxy';
    return {
      type: 'vless',
      tag,
      server: host,
      server_port: 443,
      uuid,
      tls: {
        enabled: true,
        server_name: host,
        utls: { enabled: true, fingerprint: 'chrome' }
      },
      transport: {
        type: 'ws',
        path: wsPath,
        headers: { Host: host }
      }
    };
  });

  const proxyTags = outbounds.map(o => o.tag);

  return JSON.stringify({
    dns: {
      servers: [
        { tag: 'cn', address: '223.5.5.5', detour: 'direct' },
        { tag: 'proxy-dns', address: '8.8.8.8', detour: 'select' }
      ],
      rules: [{ clash_mode: 'direct', server: 'cn' }]
    },
    outbounds: [
      {
        type: 'selector',
        tag: 'select',
        outbounds: ['auto', ...proxyTags],
        default: 'auto'
      },
      {
        type: 'urltest',
        tag: 'auto',
        outbounds: proxyTags,
        url: 'http://www.gstatic.com/generate_204',
        interval: '3m',
        tolerance: 50
      },
      ...outbounds,
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


// ============================================================
//  首页伪装（增强 nginx 响应头 + SSRF 防护）
// ============================================================
async function getDisguise(fakeSite) {
  const nginxHeaders = {
    'Content-Type': 'text/html; charset=utf-8',
    'Server': 'nginx/1.24.0',
    'X-Powered-By': 'Express',
    'X-Content-Type-Options': 'nosniff'
  };

  // 如果设置了 FAKE_SITE，先校验域名安全再反代
  if (fakeSite) {
    if (!isSafeDomain(fakeSite)) {
      log('FAKE_SITE 域名不安全，拒绝反代:', fakeSite);
      // fallback 到 nginx 页
    } else {
      try {
        const resp = await fetch('https://' + fakeSite, {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          redirect: 'follow'
        });
        return new Response(resp.body, {
          status: resp.status,
          headers: {
            'Content-Type': resp.headers.get('Content-Type') || 'text/html',
            'Server': 'nginx/1.24.0'
          }
        });
      } catch (e) {
        log('FAKE_SITE 请求失败:', e.message);
        /* fallback to nginx page */
      }
    }
  }

  // 默认 nginx 伪装页
  return new Response(`<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
</head><body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body></html>`, { headers: nginxHeaders });
}