import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env) {
    const uuid = (env.UUID || '').toLowerCase();
    const proxyIP = env.PROXYIP || '';
    const subPath = env.SUB_PATH || uuid;
    const fakeSite = env.FAKE_SITE || '';

    if (!uuid || uuid.length !== 36) {
      return new Response('请设置环境变量 UUID', { status: 500 });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const host = request.headers.get('Host') || url.hostname;

    // robots.txt 屏蔽爬虫
    if (path === '/robots.txt') {
      return new Response('User-agent: *\nDisallow: /', {
        headers: { 'Content-Type': 'text/plain' }
      });
    }

    // 订阅链接
    if (path === '/' + subPath || path === '/sub/' + subPath) {
      const ua = request.headers.get('User-Agent') || '';
      return generateSubscription(uuid, host, proxyIP, ua);
    }

    // WebSocket 升级 - VLESS 代理
    if (request.headers.get('Upgrade') === 'websocket') {
      return handleVless(request, uuid, proxyIP);
    }

    // 首页伪装
    return getDisguise(fakeSite);
  }
};

// ===================== VLESS 代理核心 =====================

async function handleVless(request, uuid, proxyIP) {
  const pair = new WebSocketPair();
  const [client, ws] = Object.values(pair);
  ws.accept();

  let parsed = false;
  let writer = null;
  let socket = null;

  ws.addEventListener('message', async (event) => {
    try {
      const chunk = new Uint8Array(event.data);

      if (!parsed) {
        const header = parseVless(chunk, uuid);
        if (!header) { ws.close(1002, 'bad header'); return; }
        parsed = true;

        const target = proxyIP || header.addr;
        socket = connect({ hostname: target, port: header.port });
        writer = socket.writable.getWriter();

        if (header.payload.byteLength > 0) {
          await writer.write(header.payload);
        }

        // VLESS 响应头
        ws.send(new Uint8Array([header.ver, 0]).buffer);

        // TCP 到 WS 转发
        relay(socket.readable, ws);
      } else if (writer) {
        await writer.write(chunk);
      }
    } catch (e) {
      ws.close(1011, 'error');
    }
  });

  ws.addEventListener('close', () => { if (socket) try { socket.close(); } catch(e) {} });
  ws.addEventListener('error', () => { if (socket) try { socket.close(); } catch(e) {} });

  return new Response(null, { status: 101, webSocket: client });
}

async function relay(readable, ws) {
  try {
    const reader = readable.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done || ws.readyState !== 1) break;
      ws.send(value.buffer);
    }
  } catch (e) { /* 连接已关闭 */ }
}

// ===================== VLESS 协议解析 =====================

function parseVless(buf, uuid) {
  if (buf.byteLength < 24) return null;

  const ver = buf[0];

  // UUID 校验 (字节 1-16)
  const got = fmtUuid(buf.slice(1, 17));
  if (got !== uuid) return null;

  // 附加信息
  let pos = 18 + buf[17];

  // 命令 1=TCP 2=UDP
  const cmd = buf[pos++];
  // 端口 (大端序)
  const port = (buf[pos] << 8) | buf[pos + 1]; pos += 2;
  // 地址类型
  const atype = buf[pos++];

  let addr = '';
  if (atype === 1) {
    // IPv4
    addr = buf[pos] + '.' + buf[pos+1] + '.' + buf[pos+2] + '.' + buf[pos+3];
    pos += 4;
  } else if (atype === 2) {
    // 域名
    const len = buf[pos++];
    addr = new TextDecoder().decode(buf.slice(pos, pos + len));
    pos += len;
  } else if (atype === 3) {
    // IPv6
    const s = [];
    for (let i = 0; i < 8; i++) s.push(((buf[pos+i*2] << 8) | buf[pos+i*2+1]).toString(16));
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

// ===================== 订阅生成 =====================

function generateSubscription(uuid, host, proxyIP, ua) {
  const node = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F&fp=chrome#CF-${host}`;

  // Clash 客户端
  if (/clash|stash/i.test(ua)) {
    return new Response(clashYaml(uuid, host), {
      headers: { 'Content-Type': 'text/yaml; charset=utf-8', 'Content-Disposition': 'attachment; filename=config.yaml' }
    });
  }

  // Sing-box 客户端
  if (/sing-?box/i.test(ua)) {
    return new Response(singboxJson(uuid, host), {
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 通用 (V2rayN / Shadowrocket 等) base64
  return new Response(btoa(node), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': 'attachment; filename=sub.txt' }
  });
}

function clashYaml(uuid, host) {
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
  - name: "CF-${host}"
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
      path: /
      headers:
        Host: ${host}

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - "CF-${host}"

rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy`;
}

function singboxJson(uuid, host) {
  return JSON.stringify({
    dns: {
      servers: [
        { tag: 'cn', address: '223.5.5.5', detour: 'direct' },
        { tag: 'proxy-dns', address: '8.8.8.8', detour: 'proxy' }
      ],
      rules: [{ clash_mode: 'direct', server: 'cn' }]
    },
    outbounds: [
      {
        type: 'vless', tag: 'proxy', server: host, server_port: 443,
        uuid: uuid,
        tls: { enabled: true, server_name: host, utls: { enabled: true, fingerprint: 'chrome' } },
        transport: { type: 'ws', path: '/', headers: { Host: host } }
      },
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' }
    ],
    route: {
      rules: [{ geosite: 'cn', geoip: 'cn', outbound: 'direct' }],
      final: 'proxy'
    }
  }, null, 2);
}

// ===================== 首页伪装 =====================

async function getDisguise(fakeSite) {
  // 如果设置了 FAKE_SITE，反代该网站
  if (fakeSite) {
    try {
      const resp = await fetch('https://' + fakeSite);
      return new Response(resp.body, {
        status: resp.status,
        headers: { 'Content-Type': resp.headers.get('Content-Type') || 'text/html' }
      });
    } catch (e) { /* fallback to nginx page */ }
  }

  // 默认 nginx 伪装页
  return new Response(`<!DOCTYPE html>
<html><head><title>Welcome to nginx</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
</head><body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body></html>`, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
                                        }
