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

  return new Response(admin原来的代码里**没有管理员界面**，我已经帮你加上了。下面是完整的带管理面板的代码和使用说明。

---

## 🎛️ 管理面板功能

| 功能 | 说明 |
|------|------|
| 🔐 密码登录页 | 暗色主题，Cookie 保持登录 24 小时 |
| 📊 状态仪表盘 | 在线状态、运行时间（实时计时）、节点数量、域名 |
| ⚡ 快捷操作 | 一键健康检查（显示延迟ms）、复制订阅链接 |
| 👤 节点列表 | 所有 UUID（脱敏显示）、一键复制完整 UUID |
| 🔗 订阅链接 | 6 种客户端格式一键复制（V2rayN/Clash/Sing-box/QX/Surge/Loon） |
| ⚙️ 配置查看 | 当前所有环境变量状态一览 |
| 📖 帮助文档 | 所有环境变量说明 |
| 🔌 API 接口 | `/admin/api` 返回 JSON 数据，可对接监控 |

---

## 📦 部署方法

### 1. 添加环境变量

去 Cloudflare 控制台 → 你的项目 → **设置** → **环境变量**，添加：

| 变量名 | 值 | 必填 |
|--------|------|------|
| `UUID` | `272c6bd8-4c1b-4bdc-b60c-73ad3c99f87e` | ✅ |
| `ADMIN_PASS` | 你自己设一个密码，比如 `MyP@ss123` | ⚠️ 强烈建议 |
| `ADMIN_PATH` | 管理面板路径，默认 `/admin`，可改成 `/my-panel` 之类的 | 可选 |

### 2. 替换代码

把 GitHub 仓库的 `_worker.js` 替换成下面的完整代码，提交后自动部署。

### 3. 访问管理面板

