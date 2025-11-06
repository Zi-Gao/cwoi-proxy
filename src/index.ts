import { Hono } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import loginPageHtml from '../static/login.html'

import { SCRIPT_CONSTANTS, SPECIAL_API_PATHS } from './config';

// -----------------------------------------------------------------------------
// 程序常量定义
// -----------------------------------------------------------------------------



// -----------------------------------------------------------------------------
// 类型定义与全局变量
// -----------------------------------------------------------------------------

/**
 * 定义绑定到 Worker 的环境变量和 Secret 的类型。
 */
type Bindings = {
  DB: D1Database;
  OJ_ORIGIN: string;
  ROOT_USERNAME: string;
  ROOT_PASSWORD: string;
  DEBUG_MODE?: string;
}

const app = new Hono<{ Bindings: Bindings }>();

/**
 * 全局变量，用于在内存中缓存 root 用户的 token。
 */
let rootToken: string | null = null;

// -----------------------------------------------------------------------------
// 辅助函数
// -----------------------------------------------------------------------------

/**
 * 登录目标 OJ 并返回 token。
 */
async function loginToOj(username: string, password: string, env: Bindings): Promise<string | null> {
  const loginUrl = `${env.OJ_ORIGIN}/api/user/login`;
  try {
    const response = await fetch(loginUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Accept': 'application/json, text/plain, */*',
        'Origin': env.OJ_ORIGIN,
      },
      body: JSON.stringify({
        login: username,
        password: password,
        totp: null,
        remember: false,
      }),
    });
    if (!response.ok) {
      console.error(`OJ Login failed for ${username}: ${response.status}`);
      return null;
    }
    const data: { token?: string } = await response.json();
    return data.token || null;
  } catch (error) {
    console.error(`Error during OJ login for ${username}:`, error);
    return null;
  }
}

/**
 * 获取（或在失效时刷新）root 用户的 token。
 */
async function getRootToken(env: Bindings, forceRefresh = false): Promise<string> {
  if (rootToken && !forceRefresh) {
    return rootToken;
  }
  console.log('Root token is invalid or missing, attempting to re-login...');
  const token = await loginToOj(env.ROOT_USERNAME, env.ROOT_PASSWORD, env);
  if (!token) {
    throw new Error('FATAL: Could not log in as root user.');
  }
  rootToken = token;
  console.log('Successfully obtained a new root token.');
  return rootToken;
}

/**
 * 将收到的请求转发到目标 OJ。
 */
async function forwardRequest(request: Request, token: string, origin: string): Promise<Response> {
  const url = new URL(request.url);
  const targetUrl = `${origin}${url.pathname}${url.search}`;
  const headers = new Headers(request.headers);
  headers.set('Authorization', `Bearer ${token}`);
  headers.set('Origin', origin);
  headers.delete('cf-connecting-ip');
  headers.delete('cf-ipcountry');
  headers.delete('cf-ray');
  headers.delete('cf-visitor');
  const newRequest = new Request(targetUrl, {
    method: request.method,
    headers: headers,
    body: request.body,
    redirect: 'follow',
  });
  return fetch(newRequest);
}

/**
 * Base64Url 解码函数，能正确处理 UTF-8 字符。
 */
function base64UrlDecode(input: string): string {
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const decodedData = atob(padded);
    return new TextDecoder().decode(Uint8Array.from(decodedData, c => c.charCodeAt(0)));
}

/**
 * Base64Url 编码函数，能正确处理 UTF-8 字符。
 */
function base64UrlEncode(input: string): string {
    const encodedData = new TextEncoder().encode(input);
    const binaryString = String.fromCharCode.apply(null, Array.from(encodedData));
    const base64 = btoa(binaryString);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * 修改用户 Token，将其伪装成 Admin 并设置新的过期时间。
 */
function createFakeAdminToken(userToken: string, durationInSeconds: number): string | null {
    try {
        const parts = userToken.split('.');
        if (parts.length !== 3) return null;
        const header = parts[0];
        const payloadB64 = parts[1];
        const payloadObject = JSON.parse(base64UrlDecode(payloadB64));

        const nowInSeconds = Math.floor(Date.now() / 1000);
        payloadObject.iat = nowInSeconds;
        payloadObject.exp = nowInSeconds+durationInSeconds;
        payloadObject.type = "Admin";

        const newPayloadB64 = base64UrlEncode(JSON.stringify(payloadObject));
        return `${header}.${newPayloadB64}.invalid_signature_by_proxy`;
    } catch (error) {
        console.error("修改 JWT 时发生错误:", error);
        return null;
    }
}

// -----------------------------------------------------------------------------
// 路由定义
// -----------------------------------------------------------------------------

// 路由 1: 提供独立的登录页面 (无变化)
app.get('/proxy-login', (c) => {
  return c.html(loginPageHtml);
});

// 路由 2: [已修改] 处理登录逻辑
app.post('/api/login', async (c) => {
  const { username, password, remember } = await c.req.json<{ username?: string, password?: string, remember?: boolean }>();
  if (!username || !password) return c.json({ success: false, message: '用户名和密码不能为空。' }, 400);

  const user = await c.env.DB.prepare("SELECT username FROM users WHERE username = ?1 OR email = ?1").bind(username).first();
  if (!user) return c.json({ success: false, message: '用户不在白名单内。' }, 403);

  const realUserToken = await loginToOj(username, password, c.env);
  if (!realUserToken) return c.json({ success: false, message: 'OJ 登录失败，请检查凭据。' }, 401);

  if (remember) {
    await c.env.DB.prepare("UPDATE users SET password = ?1 WHERE username = ?2").bind(password, user.username).run();
  } else {
    await c.env.DB.prepare("UPDATE users SET password = NULL WHERE username = ?1").bind(user.username).run();
  }

  // 步骤 1: 根据 "记住我" 选项，决定【真实会话 Cookie】的有效期
  const cookieDuration = remember 
    ? SCRIPT_CONSTANTS.COOKIE_LIFETIME_LONG_SECONDS 
    : SCRIPT_CONSTANTS.COOKIE_LIFETIME_SHORT_SECONDS;

  const sessionId = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO sessions (session_id, username, oj_token) VALUES (?1, ?2, ?3)
     ON CONFLICT(username) DO UPDATE SET session_id = ?1, oj_token = ?3`
  ).bind(sessionId, user.username, realUserToken).run();

  const cookieOptions = {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax' as const, // 使用 as const 避免 TypeScript 类型问题
    maxAge: cookieDuration,
    // 判断当前环境是否为生产环境（通过检查 DEBUG_MODE 或 URL 协议）
    // 如果不是 debug 模式 (即生产环境)，则启用 secure
    secure: c.env.DEBUG_MODE !== 'true', 
  };
  
  // 在 debug 模式下打印 cookie 选项，方便排查
  const isDebug = c.env.DEBUG_MODE === 'true';
  if (isDebug) {
    console.log('[DEBUG] Setting cookie with options:', cookieOptions);
  }

  setCookie(c, 'proxy-session-id', sessionId, cookieOptions);
  
  // 步骤 2: 创建一个【“假象”的、超长有效期】的 token 给前端
  const fakeAdminToken = createFakeAdminToken(realUserToken, SCRIPT_CONSTANTS.FAKE_TOKEN_LIFETIME_SECONDS);
  if (!fakeAdminToken) {
    return c.json({ success: false, message: '代理服务器内部错误：无法生成凭证。' }, 500);
  }

  // 步骤 3: 在返回给前端的 JSON 中，明确告知这个超长的有效期
  return c.json({
    success: true,
    token: fakeAdminToken,
    expires_in: SCRIPT_CONSTANTS.FAKE_TOKEN_LIFETIME_SECONDS,
  });
});

// 路由 3: 主代理逻辑 (无变化)
app.all('*', async (c) => {
  const isDebug = c.env.DEBUG_MODE === 'true';
  const url = new URL(c.req.url);
  if (isDebug) console.log(`\n--- [DEBUG] ---\n[INFO] Request: ${c.req.method} ${url.pathname}`);

  const sessionId = getCookie(c, 'proxy-session-id');
  if (!sessionId) {
    return c.redirect('/proxy-login', 302);
  }

  const session = await c.env.DB.prepare("SELECT username, oj_token FROM sessions WHERE session_id = ?1").bind(sessionId).first<{ username: string; oj_token: string }>();
  if (!session) {
    return c.redirect('/proxy-login', 302);
  }

  // ====================================================================
  // [核心修改] 使用精细化的规则来决定使用哪个 Token
  // ====================================================================
  let tokenToUse: string;
  let isUserRequest = false;

  // 规则 1: 精确匹配 `/api/submission` 或 `/api/submission/`。
  // 这通常用于获取列表或创建新提交，需要用户自己的身份。
  if (url.pathname === '/api/submission' || url.pathname === '/api/submission/') {
    tokenToUse = session.oj_token;
    isUserRequest = true;
    if (isDebug) console.log(`[DECISION] Path is exact submission endpoint. Using USER token for '${session.username}'.`);
  }
  // 规则 2: 检查是否匹配 config.ts 中定义的其他特殊路径。
  else if (SPECIAL_API_PATHS.some(p => url.pathname.startsWith(p))) {
    tokenToUse = session.oj_token;
    isUserRequest = true;
    if (isDebug) console.log(`[DECISION] Path is a generic special API. Using USER token for '${session.username}'.`);
  }
  // 规则 3: 所有其他情况（包括 `/api/submission/xxx`）都使用 root 账户。
  // 因为规则1已经处理了精确匹配，所以任何以 /api/submission/ 开头但更长的路径会落到这里。
  else {
    tokenToUse = await getRootToken(c.env);
    // isUserRequest 默认是 false
    if (isDebug) console.log(`[DECISION] Path is a general request or specific submission detail. Using ROOT token.`);
  }

  let ojResponse = await forwardRequest(c.req.raw, tokenToUse, c.env.OJ_ORIGIN);

  if (ojResponse.status === 401 || ojResponse.status === 403) {
    if (isUserRequest) {
      if (isDebug) console.log(`用户 '${session.username}' 的 token 已失效，尝试自动重登...`);
      const savedUser = await c.env.DB.prepare("SELECT password FROM users WHERE username = ?1").bind(session.username).first<{ password?: string }>();

      if (savedUser && savedUser.password) {
        const newOjToken = await loginToOj(session.username, savedUser.password, c.env);
        if (newOjToken) {
          if (isDebug) console.log(`用户 '${session.username}' 自动重登成功。`);
          await c.env.DB.prepare("UPDATE sessions SET oj_token = ?1 WHERE session_id = ?2").bind(newOjToken, sessionId).run();
          return await forwardRequest(c.req.raw, newOjToken, c.env.OJ_ORIGIN);
        } else {
          if (isDebug) console.log(`用户 '${session.username}' 自动重登失败，存储的密码可能已失效。`);
          await c.env.DB.prepare("UPDATE users SET password = NULL WHERE username = ?1").bind(session.username).run();
          return c.redirect('/proxy-login', 302);
        }
      } else {
        if (isDebug) console.log(`用户 '${session.username}' 未存储密码，无法自动重登。`);
        return c.redirect('/proxy-login', 302);
      }
    } else {
      console.log('Root token 已过期。正在重试一次...');
      const newRootToken = await getRootToken(c.env, true);
      return await forwardRequest(c.req.raw, newRootToken, c.env.OJ_ORIGIN);
    }
  }

  return ojResponse;
});

export default app;
