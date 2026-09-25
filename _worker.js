// MeowZ Cloudflare Pages Advanced Mode worker
// This file is intentionally self-contained so Cloudflare Pages Dashboard
// Drag & Drop / Direct Upload can deploy it without a /functions directory.

// ---- functions/api/_lib.js ----
const COOKIE = "meowz_session";
const SESSION_DAYS = 30;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extra
    }
  });
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin");
  const allowed = origin || "*";
  return {
    "access-control-allow-origin": allowed,
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "Content-Type",
    "access-control-allow-methods": "GET,POST,OPTIONS"
  };
}

function withCors(response, request) {
  const h = new Headers(response.headers);
  Object.entries(corsHeaders(request)).forEach(([k,v]) => h.set(k,v));
  return new Response(response.body, { status: response.status, headers: h });
}

async function readJson(request) {
  try { return await request.json(); }
  catch { return null; }
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2,"0")).join("");
}

async function sha256(text) {
  return bytesToHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

function randomToken(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return bytesToHex(a);
}

async function passwordHash(password) {
  const salt = randomToken(16);
  const hash = await sha256(`${salt}:${password}`);
  return `${salt}$${hash}`;
}

async function passwordVerify(password, stored) {
  const [salt, expected] = String(stored).split("$");
  if (!salt || !expected) return false;
  const actual = await sha256(`${salt}:${password}`);
  return actual === expected;
}

function setCookie(token) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS*86400}`;
}

function clearCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function getCookie(request) {
  const raw = request.headers.get("Cookie") || "";
  const match = raw.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  return match ? match[1] : null;
}

async function currentUser(request, env) {
  const token = getCookie(request);
  if (!token) return null;

  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(`
    SELECT u.id,u.username,u.email
    FROM sessions s
    JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>?
  `).bind(tokenHash, Date.now()).first();

  return row || null;
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);
  if (!user) throw new Error("UNAUTHORIZED");
  return user;
}

async function createSession(userId, env) {
  const token = randomToken(32);
  const tokenHash = await sha256(token);
  const expires = Date.now() + SESSION_DAYS*86400*1000;
  await env.DB.prepare(
    "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)"
  ).bind(tokenHash,userId,expires).run();
  return token;
}

async function deleteSession(request, env) {
  const token = getCookie(request);
  if (!token) return;
  await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?")
    .bind(await sha256(token)).run();
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function licenseKey() {
  const block = () => randomToken(4).slice(0,6).toUpperCase();
  return `MEOW-${block()}-${block()}-${block()}-${block()}`;
}

async function issueLicense(env, order, userId) {
  for (let i=0; i<10; i++) {
    const key = licenseKey();
    try {
      let expires = null;
      if (order.duration_days != null) {
        expires = Date.now() + Number(order.duration_days) * 86400 * 1000;
      }
      await env.DB.prepare(`
        INSERT INTO licenses(license_key,user_id,order_id,product_id,expires_at)
        VALUES(?,?,?,?,?)
      `).bind(key,userId,order.id,order.product_id,expires).run();
      return { key, expires_at: expires };
    } catch (e) {
      if (!String(e.message || "").includes("UNIQUE")) throw e;
    }
  }
  throw new Error("LICENSE_GENERATION_FAILED");
}

// ---- D1 bootstrap ----
// The schema is created automatically on first API request, so no manual SQL migration
// is required after the D1 binding is available. Products are starter values and can be
// edited later in D1.
let schemaReady = null;
async function ensureSchema(env) {
  if (schemaReady) return schemaReady;
  schemaReady = (async () => {
    const statements = [
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)*1000)
      )`,
      `CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)*1000),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      )`,
      `CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        duration_days INTEGER,
        price_vnd INTEGER NOT NULL DEFAULT 0,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)*1000)
      )`,
      `CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        amount_vnd INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        carrier TEXT,
        denomination_vnd INTEGER,
        card_serial TEXT,
        card_code TEXT,
        created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)*1000),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(product_id) REFERENCES products(id)
      )`,
      `CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        expires_at INTEGER,
        created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)*1000),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY(product_id) REFERENCES products(id)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_licenses_user_id ON licenses(user_id)`,
      `INSERT OR IGNORE INTO products(slug,name,duration_days,price_vnd,sort_order) VALUES
        ('starter-30','MeowZ License 30 ngày',30,0,10),
        ('pro-90','MeowZ License 90 ngày',90,0,20),
        ('premium-365','MeowZ License 365 ngày',365,0,30)`
    ];
    await env.DB.batch(statements.map(sql => env.DB.prepare(sql)));
  })();
  try { await schemaReady; }
  catch (e) { schemaReady = null; throw e; }
}

// ---- functions/api/health.js ----
function healthHandler(context) {
  if (context.request.method === "OPTIONS")
    return withCors(new Response(null,{status:204}), context.request);

  return withCors(json({ok:true, service:"MeowZ Store Cloudflare"}), context.request);
}

// ---- functions/api/products.js ----
async function productsHandler(context) {
  if (context.request.method === "OPTIONS")
    return withCors(new Response(null,{status:204}), context.request);

  if (context.request.method !== "GET")
    return withCors(json({error:"Method not allowed"},405), context.request);

  const rows = await context.env.DB.prepare(
    "SELECT id,slug,name,duration_days,price_vnd,sort_order FROM products ORDER BY sort_order"
  ).all();

  return withCors(json({products:rows.results || []}), context.request);
}

// ---- functions/api/auth/register.js ----
async function registerHandler(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return withCors(new Response(null,{status:204}),req);
  if (req.method !== "POST") return withCors(json({error:"Method not allowed"},405),req);

  const body = await readJson(req);
  const username = String(body?.username || "").trim();
  const email = normalizeEmail(body?.email);
  const password = String(body?.password || "");

  if (!/^[A-Za-z0-9_]{3,24}$/.test(username))
    return withCors(json({error:"Username 3-24 ký tự, chỉ chữ/số/_"},400),req);
  if (!validEmail(email))
    return withCors(json({error:"Email không hợp lệ"},400),req);
  if (password.length < 6)
    return withCors(json({error:"Mật khẩu tối thiểu 6 ký tự"},400),req);

  const exists = await context.env.DB.prepare(
    "SELECT id FROM users WHERE username=? OR email=?"
  ).bind(username,email).first();

  if (exists)
    return withCors(json({error:"Username hoặc email đã tồn tại"},409),req);

  const hash = await passwordHash(password);
  const result = await context.env.DB.prepare(
    "INSERT INTO users(username,email,password_hash) VALUES(?,?,?)"
  ).bind(username,email,hash).run();

  const token = await createSession(result.meta.last_row_id, context.env);
  return withCors(
    json({ok:true,user:{username,email}},201,{"set-cookie":setCookie(token)}),
    req
  );
}

// ---- functions/api/auth/login.js ----
async function loginHandler(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return withCors(new Response(null,{status:204}),req);
  if (req.method !== "POST") return withCors(json({error:"Method not allowed"},405),req);

  const body = await readJson(req);
  const identity = String(body?.identity || "").trim();
  const password = String(body?.password || "");

  const row = await context.env.DB.prepare(
    "SELECT id,username,email,password_hash FROM users WHERE username=? OR email=?"
  ).bind(identity,normalizeEmail(identity)).first();

  if (!row || !(await passwordVerify(password,row.password_hash)))
    return withCors(json({error:"Sai tài khoản hoặc mật khẩu"},401),req);

  const token = await createSession(row.id, context.env);
  return withCors(
    json({ok:true,user:{username:row.username,email:row.email}},200,{"set-cookie":setCookie(token)}),
    req
  );
}

// ---- functions/api/auth/logout.js ----
async function logoutHandler(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return withCors(new Response(null,{status:204}),req);
  if (req.method !== "POST") return withCors(json({error:"Method not allowed"},405),req);

  await deleteSession(req,context.env);
  return withCors(json({ok:true},200,{"set-cookie":clearCookie()}),req);
}

// ---- functions/api/auth/me.js ----
async function meHandler(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return withCors(new Response(null,{status:204}),req);
  if (req.method !== "GET") return withCors(json({error:"Method not allowed"},405),req);

  const user = await currentUser(req, context.env);
  return withCors(json({authenticated:!!user,user:user||null}),req);
}

// ---- functions/api/orders.js ----
async function ordersHandler(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return withCors(new Response(null,{status:204}),req);

  if (req.method === "POST") {
    let user;
    try { user = await requireUser(req,context.env); }
    catch { return withCors(json({error:"Bạn cần đăng nhập"},401),req); }

    const body = await readJson(req);
    const productId = Number(body?.product_id);
    const carrier = String(body?.carrier || "").trim();
    const denomination = Number(body?.denomination_vnd || 0);
    const serial = String(body?.card_serial || "").trim();
    const cardCode = String(body?.card_code || "").trim();

    const product = await context.env.DB.prepare(
      "SELECT id,slug,name,duration_days,price_vnd FROM products WHERE id=?"
    ).bind(productId).first();

    if (!product) return withCors(json({error:"Gói license không tồn tại"},400),req);
    if (!carrier || !denomination || !serial || !cardCode)
      return withCors(json({error:"Vui lòng nhập đủ thông tin thẻ"},400),req);

    const code = `MZ-${Date.now().toString(36).toUpperCase()}-${crypto.randomUUID().slice(0,8).toUpperCase()}`;

    await context.env.DB.prepare(`
      INSERT INTO orders(code,user_id,product_id,amount_vnd,carrier,denomination_vnd,card_serial,card_code)
      VALUES(?,?,?,?,?,?,?,?)
    `).bind(code,user.id,product.id,product.price_vnd,carrier,denomination,serial,cardCode).run();

    return withCors(json({
      ok:true,
      order:{code,amount_vnd:product.price_vnd,status:"pending",product:product.name}
    },201),req);
  }

  return withCors(json({error:"Method not allowed"},405),req);
}

// ---- functions/api/orders/[code].js ----
async function orderCodeHandler(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return withCors(new Response(null,{status:204}),req);
  if (req.method !== "GET") return withCors(json({error:"Method not allowed"},405),req);

  let user;
  try { user = await requireUser(req,context.env); }
  catch { return withCors(json({error:"Bạn cần đăng nhập"},401),req); }

  const code = context.params.code;
  const row = await context.env.DB.prepare(`
    SELECT o.code,o.amount_vnd,o.status,o.created_at,
           p.name product_name,p.duration_days
    FROM orders o JOIN products p ON p.id=o.product_id
    WHERE o.code=? AND o.user_id=?
  `).bind(code,user.id).first();

  if (!row) return withCors(json({error:"Không tìm thấy đơn hàng"},404),req);
  return withCors(json({order:row}),req);
}

// ---- functions/api/orders/[code]/check-payment.js ----
async function checkPaymentHandler(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return withCors(new Response(null,{status:204}),req);
  if (req.method !== "POST") return withCors(json({error:"Method not allowed"},405),req);

  let user;
  try { user = await requireUser(req,context.env); }
  catch { return withCors(json({error:"Bạn cần đăng nhập"},401),req); }

  const code = context.params.code;
  const order = await context.env.DB.prepare(`
    SELECT o.*,p.duration_days
    FROM orders o JOIN products p ON p.id=o.product_id
    WHERE o.code=? AND o.user_id=?
  `).bind(code,user.id).first();

  if (!order) return withCors(json({error:"Không tìm thấy đơn hàng"},404),req);

  // Safe default: never issue a paid license without a verified Card2K result.
  return withCors(json({
    ok:false,
    verified:false,
    status:order.status,
    error:"Card2K chưa được nối API xác minh thật. Chưa cấp license để tránh giả thanh toán."
  },409),req);
}

// ---- functions/api/licenses.js ----
async function licensesHandler(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return withCors(new Response(null,{status:204}),req);
  if (req.method !== "GET") return withCors(json({error:"Method not allowed"},405),req);

  let user;
  try { user = await requireUser(req,context.env); }
  catch { return withCors(json({error:"Bạn cần đăng nhập"},401),req); }

  const rows = await context.env.DB.prepare(`
    SELECT l.license_key,l.expires_at,l.created_at,p.name product_name,o.code order_code
    FROM licenses l
    JOIN products p ON p.id=l.product_id
    JOIN orders o ON o.id=l.order_id
    WHERE l.user_id=?
    ORDER BY l.id DESC
  `).bind(user.id).all();

  return withCors(json({licenses:rows.results || []}),req);
}

function notFound() { return new Response("Not Found", {status:404}); }

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        if (url.pathname !== '/api/health') await ensureSchema(env);
        let response;
        if (url.pathname === '/api/health') response = await healthHandler({request, env, params:{}});
        else if (url.pathname === '/api/products') response = await productsHandler({request, env, params:{}});
        else if (url.pathname === '/api/auth/register') response = await registerHandler({request, env, params:{}});
        else if (url.pathname === '/api/auth/login') response = await loginHandler({request, env, params:{}});
        else if (url.pathname === '/api/auth/logout') response = await logoutHandler({request, env, params:{}});
        else if (url.pathname === '/api/auth/me') response = await meHandler({request, env, params:{}});
        else if (url.pathname === '/api/orders') response = await ordersHandler({request, env, params:{}});
        else if (url.pathname === '/api/licenses') response = await licensesHandler({request, env, params:{}});
        else {
          const m = url.pathname.match(/^\/api\/orders\/([^/]+)\/check-payment\/?$/);
          if (m) response = await checkPaymentHandler({request, env, params:{code:decodeURIComponent(m[1])}});
          else {
            const m2 = url.pathname.match(/^\/api\/orders\/([^/]+)\/?$/);
            if (m2) response = await orderCodeHandler({request, env, params:{code:decodeURIComponent(m2[1])}});
            else response = notFound();
          }
        }
        return response;
      } catch (err) {
        console.error('API error', err);
        return withCors(json({error:'Server error'},500), request);
      }
    }
    return env.ASSETS.fetch(request);
  }
};
