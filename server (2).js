'use strict';
/*
 * Mell Wallet — сервер на Node.js (без внешних зависимостей).
 *
 * Запуск:   npm start      (по умолчанию http://localhost:3000)
 *
 * Регистрация и вход по логину и паролю. Случайный кошелёк создаётся сразу
 * при регистрации и дальше не меняется.
 *
 * Переменные окружения:
 *   PORT, HOST        порт и хост (3000, 0.0.0.0)
 *   DATA_DIR          где хранить базу (./data)
 *   ADMIN_LOGIN       логин админа (admin)
 *   ADMIN_PASSWORD    пароль админа. Если задан, применяется при каждом запуске.
 *                     Если не задан, при первом создании админа генерируется
 *                     случайный пароль и печатается в консоль один раз.
 *   COOKIE_SECURE=1   ставить Secure на cookie (нужно при HTTPS)
 *   TRUST_PROXY=1     брать IP из X-Forwarded-For (если сервер за прокси)
 *   SECRET            ключ для подписи сессий; если не задан, создаётся
 *                     и хранится в DATA_DIR/secret.key
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const HTML_FILE = path.join(__dirname, 'index.html');
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_FAILS = 5;
const LOCK_MS = 5 * 60 * 1000;
const ADDRESS_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
const PREFIXES = ['MQ', 'UQ', 'EQ'];
const LOGIN_RE = /^[a-z0-9_.-]{3,24}$/;
const ADDR_RE = /^(MQ|UQ|EQ)[A-Za-z0-9_-]{46}$/;
const MAX_AMOUNT = 1e12;

/* Монеты и цены в звёздах (должны совпадать с таблицей в index.html). */
const COINS = {
  fogcoin: { ticker: 'FGC', price: 35 },
  mytacoin: { ticker: 'MTC', price: 29 },
  oblacoin: { ticker: 'OBC', price: 24 },
  molcoin: { ticker: 'MLC', price: 19 },
  kotcoin: { ticker: 'KTC', price: 15 },
  dpgcoin: { ticker: 'DGC', price: 12 },
  eljcoin: { ticker: 'EJC', price: 9 },
  shlyacoin: { ticker: 'SHC', price: 7 },
  chekcoin: { ticker: 'CHC', price: 5 },
  kachestvocoin: { ticker: 'KSC', price: 3 },
  burmalcoin: { ticker: 'BLC', price: 2 },
};
const ADMIN_MTC = 1000000;   // у админа больше всего Mytacoin
const ADMIN_OTHER = 900000;  // и чуть меньше каждой из остальных монет
const ADMIN_LOGIN = String(process.env.ADMIN_LOGIN || 'admin').trim().toLowerCase();

/* ---------- хранилище ---------- */

fs.mkdirSync(DATA_DIR, { recursive: true });

function loadSecret() {
  if (process.env.SECRET) return process.env.SECRET;
  const f = path.join(DATA_DIR, 'secret.key');
  try {
    return fs.readFileSync(f, 'utf8').trim();
  } catch (_) {
    const s = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(f, s, { mode: 0o600 });
    return s;
  }
}
const SECRET = loadSecret();

let db = { users: {}, sessions: {} };
try {
  db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
} catch (_) { /* первый запуск */ }

const addrIndex = {}; // адрес -> логин (ключ в db.users)
for (const [key, u] of Object.entries(db.users)) {
  u.balances = u.balances || {};
  u.history = u.history || [];
  addrIndex[u.address] = key;
}

function saveDb() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}

/* ---------- пользователи, пароли, балансы ---------- */

function scrypt(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => (err ? reject(err) : resolve(key)));
  });
}
async function makePass(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt);
  return { salt: salt.toString('hex'), hash: key.toString('hex') };
}
const DUMMY_SALT = crypto.randomBytes(16);

function hmac(value) {
  return crypto.createHmac('sha256', SECRET).update(value).digest('hex');
}
function safeEqual(a, b) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function isAdmin(u) { return u.login === ADMIN_LOGIN; }
function seedAdmin(u) {
  if (!isAdmin(u) || u.seeded) return;
  for (const id of Object.keys(COINS)) {
    u.balances[id] = (u.balances[id] || 0) + (id === 'mytacoin' ? ADMIN_MTC : ADMIN_OTHER);
  }
  u.seeded = true;
}
function userByAddress(a) { return db.users[addrIndex[a]] || null; }
function shortAddr(a) { return a.slice(0, 6) + '…' + a.slice(-4); }
function pushHistory(u, entry) {
  u.history.unshift(Object.assign({ t: new Date().toISOString() }, entry));
  if (u.history.length > 50) u.history.length = 50;
}
function publicUser(u) {
  return { login: u.login, address: u.address, isAdmin: isAdmin(u), balances: u.balances, history: u.history.slice(0, 20) };
}
function parseAmount(v) {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1 && v <= MAX_AMOUNT ? v : null;
}
function normLogin(v) {
  if (typeof v !== 'string') return null;
  const l = v.trim().toLowerCase();
  return LOGIN_RE.test(l) ? l : null;
}

/* Адрес создаётся один раз при регистрации и дальше не меняется. */
function generateAddress() {
  const prefix = PREFIXES[crypto.randomInt(0, PREFIXES.length)];
  for (;;) {
    const bytes = crypto.randomBytes(46);
    let body = '';
    for (const b of bytes) body += ADDRESS_ALPHABET[b & 63];
    const addr = prefix + body;
    if (!addrIndex[addr]) return addr;
  }
}
function createUser(login, pass) {
  const u = db.users[login] = {
    login, pass, address: generateAddress(), createdAt: new Date().toISOString(), balances: {}, history: [],
  };
  addrIndex[u.address] = login;
  seedAdmin(u);
  return u;
}

/* ---------- лимиты и сессии ---------- */

const hits = new Map();      // ключ -> [timestamps]
const lockouts = new Map();  // логин -> { fails, until }

function rateLimited(key, limit, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  return arr.length > limit;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) if (!v.some((t) => now - t < 600000)) hits.delete(k);
  for (const [k, v] of lockouts) if (v.until < now && !v.fails) lockouts.delete(k);
  let changed = false;
  for (const [k, s] of Object.entries(db.sessions)) {
    if (s.exp < now) { delete db.sessions[k]; changed = true; }
  }
  if (changed) saveDb();
}, 60 * 1000).unref();

function createSession(login) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.sessions[hmac(token)] = { login, exp: Date.now() + SESSION_TTL_MS };
  return token;
}
function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
function currentUser(req) {
  const token = getCookie(req, 'mw_sid');
  if (!token) return null;
  const s = db.sessions[hmac(token)];
  if (!s || s.exp < Date.now()) return null;
  return db.users[s.login] || null;
}
function cookieHeader(value, maxAge) {
  return 'mw_sid=' + value + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + maxAge + (COOKIE_SECURE ? '; Secure' : '');
}

/* ---------- HTTP ---------- */

function clientIp(req) {
  if (TRUST_PROXY) {
    const xf = req.headers['x-forwarded-for'];
    if (xf) return String(xf).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function send(res, status, body, headers) {
  const isObj = typeof body === 'object';
  res.writeHead(status, Object.assign({
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
  }, headers));
  res.end(isObj ? JSON.stringify(body) : body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] || '');
    if (!ct.startsWith('application/json')) return reject({ status: 415, error: 'Нужен JSON' });
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 4096) { reject({ status: 413, error: 'Слишком большой запрос' }); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch (_) { reject({ status: 400, error: 'Некорректный JSON' }); }
    });
    req.on('error', () => reject({ status: 400, error: 'Ошибка запроса' }));
  });
}

function startSession(res, user, extra) {
  const token = createSession(user.login);
  saveDb();
  return send(res, 200, Object.assign(publicUser(user), extra),
    { 'Set-Cookie': cookieHeader(token, SESSION_TTL_MS / 1000) });
}

async function handleApi(req, res, url) {
  const ip = clientIp(req);

  if (req.method === 'GET' && url === '/api/me') {
    const u = currentUser(req);
    if (!u) return send(res, 401, { error: 'Не выполнен вход' });
    return send(res, 200, publicUser(u));
  }

  if (req.method === 'POST' && url === '/api/logout') {
    const token = getCookie(req, 'mw_sid');
    if (token && db.sessions[hmac(token)]) { delete db.sessions[hmac(token)]; saveDb(); }
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
  }

  /* ---------- регистрация и вход ---------- */

  if (req.method === 'POST' && url === '/api/register') {
    if (rateLimited('reg:' + ip, 10, 10 * 60 * 1000)) return send(res, 429, { error: 'Слишком много попыток, попробуйте позже' });
    const b = await readJson(req);
    const login = normLogin(b.login);
    const pw = b.password;
    if (!login) return send(res, 400, { error: 'Логин: 3–24 символа, латиница, цифры, _ . -' });
    if (typeof pw !== 'string' || pw.length < 8 || pw.length > 128) return send(res, 400, { error: 'Пароль: от 8 до 128 символов' });
    if (db.users[login]) return send(res, 409, { error: 'Этот логин уже занят' });
    const pass = await makePass(pw);
    if (db.users[login]) return send(res, 409, { error: 'Этот логин уже занят' });
    // Случайный кошелёк создаётся сразу при регистрации.
    const user = createUser(login, pass);
    return startSession(res, user, { isNew: true });
  }

  if (req.method === 'POST' && url === '/api/login') {
    if (rateLimited('log:' + ip, 30, 10 * 60 * 1000)) return send(res, 429, { error: 'Слишком много попыток, попробуйте позже' });
    const b = await readJson(req);
    const login = normLogin(b.login);
    const pw = typeof b.password === 'string' && b.password.length <= 128 ? b.password : '';
    const bad = () => send(res, 401, { error: 'Неверный логин или пароль' });
    if (!login || !pw) return bad();
    const lk = lockouts.get(login);
    if (lk && lk.until > Date.now()) return send(res, 429, { error: 'Слишком много неверных попыток. Подождите несколько минут' });

    const u = db.users[login];
    const hasPass = !!(u && u.pass);
    // Хэш считаем всегда, чтобы время ответа не выдавало, существует ли логин.
    const key = await scrypt(pw, hasPass ? Buffer.from(u.pass.salt, 'hex') : DUMMY_SALT);
    if (!hasPass || !safeEqual(key.toString('hex'), u.pass.hash)) {
      const l = lockouts.get(login) || { fails: 0, until: 0 };
      l.fails++;
      if (l.fails >= MAX_FAILS) { l.until = Date.now() + LOCK_MS; l.fails = 0; }
      lockouts.set(login, l);
      return bad();
    }
    lockouts.delete(login);
    return startSession(res, u, { isNew: false });
  }

  /* ---------- переводы ---------- */

  if (req.method === 'POST' && url === '/api/transfer') {
    const me = currentUser(req);
    if (!me) return send(res, 401, { error: 'Не выполнен вход' });
    if (rateLimited('tx:' + ip, 60, 60 * 1000)) return send(res, 429, { error: 'Слишком много операций, подождите минуту' });
    const b = await readJson(req);
    const amount = parseAmount(b.amount);
    const to = typeof b.to === 'string' ? b.to.trim() : '';
    if (!COINS[b.coin]) return send(res, 400, { error: 'Неизвестная монета' });
    if (!amount) return send(res, 400, { error: 'Введите целое количество монет' });
    if (!ADDR_RE.test(to)) return send(res, 400, { error: 'Некорректный адрес кошелька' });
    const rcpt = userByAddress(to);
    if (!rcpt) return send(res, 404, { error: 'Кошелёк с таким адресом не найден' });
    if (rcpt === me) return send(res, 400, { error: 'Нельзя отправить самому себе' });
    if ((me.balances[b.coin] || 0) < amount) return send(res, 400, { error: 'Недостаточно монет' });
    me.balances[b.coin] -= amount;
    rcpt.balances[b.coin] = (rcpt.balances[b.coin] || 0) + amount;
    pushHistory(me, { type: 'out', coin: b.coin, amount, peer: shortAddr(to) });
    pushHistory(rcpt, { type: 'in', coin: b.coin, amount, peer: shortAddr(me.address) });
    saveDb();
    return send(res, 200, publicUser(me));
  }

  if (req.method === 'POST' && url === '/api/exchange') {
    const me = currentUser(req);
    if (!me) return send(res, 401, { error: 'Не выполнен вход' });
    if (rateLimited('tx:' + ip, 60, 60 * 1000)) return send(res, 429, { error: 'Слишком много операций, подождите минуту' });
    const b = await readJson(req);
    const amount = parseAmount(b.amount);
    if (!COINS[b.from] || !COINS[b.to] || b.from === b.to) return send(res, 400, { error: 'Выберите две разные монеты' });
    if (!amount) return send(res, 400, { error: 'Введите целое количество монет' });
    const pf = COINS[b.from].price, pt = COINS[b.to].price;
    const got = Math.floor(amount * pf / pt);
    if (got < 1) return send(res, 400, { error: 'Слишком маленькая сумма для обмена' });
    const spent = Math.ceil(got * pt / pf); // списываем только то, что реально нужно
    if ((me.balances[b.from] || 0) < spent) return send(res, 400, { error: 'Недостаточно монет' });
    me.balances[b.from] -= spent;
    me.balances[b.to] = (me.balances[b.to] || 0) + got;
    pushHistory(me, { type: 'swap', coin: b.from, amount: spent, coin2: b.to, amount2: got });
    saveDb();
    return send(res, 200, publicUser(me));
  }

  /* Админ выдаёт крипту на любой кошелёк. */
  if (req.method === 'POST' && url === '/api/admin/issue') {
    const me = currentUser(req);
    if (!me) return send(res, 401, { error: 'Не выполнен вход' });
    if (!isAdmin(me)) return send(res, 403, { error: 'Только для админа' });
    const b = await readJson(req);
    const amount = parseAmount(b.amount);
    const to = typeof b.to === 'string' ? b.to.trim() : '';
    if (!COINS[b.coin]) return send(res, 400, { error: 'Неизвестная монета' });
    if (!amount) return send(res, 400, { error: 'Введите целое количество монет' });
    if (!ADDR_RE.test(to)) return send(res, 400, { error: 'Некорректный адрес кошелька' });
    const rcpt = userByAddress(to);
    if (!rcpt) return send(res, 404, { error: 'Кошелёк с таким адресом не найден' });
    rcpt.balances[b.coin] = (rcpt.balances[b.coin] || 0) + amount;
    pushHistory(rcpt, { type: 'issue', coin: b.coin, amount, peer: 'Админ' });
    if (rcpt !== me) pushHistory(me, { type: 'issued', coin: b.coin, amount, peer: shortAddr(to) });
    saveDb();
    return send(res, 200, publicUser(me));
  }

  return send(res, 404, { error: 'Не найдено' });
}

const server = http.createServer(async (req, res) => {
  const url = (req.url || '/').split('?')[0];
  try {
    if (url.startsWith('/api/')) return await handleApi(req, res, url);

    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      const nonce = crypto.randomBytes(16).toString('base64');
      const html = fs.readFileSync(HTML_FILE, 'utf8').replace(/\{\{NONCE\}\}/g, nonce);
      return send(res, 200, html, {
        'Content-Security-Policy':
          "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      });
    }
    if (url === '/health') return send(res, 200, { ok: true });
    return send(res, 404, { error: 'Не найдено' });
  } catch (e) {
    if (e && e.status) return send(res, e.status, { error: e.error });
    console.error(e);
    return send(res, 500, { error: 'Внутренняя ошибка сервера' });
  }
});

/* Аккаунт админа создаётся при запуске. */
async function ensureAdmin() {
  if (!LOGIN_RE.test(ADMIN_LOGIN)) throw new Error('ADMIN_LOGIN должен быть 3–24 символа: a-z, 0-9, _ . -');
  const envPw = process.env.ADMIN_PASSWORD;
  let u = db.users[ADMIN_LOGIN];
  if (!u || !u.pass) {
    const pw = envPw || crypto.randomBytes(9).toString('base64url');
    const pass = await makePass(pw);
    u = createUser(ADMIN_LOGIN, pass);
    saveDb();
    console.log('Создан аккаунт админа. Логин: ' + ADMIN_LOGIN + (envPw ? '' : '  Пароль: ' + pw + '  (показан один раз, запишите)'));
    return;
  }
  let changed = false;
  if (envPw) { u.pass = await makePass(envPw); changed = true; }
  if (!u.seeded) { seedAdmin(u); changed = true; }
  if (changed) saveDb();
}

ensureAdmin().then(() => {
  server.listen(PORT, HOST, () => console.log('Mell Wallet: http://localhost:' + PORT));
}).catch((e) => { console.error(e.message || e); process.exit(1); });
