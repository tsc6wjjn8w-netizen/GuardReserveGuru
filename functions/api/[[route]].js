// GuardReserveGuru v2 API — Cloudflare Pages Function + D1
// Routes: POST register | POST login | POST logout | GET data | PUT data
// Optional env: SIGNUP_CODE (invite code needed to create accounts), PIN_PEPPER (secret mixed into PIN hashes)

const enc = new TextEncoder();
const NOW = () => Date.now();
const SESSION_MS = 90 * 24 * 3600e3;
const LOCK_AFTER = 5, LOCK_MS = 15 * 60e3;
const MAX_DATA = 900000;

const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };

async function hashPin(env, key, pin, saltHex) {
  const k = await crypto.subtle.importKey('raw', enc.encode((env.PIN_PEPPER || '') + ':' + key + ':' + pin), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: 100000 }, k, 256));
}

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const fail = (msg, status = 400, extra = {}) => json({ error: msg, ...extra }, status);

const nameKey = n => n.trim().toLowerCase().replace(/\s+/g, ' ');
const nameOk = n => typeof n === 'string' && /^[\p{L}\p{N} ._'-]{2,30}$/u.test(n.trim());
const pinOk = p => typeof p === 'string' && /^\d{4}$/.test(p);
const dataOk = d => d && typeof d === 'object' && !Array.isArray(d) && JSON.stringify(d).length <= MAX_DATA;

async function newSession(env, userId) {
  const token = rand(32);
  const t = NOW();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(t).run();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)').bind(await sha(token), userId, t + SESSION_MS).run();
  return token;
}

async function authed(env, request) {
  const m = /^Bearer ([0-9a-f]{64})$/.exec(request.headers.get('authorization') || '');
  if (!m) return null;
  const h = await sha(m[1]);
  const s = await env.DB.prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash = ?').bind(h).first();
  if (!s) return null;
  if (s.expires_at < NOW()) { await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(h).run(); return null; }
  return { userId: s.user_id, tokenHash: h };
}

async function readBody(request) {
  const txt = await request.text();
  if (txt.length > MAX_DATA + 20000) throw Object.assign(new Error('too big'), { status: 413 });
  try { return JSON.parse(txt || '{}'); } catch { throw Object.assign(new Error('bad json'), { status: 400 }); }
}

export async function onRequest({ request, env }) {
  try {
    if (!env.DB) return fail('Database not connected: the D1 binding named DB is missing.', 500);
    const route = new URL(request.url).pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '');
    const method = request.method;

    if (route === 'register' && method === 'POST') {
      const b = await readBody(request);
      if (env.SIGNUP_CODE && String(b.code || '').trim() !== env.SIGNUP_CODE) return fail('Invite code is missing or wrong.', 403);
      if (!nameOk(b.name)) return fail('Name must be 2–30 characters (letters, numbers, spaces, . _ - \').');
      if (!pinOk(b.pin)) return fail('Last 4 must be exactly 4 digits.');
      if (b.data !== undefined && !dataOk(b.data)) return fail('Import data is invalid or too large.');
      const key = nameKey(b.name), name = b.name.trim().replace(/\s+/g, ' ');
      const salt = rand(16), t = NOW();
      let userId;
      try {
        const r = await env.DB.prepare('INSERT INTO users (name, name_key, pin_salt, pin_hash, created_at) VALUES (?,?,?,?,?)')
          .bind(name, key, salt, await hashPin(env, key, b.pin, salt), t).run();
        userId = r.meta.last_row_id;
      } catch (e) {
        if (/UNIQUE/i.test(String(e.message || e))) return fail('That name is already taken. Pick another (add initials or a number).', 409);
        throw e;
      }
      const has = b.data !== undefined;
      await env.DB.prepare('INSERT INTO user_data (user_id, rev, json, updated_at) VALUES (?,?,?,?)')
        .bind(userId, has ? 1 : 0, has ? JSON.stringify(b.data) : '{}', t).run();
      const token = await newSession(env, userId);
      return json({ token, name, key, rev: has ? 1 : 0, data: has ? b.data : {} });
    }

    if (route === 'login' && method === 'POST') {
      const b = await readBody(request);
      const generic = 'Name and last 4 did not match.';
      if (!nameOk(b.name) || !pinOk(b.pin)) return fail(generic, 401);
      const key = nameKey(b.name);
      const u = await env.DB.prepare('SELECT * FROM users WHERE name_key = ?').bind(key).first();
      if (!u) { await hashPin(env, key, b.pin, '00'.repeat(16)); return fail(generic, 401); }
      const t = NOW();
      if (u.locked_until > t) return fail(`Too many wrong tries. Try again in ${Math.ceil((u.locked_until - t) / 60000)} min.`, 429);
      if (!same(await hashPin(env, key, b.pin, u.pin_salt), u.pin_hash)) {
        const fails = u.fails + 1;
        if (fails >= LOCK_AFTER) await env.DB.prepare('UPDATE users SET fails = 0, locked_until = ? WHERE id = ?').bind(t + LOCK_MS, u.id).run();
        else await env.DB.prepare('UPDATE users SET fails = ? WHERE id = ?').bind(fails, u.id).run();
        return fail(generic, 401);
      }
      if (u.fails) await env.DB.prepare('UPDATE users SET fails = 0 WHERE id = ?').bind(u.id).run();
      const d = await env.DB.prepare('SELECT rev, json FROM user_data WHERE user_id = ?').bind(u.id).first();
      const token = await newSession(env, u.id);
      return json({ token, name: u.name, key, rev: d ? d.rev : 0, data: d ? JSON.parse(d.json) : {} });
    }

    const a = await authed(env, request);
    if (!a) return fail('Not signed in.', 401);

    if (route === 'logout' && method === 'POST') {
      await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(a.tokenHash).run();
      return json({ ok: true });
    }

    if (route === 'data' && method === 'GET') {
      const d = await env.DB.prepare('SELECT rev, json FROM user_data WHERE user_id = ?').bind(a.userId).first();
      return json({ rev: d ? d.rev : 0, data: d ? JSON.parse(d.json) : {} });
    }

    if (route === 'data' && method === 'PUT') {
      const b = await readBody(request);
      if (!Number.isInteger(b.rev) || !dataOk(b.data)) return fail('Bad data.');
      const r = await env.DB.prepare('UPDATE user_data SET json = ?, rev = rev + 1, updated_at = ? WHERE user_id = ? AND rev = ?')
        .bind(JSON.stringify(b.data), NOW(), a.userId, b.rev).run();
      if (r.meta.changes === 1) return json({ rev: b.rev + 1 });
      const d = await env.DB.prepare('SELECT rev, json FROM user_data WHERE user_id = ?').bind(a.userId).first();
      return fail('Changed on another device.', 409, { rev: d ? d.rev : 0, data: d ? JSON.parse(d.json) : {} });
    }

    return fail('Not found.', 404);
  } catch (e) {
    return fail(e.status ? e.message : 'Server error.', e.status || 500);
  }
}
