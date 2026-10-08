/**
 * Gerbang login email + password untuk dasbor Tzu Chi (Cloudflare Worker + static assets).
 * Pengecekan dilakukan di SERVER, jadi halaman dasbor tidak terkirim sebelum login benar.
 *
 * Variabel (Settings → Variables and Secrets, tipe RUNTIME):
 *   USER_PASSWORDS  (secret) JSON {"email1":"password1","email2":"password2",...} → password per email
 *   SESSION_SECRET  (secret) teks acak ≥ 32 karakter
 * Cadangan bila USER_PASSWORDS belum diisi: ALLOWED_EMAILS (var) + APP_PASSWORD (secret) = satu password bersama.
 */
const SESSION_HOURS = 12;
const enc = new TextEncoder();
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
const hkey = (secret, use) => crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC', hash:'SHA-256'}, false, [use]);

async function sign(payload, secret){
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hkey(secret,'sign'), enc.encode(body));
  return body + '.' + b64u(sig);
}
async function verify(token, secret){
  try{
    const [body, sig] = (token || '').split('.');
    if(!body || !sig) return null;
    if(!await crypto.subtle.verify('HMAC', await hkey(secret,'verify'), unb64u(sig), enc.encode(body))) return null;
    const p = JSON.parse(new TextDecoder().decode(unb64u(body)));
    return p.exp > Date.now()/1000 ? p : null;
  }catch{ return null; }
}
// perbandingan waktu-konstan lewat hash SHA-256
async function sameSecret(a, b){
  const [x, y] = await Promise.all([a, b].map(v => crypto.subtle.digest('SHA-256', enc.encode(String(v)))));
  const A = new Uint8Array(x), B = new Uint8Array(y); let d = 0;
  for(let i = 0; i < A.length; i++) d |= A[i] ^ B[i];
  return d === 0;
}
const getCookie = (req, name) =>
  (req.headers.get('Cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))?.slice(name.length + 1);
const cookie = (name, val, maxAge) => `${name}=${val}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function loginPage(error = '', status = 401, cookies = []){
  const html = `<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Masuk — Dasbor Tzu Chi</title>
<style>body{font-family:system-ui,sans-serif;background:#f6f4f1;color:#222;display:grid;place-items:center;min-height:100vh;margin:0}
form{background:#fff;border:1px solid #ddd;border-radius:12px;padding:28px;width:min(340px,90vw)}
h1{font-size:18px;margin:0 0 4px}p{color:#555;font-size:13px;margin:0 0 16px}
input{width:100%;box-sizing:border-box;padding:10px;margin-bottom:10px;border:1px solid #bbb;border-radius:8px;font-size:14px}
button{width:100%;padding:10px;border:1px solid #222;background:#222;color:#fff;border-radius:8px;font-weight:600;cursor:pointer}
.e{color:#a00;font-size:13px;margin:0 0 10px}</style></head>
<body><form method="POST" action="/auth/login"><h1>Dasbor Tzu Chi</h1><p>Biro Mindset · khusus pengguna yang diizinkan</p>
${error ? `<div class="e">${esc(error)}</div>` : ''}
<input type="email" name="email" placeholder="Email" autocomplete="username" required>
<input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
<button type="submit">Masuk</button></form></body></html>`;
  const h = new Headers({'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});
  cookies.forEach(v => h.append('Set-Cookie', v));
  return new Response(html, {status, headers:h});
}

// Peta email → password. Sumber utama USER_PASSWORDS; cadangan: ALLOWED_EMAILS + APP_PASSWORD.
function getUsers(env){
  const m = new Map();
  try{
    const o = JSON.parse(env.USER_PASSWORDS || '');
    for(const [k, v] of Object.entries(o)) if(typeof v === 'string' && v) m.set(k.trim().toLowerCase(), v);
    if(m.size) return m;
  }catch{}
  if(env.APP_PASSWORD)
    (env.ALLOWED_EMAILS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean).forEach(e => m.set(e, env.APP_PASSWORD));
  return m;
}
// "versi password": sesi otomatis tidak berlaku bila password email tsb diganti/dihapus
const pwVersion = async (email, pw) =>
  b64u(await crypto.subtle.digest('SHA-256', enc.encode(email + ':' + pw))).slice(0, 16);

export default {
  async fetch(request, env){
    const url = new URL(request.url);
    const users = getUsers(env);

    if(url.pathname === '/auth/login' && request.method === 'POST'){
      const f = await request.formData();
      const email = String(f.get('email') || '').trim().toLowerCase(), pw = String(f.get('password') || '');
      const expected = users.get(email);
      // selalu lakukan perbandingan agar waktu respons tidak membocorkan email mana yang terdaftar
      const same = await sameSecret(pw, expected ?? b64u(crypto.getRandomValues(new Uint8Array(16))));
      if(!(expected !== undefined && same)){
        await new Promise(r => setTimeout(r, 1000)); // memperlambat tebak-tebakan
        return loginPage('Email atau password salah.', 401);
      }
      const sid = await sign({email, pv: await pwVersion(email, expected), exp: Math.floor(Date.now()/1000) + SESSION_HOURS*3600}, env.SESSION_SECRET);
      const h = new Headers({Location:'/', 'Cache-Control':'no-store'});
      h.append('Set-Cookie', cookie('sid', sid, SESSION_HOURS*3600));
      return new Response(null, {status:303, headers:h});
    }
    if(url.pathname === '/auth/logout') return loginPage('Anda sudah keluar.', 200, [cookie('sid','',0)]);

    const sess = await verify(getCookie(request,'sid'), env.SESSION_SECRET);
    const cur = sess && users.get(String(sess.email).toLowerCase());
    if(!sess || cur === undefined || sess.pv !== await pwVersion(String(sess.email).toLowerCase(), cur)) return loginPage();

    const res = await env.ASSETS.fetch(request);
    const h = new Headers(res.headers);
    h.set('Cache-Control','private, no-store'); h.set('X-Robots-Tag','noindex'); h.set('Referrer-Policy','no-referrer');
    return new Response(res.body, {status:res.status, statusText:res.statusText, headers:h});
  }
};
