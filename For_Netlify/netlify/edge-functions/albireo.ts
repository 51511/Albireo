import type { Context } from "@netlify/edge-functions";

// === Configuration ===
const DIFFICULTY = 5; 
const SECRET_KEY = "NETLIFY_ALBIREO_SECRET_KEY_CHANGE_ME"; // ★ 請務必修改這裡
const BOT_AGENTS = ["google", "bingbot", "yahoo", "duckduckbot"];

// === Crypto Utils ===
async function sign(msg: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(SECRET_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function verify(msg: string, sig: string): Promise<boolean> {
  const expected = await sign(msg);
  return expected === sig;
}

async function checkPoW(challenge: string, nonce: string, response: string, difficulty: number): Promise<boolean> {
  const msg = challenge + String(nonce);
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(msg));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const calculated = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  if (calculated !== response) return false;
  const prefix = "0".repeat(difficulty);
  if (!calculated.startsWith(prefix)) return false;
  return true;
}

// === HTML Generator ===
const GENERATE_HTML = (challenge: string) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
  <title>Security Check | Albireo</title>
  <style>
    :root { --primary: #00ad9f; --bg: #f4f6f8; --card: #ffffff; --text: #2d3748; }
    @media (prefers-color-scheme: dark) { :root { --bg: #121212; --card: #1e1e1e; --text: #ffffff; } }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
    .box { background: var(--card); padding: 40px; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 100%; }
    .mascot { width: 120px; height: 120px; border-radius: 50%; object-fit: cover; border: 4px solid var(--card); box-shadow: 0 0 0 4px var(--primary); margin-bottom: 20px; }
    h1 { margin-bottom: 10px; }
    button { background: var(--primary); color: white; border: none; padding: 12px 30px; border-radius: 8px; font-size: 1rem; cursor: pointer; margin-top: 20px; width: 100%; }
    button:disabled { opacity: 0.7; }
  </style>
</head>
<body>
  <div class="box">
    <img src="/anubis-dist/img/pensive.webp" class="mascot" id="mascot-img" alt="Guard">
    <h1>Security Check</h1>
    <p>Please verify you are human.</p>
    <button id="verify-btn">I am human</button>
  </div>
  <script>
    const CHALLENGE = "${challenge}";
    const DIFFICULTY = ${DIFFICULTY};
    const IMG_CHECK = "/anubis-dist/img/pensive.webp";
    const IMG_SUCCESS = "/anubis-dist/img/happy.webp";
    const IMG_FAILED = "/anubis-dist/img/reject.webp";
    const btn = document.getElementById('verify-btn');
    const img = document.getElementById('mascot-img');

    async function sha256(str) {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function mine() {
      btn.disabled = true; btn.innerText = 'Calculating...'; img.src = IMG_CHECK; 
      const prefix = "0".repeat(DIFFICULTY);
      let nonce = 0;
      while(true) {
        if (nonce % 1000 === 0) await new Promise(r => setTimeout(r, 0));
        const hash = await sha256(CHALLENGE + nonce);
        if (hash.startsWith(prefix)) { submit(nonce, hash); break; }
        nonce++;
      }
    }

    function submit(nonce, response) {
      btn.innerText = 'Verifying...';
      const fd = new FormData();
      fd.append('nonce', nonce); fd.append('response', response); fd.append('verify', 'true');
      fetch(window.location.href, { method: 'POST', body: fd }).then(async res => {
        if (res.ok) {
          img.src = IMG_SUCCESS; btn.innerText = 'Success!';
          setTimeout(() => window.location.replace(window.location.href), 500);
        } else {
          img.src = IMG_FAILED; btn.innerText = 'Retry'; btn.disabled = false;
        }
      }).catch(() => { img.src = IMG_FAILED; btn.innerText = 'Error'; btn.disabled = false; });
    }
    btn.addEventListener('click', mine);
  </script>
</body>
</html>
`;

// === Netlify Entry Point ===
export default async (request: Request, context: Context) => {
  if (SECRET_KEY === "NETLIFY_ALBIREO_SECRET_KEY_CHANGE_ME") {
    return new Response("SECURITY ERROR: Please change SECRET_KEY in albireo.ts", { status: 500 });
  }

  const url = new URL(request.url);
  const ua = (request.headers.get("User-Agent") || "").toLowerCase();

  // 1. Pass static assets
  if (url.pathname.match(/\.(png|jpg|jpeg|gif|webp|css|js|ico|svg|json)$/) || url.pathname.startsWith("/anubis-dist/")) {
    return context.next();
  }
  
  // 2. Pass SEO bots
  if (BOT_AGENTS.some(b => ua.includes(b))) return context.next();

  // 3. Check Cookie
  const cookie = request.headers.get("Cookie") || "";
  if (cookie.includes("anubis_solved=true")) return context.next();

  // 4. Handle POST
  if (request.method === "POST") {
    try {
      const fd = await request.formData();
      if (!fd.has('verify')) return new Response("Bad Request", { status: 400 });

      const nonce = fd.get("nonce") as string;
      const response = fd.get("response") as string;
      
      const cStr = cookie.split(';').find(c => c.trim().startsWith('anubis_challenge='));
      if (!cStr) return new Response("Expired", { status: 403 });

      const [challenge, sig] = decodeURIComponent(cStr.split('=')[1].trim()).split('.');

      if (!await verify(challenge, sig)) return new Response("Invalid Signature", { status: 403 });
      if (!await checkPoW(challenge, nonce, response, DIFFICULTY)) return new Response("POW Failed", { status: 403 });

      const headers = new Headers();
      headers.append("Set-Cookie", "anubis_solved=true; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400");
      
      return new Response(JSON.stringify({ success: true }), { status: 200, headers });
    } catch (e) {
      return new Response("Server Error", { status: 500 });
    }
  }

  // 5. Issue Challenge
  const rnd = crypto.randomUUID().replace(/-/g, '');
  const sig = await sign(rnd);
  const headers = new Headers();
  headers.set("Content-Type", "text/html");
  headers.set("Cache-Control", "private, no-cache, no-store, must-revalidate");
  headers.set("Set-Cookie", `anubis_challenge=${encodeURIComponent(rnd + '.' + sig)}; Path=/; HttpOnly; Secure; SameSite=Lax`);
  
  return new Response(GENERATE_HTML(rnd), { headers });
};
