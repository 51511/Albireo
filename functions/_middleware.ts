interface Env {
  ASSETS: Fetcher;
}


// === Configuration ===
const DIFFICULTY = 3; // 可調整難度：數字越大越慢，建議 3~6
const SECRET_KEY = "ALBIREO_SECRET_KEY_CHANGE_ME"; // ★ 請務必修改這裡
const BOT_AGENTS = ["google", "bingbot", "yahoo", "duckduckbot"];
const CHALLENGE_TTL = 5 * 60 * 1000;
const HONEYPOT_TTL = 60 * 60 * 1000; // Honeypot 連結有效期 1 小時
const HONEYPOT_PREFIX = "/albireo-trap-";

// === UI Strings（可自訂語言）===
const STRINGS = {
  title: "Security Check | Albireo",
  heading: "Security Check",
  description: "Please verify you are human.",
  btn_start: "I am human",
  btn_checking: "Checking...",
  btn_calculating: "Calculating...",
  btn_verifying: "Verifying...",
  btn_success: "Success!",
  btn_retry: "Retry",
  btn_error: "Error",
  btn_bot_detected: "Access Denied",
};

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

// === Honeypot Utils ===
// 產生帶時間戳的 honeypot path token：timestamp.HMAC
async function generateHoneypotToken(): Promise<string> {
  const timestamp = Date.now().toString();
  const sig = await sign("honeypot." + timestamp);
  // URL-safe base64
  const safeSig = sig.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return timestamp + "." + safeSig;
}

// 驗證 honeypot token 是否合法且未過期
async function verifyHoneypotToken(token: string): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [timestamp, safeSig] = parts;
  // 還原 URL-safe base64（補回 = padding）
  let sig = safeSig.replace(/-/g, '+').replace(/_/g, '/');
  while (sig.length % 4 !== 0) sig += '=';
  const issuedAt = parseInt(timestamp, 10);
  if (isNaN(issuedAt)) return false;
  if (Date.now() - issuedAt > HONEYPOT_TTL) return false;
  return await verify("honeypot." + timestamp, sig);
}

// === Safe Redirect Validator ===
function safeRedirect(path: string): string {
  try {
    if (path.startsWith('/') && !path.startsWith('//')) return path;
  } catch (_) {}
  return '/';
}

// === HTML Generator ===
const GENERATE_HTML = (challenge: string, originalPath: string) => `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<title>${STRINGS.title}</title>
<style>
:root { --primary: #00ad9f; --bg: #f4f6f8; --card: #ffffff; --text: #2d3748; }
@media (prefers-color-scheme: dark) { :root { --bg: #121212; --card: #1e1e1e; --text: #ffffff; } }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
.box { background: var(--card); padding: 40px; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 100%; }
.mascot { width: 120px; height: 120px; border-radius: 50%; object-fit: cover; border: 4px solid var(--card); box-shadow: 0 0 0 4px var(--primary); margin-bottom: 20px; }
.mascot-emoji { font-size: 80px; line-height: 1; margin-bottom: 20px; display: none; }
h1 { margin-bottom: 10px; }
button { background: var(--primary); color: white; border: none; padding: 12px 30px; border-radius: 8px; font-size: 1rem; cursor: pointer; margin-top: 20px; width: 100%; }
button:disabled { opacity: 0.7; }
</style>
</head>
<body>
<div class="box">
<img src="/albireo-dist/img/pensive.webp" class="mascot" id="mascot-img" alt="Guard"
onerror="this.style.display='none'; document.getElementById('mascot-emoji').style.display='block';">
<div class="mascot-emoji" id="mascot-emoji">😐</div>
<h1>${STRINGS.heading}</h1>
<p>${STRINGS.description}</p>
<button id="verify-btn">${STRINGS.btn_start}</button>
</div>
<script>
const CHALLENGE = "${challenge}";
const DIFFICULTY = ${DIFFICULTY};
const ORIGINAL_PATH = "${originalPath}";
const IMG_CHECK = "/albireo-dist/img/pensive.webp";
const IMG_SUCCESS = "/albireo-dist/img/happy.webp";
const IMG_FAILED = "/albireo-dist/img/reject.webp";
const EMOJI_CHECK = "😐";
const EMOJI_SUCCESS = "😊";
const EMOJI_FAILED = "❌";
const S = {
  checking: ${JSON.stringify(STRINGS.btn_checking)},
  calculating: ${JSON.stringify(STRINGS.btn_calculating)},
  verifying: ${JSON.stringify(STRINGS.btn_verifying)},
  success: ${JSON.stringify(STRINGS.btn_success)},
  retry: ${JSON.stringify(STRINGS.btn_retry)},
  error: ${JSON.stringify(STRINGS.btn_error)},
  bot_detected: ${JSON.stringify(STRINGS.btn_bot_detected)},
};
const btn = document.getElementById('verify-btn');
const img = document.getElementById('mascot-img');
const emoji = document.getElementById('mascot-emoji');
const usingEmoji = () => img.style.display === 'none';

function setMascot(imgSrc, emojiChar) {
  if (usingEmoji()) {
    emoji.innerText = emojiChar;
  } else {
    img.src = imgSrc;
  }
}

const WORKER_CODE = \`
async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
self.onmessage = async (e) => {
  const { challenge, difficulty, startNonce, step } = e.data;
  const prefix = "0".repeat(difficulty);
  let nonce = startNonce;
  while (true) {
    const hash = await sha256(challenge + nonce);
    if (hash.startsWith(prefix)) {
      self.postMessage({ found: true, nonce, hash });
      return;
    }
    nonce += step;
  }
};
\`;

function createWorker() {
  const blob = new Blob([WORKER_CODE], { type: 'application/javascript' });
  return new Worker(URL.createObjectURL(blob));
}

function mine() {
  btn.disabled = true; btn.innerText = S.calculating;
  setMascot(IMG_CHECK, EMOJI_CHECK);
  const numWorkers = Math.max(1, (navigator.hardwareConcurrency || 4) - 1);
  const workers = [];
  let done = false;
  for (let i = 0; i < numWorkers; i++) {
    const worker = createWorker();
    workers.push(worker);
    worker.postMessage({ challenge: CHALLENGE, difficulty: DIFFICULTY, startNonce: i, step: numWorkers });
    worker.onmessage = (e) => {
      if (done) return;
      done = true;
      workers.forEach(w => w.terminate());
      submit(e.data.nonce, e.data.hash);
    };
  }
}

function submit(nonce, response) {
  btn.innerText = S.verifying;
  const fd = new FormData();
  fd.append('nonce', nonce);
  fd.append('response', response);
  fd.append('verify', 'true');
  fd.append('original_path', ORIGINAL_PATH);
  fetch(window.location.href, { method: 'POST', body: fd }).then(async res => {
    if (res.ok) {
      const data = await res.json();
      setMascot(IMG_SUCCESS, EMOJI_SUCCESS);
      btn.innerText = S.success;
      setTimeout(() => { window.location.href = data.redirect; }, 500);
    } else {
      setMascot(IMG_FAILED, EMOJI_FAILED);
      btn.innerText = S.retry; btn.disabled = false;
    }
  }).catch(() => {
    setMascot(IMG_FAILED, EMOJI_FAILED);
    btn.innerText = S.error; btn.disabled = false;
  });
}

// === BotD 行為偵測 ===
async function checkHuman() {
  btn.disabled = true;
  btn.innerText = S.checking;
  try {
    const Botd = await import('https://openfpcdn.io/botd/v1');
    const botd = await Botd.load();
    const result = await botd.detect();
    if (result.bot) {
      setMascot(IMG_FAILED, EMOJI_FAILED);
      btn.innerText = S.bot_detected;
      btn.disabled = true;
      return;
    }
    mine();
  } catch (e) {
    // BotD 載入失敗（例如被 adblocker 擋），直接放行跑 POW
    mine();
  }
}

btn.addEventListener('click', checkHuman);
</script>
</body>
</html>
`;

// === Honeypot HTML Injector（用 HTMLRewriter 注入隱藏連結）===
class HoneypotInjector {
  private trapPath: string;
  constructor(trapPath: string) {
    this.trapPath = trapPath;
  }
  element(element: Element) {
    // 注入在 </body> 前，對人類完全不可見
    element.append(
      `<div aria-hidden="true" style="position:absolute;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;"><a href="${this.trapPath}" rel="nofollow" tabindex="-1">.</a></div>`,
      { html: true }
    );
  }
}

export const onRequest: PagesFunction<Env> = async (context) => {
  if (SECRET_KEY === "ALBIREO_DEFAULT_SECRET_KEY_CHANGE_ME") {
    return new Response("SECURITY ERROR: Please change SECRET_KEY in _middleware.ts", { status: 500 });
  }

  const { request, next } = context;
  const url = new URL(request.url);
  const ua = (request.headers.get("User-Agent") || "").toLowerCase();
  const cookie = request.headers.get("Cookie") || "";

  // 1. 靜態資源直接放行
  if (
    url.pathname.match(/\.(png|jpg|jpeg|gif|webp|css|js|ico|svg|json|xml|rss|atom)$/) ||
    url.pathname.startsWith("/albireo-dist/")
  ) {
    return next();
  }

  // 2. SEO bots 放行
  if (BOT_AGENTS.some(b => ua.includes(b))) return next();

  // 3. ★ Honeypot 路徑偵測
  if (url.pathname.startsWith(HONEYPOT_PREFIX)) {
    const token = url.pathname.slice(HONEYPOT_PREFIX.length);
    if (await verifyHoneypotToken(token)) {
      // 合法 token 被訪問 → 這是爬蟲，標記並 403
      const headers = new Headers();
      headers.append("Set-Cookie", "albireo_bot=true; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400");
      return new Response("Not Found", { status: 403, headers });
    }
    // 過期或無效 token → 當一般 404，不標記
    return new Response("Not Found", { status: 404 });
  }

  // 4. ★ Bot 黑名單檢查（被 honeypot 抓到的）
  if (cookie.includes("albireo_bot=true")) {
    return new Response("Forbidden", { status: 403 });
  }

  // 5. 已通過 POW 的放行（注入 honeypot 連結）
  if (cookie.includes("albireo_solved=true")) {
    const token = await generateHoneypotToken();
    const trapPath = HONEYPOT_PREFIX + token;
    const response = await next();
    // 只對 HTML 頁面注入
    const contentType = response.headers.get("Content-Type") || "";
    if (contentType.includes("text/html")) {
      return new HTMLRewriter()
      .on("body", new HoneypotInjector(trapPath))
      .transform(response);
    }
    return response;
  }

  // 6. Handle POST（POW 驗證）
  if (request.method === "POST") {
    try {
      const fd = await request.formData();
      if (!fd.has('verify')) return new Response("Bad Request", { status: 400 });

      const nonce = fd.get("nonce") as string;
      const response = fd.get("response") as string;
      const originalPath = safeRedirect(fd.get("original_path") as string || "/");

      const cStr = cookie.split(';').find(c => c.trim().startsWith('albireo_challenge='));
      if (!cStr) return new Response("Expired", { status: 403 });

      const [challenge, timestamp, sig] = decodeURIComponent(cStr.split('=')[1].trim()).split('.');
      if (!await verify(challenge + '.' + timestamp, sig)) return new Response("Invalid Signature", { status: 403 });

      const issuedAt = parseInt(timestamp, 10);
      if (isNaN(issuedAt) || Date.now() - issuedAt > CHALLENGE_TTL) {
        return new Response("Challenge Expired", { status: 403 });
      }

      if (!await checkPoW(challenge, nonce, response, DIFFICULTY)) return new Response("POW Failed", { status: 403 });

      const headers = new Headers();
      headers.append("Set-Cookie", "albireo_solved=true; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400");
      headers.set("Content-Type", "application/json");
      return new Response(JSON.stringify({ success: true, redirect: originalPath }), { status: 200, headers });
    } catch (e) {
      return new Response("Server Error", { status: 500 });
    }
  }

  // 7. 發 Challenge（同時注入 honeypot 連結）
  const rnd = crypto.randomUUID().replace(/-/g, '');
  const timestamp = Date.now().toString();
  const payload = rnd + '.' + timestamp;
  const sig = await sign(payload);
  const originalPath = safeRedirect(url.pathname + url.search + url.hash);
  const trapToken = await generateHoneypotToken();
  const trapPath = HONEYPOT_PREFIX + trapToken;

  const headers = new Headers();
  headers.set("Content-Type", "text/html");
  headers.set("Cache-Control", "private, no-cache, no-store, must-revalidate");
  headers.set("Set-Cookie", `albireo_challenge=${encodeURIComponent(payload + '.' + sig)}; Path=/; HttpOnly; Secure; SameSite=Lax`);

  const challengeHtml = GENERATE_HTML(rnd, originalPath);
  const injected = challengeHtml.replace("</body>",
                                         `<div aria-hidden="true" style="position:absolute;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;"><a href="${trapPath}" rel="nofollow" tabindex="-1">.</a></div></body>`
  );
  return new Response(injected, { headers });
};
